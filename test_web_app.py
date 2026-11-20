import contextlib
import http.server
import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

import web_app


class _Upstream(http.server.BaseHTTPRequestHandler):
    """模拟 OpenAI 兼容接口。"""

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        raw = json.dumps({
            "choices": [{"message": {"content": "## 判断\n\n先修 gets。\n\n```c\nfgets(buf, sizeof buf, stdin);\n```"}}]
        }, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args):
        pass


@contextlib.contextmanager
def upstream():
    server = http.server.HTTPServer(("127.0.0.1", 0), _Upstream)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/v1"
    finally:
        server.shutdown()
        server.server_close()


@contextlib.contextmanager
def app_server(report_dir: Path):
    server = web_app.ThreadingHTTPServer(("127.0.0.1", 0), web_app.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    patcher = mock.patch.object(web_app, "REPORT_DIR", report_dir)
    patcher.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        patcher.stop()
        server.shutdown()
        server.server_close()


def request(url: str, method: str = "GET", payload: dict | None = None,
            token: str | None = None) -> tuple[int, str]:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Token"] = token
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8")


class MarkdownTests(unittest.TestCase):
    def test_heading_and_bold(self):
        rendered = web_app.markdown_to_html("## 结论\n\n**立即修复**")
        self.assertIn("<h2>结论</h2>", rendered)
        self.assertIn("<strong>立即修复</strong>", rendered)

    def test_code_fence_is_escaped(self):
        rendered = web_app.markdown_to_html("```c\nprintf(\"%s\", s);\n```")
        self.assertIn('class="language-c"', rendered)
        self.assertIn("printf(&quot;%s&quot;, s);", rendered)

    def test_table_is_rendered(self):
        rendered = web_app.markdown_to_html("| 级别 | 问题 |\n| --- | --- |\n| HIGH | 溢出 |")
        self.assertIn("<table>", rendered)
        self.assertIn("<th>级别</th>", rendered)
        self.assertIn("<td>溢出</td>", rendered)

    def test_html_is_escaped(self):
        rendered = web_app.markdown_to_html("<img src=x onerror=alert(1)>")
        self.assertNotIn("<img", rendered)
        self.assertIn("&lt;img", rendered)


class PageTests(unittest.TestCase):
    def test_index_injects_config(self):
        with tempfile.TemporaryDirectory() as directory, app_server(Path(directory)) as base:
            status, body = request(base + "/")
        self.assertEqual(status, 200)
        self.assertIn("Security Toolkit", body)
        self.assertIn("window.APP = ", body)
        self.assertIn(web_app.TOKEN, body)


class ApiTests(unittest.TestCase):
    def test_scan_requires_token(self):
        with tempfile.TemporaryDirectory() as directory, app_server(Path(directory)) as base:
            status, body = request(base + "/api/scan", "POST", {"source": "."})
        self.assertEqual(status, 403)
        self.assertIn("令牌", body)

    def test_scan_returns_c_findings(self):
        with tempfile.TemporaryDirectory() as directory, app_server(Path(directory)) as base:
            target = Path(directory) / "demo.c"
            target.write_text("int main(void) { gets(buf); }\n", encoding="utf-8")
            status, body = request(base + "/api/scan", "POST",
                                   {"source": str(target)}, web_app.TOKEN)
        payload = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(payload["findings"][0]["id"], "SEC-101")
        self.assertEqual(payload["summary"]["CRITICAL"], 1)

    def test_scan_rejects_missing_path(self):
        with tempfile.TemporaryDirectory() as directory, app_server(Path(directory)) as base:
            status, body = request(base + "/api/scan", "POST",
                                   {"source": "/definitely/not/here"}, web_app.TOKEN)
        self.assertEqual(status, 400)
        self.assertIn("路径不存在", body)

    def test_ai_requires_key(self):
        with tempfile.TemporaryDirectory() as directory, app_server(Path(directory)) as base:
            with mock.patch.dict(os.environ, {}, clear=True):
                status, body = request(base + "/api/ai", "POST",
                                       {"findings": [{"id": "SEC-101", "severity": "CRITICAL"}]},
                                       web_app.TOKEN)
        self.assertEqual(status, 400)
        self.assertIn("API Key", body)

    def test_ai_returns_rendered_html(self):
        with tempfile.TemporaryDirectory() as directory, app_server(Path(directory)) as base, \
                upstream() as ai_base:
            env = {
                "SECURITY_AI_API_KEY": "sk-test",
                "SECURITY_AI_BASE_URL": ai_base,
                "SECURITY_AI_MODEL": "mock-model",
            }
            with mock.patch.dict(os.environ, env, clear=True):
                status, body = request(base + "/api/ai", "POST", {
                    "findings": [{"id": "SEC-101", "name": "禁用 gets", "severity": "CRITICAL",
                                  "file": "demo.c", "line": 1, "message": "溢出",
                                  "evidence": "gets(buf);"}]
                }, web_app.TOKEN)
        payload = json.loads(body)
        self.assertEqual(status, 200, body)
        self.assertIn("<h2>判断</h2>", payload["html"])
        self.assertIn("fgets(buf, sizeof buf, stdin);", payload["markdown"])

    def test_export_creates_and_serves_report(self):
        with tempfile.TemporaryDirectory() as directory:
            reports = Path(directory) / "reports"
            with app_server(reports) as base:
                status, body = request(base + "/api/export", "POST", {
                    "findings": [{"id": "SEC-101", "name": "禁用 gets", "severity": "CRITICAL",
                                  "file": "demo.c", "line": 3, "message": "溢出",
                                  "evidence": "gets(buf);", "cwe": "CWE-242",
                                  "fix": "fgets(buf, sizeof buf, stdin)"}],
                    "ai_analysis": "## 结论\n\n先修 gets。",
                    "meta": {"source": "demo.c", "elapsed_ms": 12},
                }, web_app.TOKEN)
                payload = json.loads(body)
                self.assertEqual(status, 200, body)
                self.assertTrue(Path(payload["path"]).is_file())
                page_status, page = request(base + payload["url"])
        self.assertEqual(page_status, 200)
        self.assertIn("软件安全性测试报告", page)
        self.assertIn("SEC-101", page)
        self.assertIn("CWE-242", page)
        self.assertIn("fgets(buf, sizeof buf, stdin)", page)
        self.assertIn("先修 gets", page)

    def test_report_name_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory, app_server(Path(directory)) as base:
            status, _ = request(base + "/reports/../security_scan.py")
        self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main()
