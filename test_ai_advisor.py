import contextlib
import http.server
import io
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import ai_advisor
from security_scan import _merge_ai, main


class MergeTests(unittest.TestCase):
    def test_json_merge_adds_ai_field(self):
        merged = json.loads(_merge_ai('{"summary": {}, "findings": []}', "分析内容", "json"))
        self.assertEqual(merged["ai_analysis"], "分析内容")

    def test_markdown_merge_appends_section(self):
        merged = _merge_ai("# 安全检查报告", "分析内容", "markdown")
        self.assertIn("## AI 安全分析", merged)
        self.assertTrue(merged.startswith("# 安全检查报告"))


class _MockHandler(http.server.BaseHTTPRequestHandler):
    """最小的 OpenAI 兼容接口，用于离线验证客户端行为。"""

    requests: list[dict] = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        payload = json.loads(self.rfile.read(length) or b"{}")
        _MockHandler.requests.append({
            "path": self.path,
            "auth": self.headers.get("Authorization", ""),
            "payload": payload,
        })
        if self.path.startswith("/fail"):
            status, body = 401, {"error": {"message": "invalid api key"}}
        elif self.path.startswith("/missing"):
            status, body = 404, {"error": {"message": "model not found"}}
        else:
            status, body = 200, {
                "choices": [{"message": {"role": "assistant",
                                         "content": "## 结论\n优先修复 gets。"}}]
            }
        raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args):
        pass


@contextlib.contextmanager
def mock_api():
    _MockHandler.requests = []
    server = http.server.HTTPServer(("127.0.0.1", 0), _MockHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/v1"
    finally:
        server.shutdown()
        server.server_close()


class PromptTests(unittest.TestCase):
    def test_prompt_contains_location_and_evidence(self):
        findings = [{
            "id": "SEC-101", "name": "禁用 gets", "severity": "CRITICAL",
            "file": "demo.c", "line": 7, "message": "溢出", "evidence": "gets(s1);",
        }]
        messages = ai_advisor.build_messages(findings)
        user = messages[1]["content"]
        self.assertIn("demo.c:7", user)
        self.assertIn("gets(s1);", user)
        self.assertEqual(messages[0]["role"], "system")

    def test_prompt_respects_max_findings(self):
        findings = [
            {"id": "SEC-101", "name": "禁用 gets", "severity": "CRITICAL",
             "file": "a.c", "line": 1, "message": "高", "evidence": "gets(a);"},
            {"id": "SEC-005", "name": "弱加密", "severity": "MEDIUM",
             "file": "b.c", "line": 2, "message": "中", "evidence": "md5(b);"},
        ]
        user = ai_advisor.build_messages(findings, max_findings=1)[1]["content"]
        self.assertIn("SEC-101", user)
        self.assertNotIn("SEC-005", user)

    def test_prompt_includes_code_context(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "demo.c"
            path.write_text("int main(void) {\n  gets(s);\n  return 0;\n}\n", encoding="utf-8")
            user = ai_advisor.build_messages(
                [{"id": "SEC-101", "name": "禁用 gets", "severity": "CRITICAL",
                  "file": str(path), "line": 2, "message": "溢出", "evidence": "gets(s);"}],
                context_lines=1,
            )[1]["content"]
        self.assertIn("2 |", user)
        self.assertIn("gets(s);", user)

    def test_secret_value_is_redacted(self):
        text = ai_advisor.redact('password = "hunter2";')
        self.assertNotIn("hunter2", text)
        self.assertIn("***", text)

    def test_private_key_block_is_redacted(self):
        text = ai_advisor.redact(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----"
        )
        self.assertNotIn("MIIEow", text)
        self.assertIn("已脱敏", text)


class ClientTests(unittest.TestCase):
    def test_chat_parses_openai_response(self):
        with mock_api() as base:
            client = ai_advisor.AIClient(
                ai_advisor.AIConfig(api_key="sk-test", base_url=base, model="mock-model")
            )
            reply = client.chat([{"role": "user", "content": "hi"}])
        self.assertIn("gets", reply)
        request = _MockHandler.requests[0]
        self.assertEqual(request["auth"], "Bearer sk-test")
        self.assertEqual(request["payload"]["model"], "mock-model")
        self.assertFalse(request["payload"]["stream"])

    def test_auth_error_is_readable(self):
        with mock_api() as base:
            client = ai_advisor.AIClient(
                ai_advisor.AIConfig(api_key="bad", base_url=base.replace("/v1", "/fail/v1"))
            )
            with self.assertRaises(ai_advisor.AIError) as context:
                client.chat([{"role": "user", "content": "hi"}])
        self.assertIn("认证失败", str(context.exception))

    def test_missing_model_error_is_readable(self):
        with mock_api() as base:
            client = ai_advisor.AIClient(
                ai_advisor.AIConfig(api_key="sk", base_url=base.replace("/v1", "/missing/v1"))
            )
            with self.assertRaises(ai_advisor.AIError) as context:
                client.chat([{"role": "user", "content": "hi"}])
        self.assertIn("模型不存在", str(context.exception))

    def test_remote_plain_http_is_rejected(self):
        with self.assertRaises(ai_advisor.AIError):
            ai_advisor.AIClient(
                ai_advisor.AIConfig(api_key="sk", base_url="http://api.example.com/v1")
            )

    def test_analyze_returns_markdown(self):
        with mock_api() as base:
            text = ai_advisor.analyze(
                [{"id": "SEC-101", "name": "禁用 gets", "severity": "CRITICAL",
                  "file": "demo.c", "line": 2, "message": "溢出", "evidence": "gets(s);"}],
                ai_advisor.AIConfig(api_key="sk-test", base_url=base, model="mock-model"),
            )
        self.assertTrue(text.startswith("## 结论"))

    def test_review_source_requires_existing_file(self):
        with self.assertRaises(ai_advisor.AIError):
            ai_advisor.review_source(Path("/nonexistent/demo.c"))


class CommandLineAITests(unittest.TestCase):
    def test_ai_flag_appends_analysis(self):
        with tempfile.TemporaryDirectory() as directory, mock_api() as base:
            path = Path(directory) / "bad.c"
            path.write_text("int main(void) { gets(buf); }\n", encoding="utf-8")
            env = {
                "SECURITY_AI_API_KEY": "sk-test",
                "SECURITY_AI_BASE_URL": base,
                "SECURITY_AI_MODEL": "mock-model",
            }
            output = io.StringIO()
            with mock.patch.dict(os.environ, env, clear=True), \
                    contextlib.redirect_stdout(output):
                code = main(["--authorized", "--source", str(path), "--ai"])
            printed = output.getvalue()
        self.assertEqual(code, 1)
        self.assertIn("SEC-101", printed)
        self.assertIn("AI 安全分析", printed)
        self.assertIn("优先修复 gets", printed)

    def test_ai_without_key_degrades_gracefully(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.c"
            path.write_text("int main(void) { gets(buf); }\n", encoding="utf-8")
            output, errors = io.StringIO(), io.StringIO()
            with mock.patch.dict(os.environ, {}, clear=True), \
                    contextlib.redirect_stdout(output), \
                    contextlib.redirect_stderr(errors):
                code = main(["--authorized", "--source", str(path), "--ai"])
        self.assertEqual(code, 1)
        self.assertIn("SEC-101", output.getvalue())
        self.assertIn("未检测到 AI 凭证", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
