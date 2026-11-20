#!/usr/bin/env python3
"""本地 Web 界面：在浏览器里跑安全扫描、看 AI 分析、导出 HTML 报告。

只监听 127.0.0.1，并用一次性令牌校验写操作，避免同机其他页面调用。
启动：python3 web_app.py --port 8765
"""

from __future__ import annotations

import argparse
import html
import json
import re
import secrets
import sys
import time
import webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import ai_advisor
from security_scan import (
    MAX_FILE_BYTES,
    filter_findings,
    http_findings,
    source_findings,
    summarize,
)

APP_DIR = Path(__file__).resolve().parent
INDEX_FILE = APP_DIR / "web" / "index.html"
REPORT_DIR = APP_DIR / "reports"
TOKEN = secrets.token_urlsafe(18)
MAX_BODY_BYTES = 8 * 1024 * 1024
REPORT_NAME_RE = re.compile(r"^security-report-[0-9]{8}-[0-9]{6}\.html$")

SEVERITY_LABELS = {
    "CRITICAL": "严重",
    "HIGH": "高危",
    "MEDIUM": "中危",
    "LOW": "低危",
    "INFO": "提示",
}


# --------------------------------------------------------------------------
# Markdown 渲染（仅用于本项目生成的 AI 文本，先转义再格式化）
# --------------------------------------------------------------------------

def _inline(text: str) -> str:
    text = html.escape(text)
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    return text


def _cells(row: str) -> list[str]:
    return [cell.strip() for cell in row.strip().strip("|").split("|")]


def markdown_to_html(markdown: str) -> str:
    """极简 Markdown：标题、列表、表格、代码块、粗体、行内代码。"""
    lines = markdown.replace("\r\n", "\n").split("\n")
    out: list[str] = []
    paragraph: list[str] = []
    bullets: list[str] = []
    numbered: list[str] = []
    code: list[str] = []
    in_code = False
    language = ""
    index = 0

    def flush_paragraph() -> None:
        if paragraph:
            out.append(f"<p>{_inline(' '.join(paragraph))}</p>")
            paragraph.clear()

    def flush_lists() -> None:
        if bullets:
            out.append("<ul>" + "".join(f"<li>{_inline(item)}</li>" for item in bullets) + "</ul>")
            bullets.clear()
        if numbered:
            out.append("<ol>" + "".join(f"<li>{_inline(item)}</li>" for item in numbered) + "</ol>")
            numbered.clear()

    while index < len(lines):
        raw = lines[index]
        line = raw.rstrip()

        if line.startswith("```"):
            if in_code:
                klass = f' class="language-{html.escape(language)}"' if language else ""
                out.append(f"<pre><code{klass}>{html.escape(chr(10).join(code))}</code></pre>")
                code.clear()
                in_code = False
                language = ""
            else:
                flush_paragraph()
                flush_lists()
                in_code = True
                language = line[3:].strip()
            index += 1
            continue

        if in_code:
            code.append(raw)
            index += 1
            continue

        if not line.strip():
            flush_paragraph()
            flush_lists()
            index += 1
            continue

        if line.startswith("|") and index + 1 < len(lines) and re.match(
            r"^\|[\s:|-]+\|$", lines[index + 1].strip()
        ):
            flush_paragraph()
            flush_lists()
            header = _cells(line)
            index += 2
            rows = []
            while index < len(lines) and lines[index].strip().startswith("|"):
                rows.append(_cells(lines[index]))
                index += 1
            out.append(
                "<table><thead><tr>"
                + "".join(f"<th>{_inline(cell)}</th>" for cell in header)
                + "</tr></thead><tbody>"
                + "".join(
                    "<tr>" + "".join(f"<td>{_inline(cell)}</td>" for cell in row) + "</tr>"
                    for row in rows
                )
                + "</tbody></table>"
            )
            continue

        match = re.match(r"^(#{1,6})\s+(.*)$", line)
        if match:
            flush_paragraph()
            flush_lists()
            level = len(match.group(1))
            out.append(f"<h{level}>{_inline(match.group(2).strip())}</h{level}>")
            index += 1
            continue

        match = re.match(r"^\s*[-*+]\s+(.*)$", line)
        if match:
            flush_paragraph()
            if numbered:
                flush_lists()
            bullets.append(match.group(1))
            index += 1
            continue

        match = re.match(r"^\s*\d+[.)]\s+(.*)$", line)
        if match:
            flush_paragraph()
            if bullets:
                flush_lists()
            numbered.append(match.group(1))
            index += 1
            continue

        paragraph.append(line.strip())
        index += 1

    flush_paragraph()
    flush_lists()
    if code:
        out.append(f"<pre><code>{html.escape(chr(10).join(code))}</code></pre>")
    return "\n".join(out)


# --------------------------------------------------------------------------
# HTML 报告
# --------------------------------------------------------------------------

REPORT_CSS = """
:root{--text:#1f2937;--muted:#6b7280;--border:#e5e7eb;--accent:#2563eb}
*{box-sizing:border-box}
body{margin:0;background:#f5f7fa;color:var(--text);font:15px/1.7 -apple-system,"PingFang SC","Microsoft YaHei",sans-serif}
.page{max-width:960px;margin:0 auto;padding:40px 24px 64px}
header.report{border-bottom:2px solid var(--text);padding-bottom:18px;margin-bottom:28px}
header.report h1{margin:0 0 6px;font-size:26px;letter-spacing:.5px}
header.report p{margin:2px 0;color:var(--muted);font-size:13px}
.summary{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:24px 0 32px}
.card{background:#fff;border:1px solid var(--border);border-radius:10px;padding:14px 16px}
.card .num{font-size:26px;font-weight:700;line-height:1.2}
.card .label{font-size:12px;color:var(--muted);letter-spacing:.5px}
.critical .num{color:#dc2626}.high .num{color:#ea580c}.medium .num{color:#d97706}
.low .num{color:#0284c7}.info .num{color:#64748b}
h2.section{font-size:19px;margin:36px 0 14px;padding-left:10px;border-left:4px solid var(--accent)}
table.findings{width:100%;border-collapse:collapse;background:#fff;font-size:13.5px}
table.findings th{text-align:left;background:#f1f5f9;font-weight:600;padding:9px 10px;border-bottom:1px solid var(--border)}
table.findings td{padding:9px 10px;border-bottom:1px solid var(--border);vertical-align:top}
table.findings tr:last-child td{border-bottom:none}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:700;color:#fff;white-space:nowrap}
.badge.CRITICAL{background:#dc2626}.badge.HIGH{background:#ea580c}.badge.MEDIUM{background:#d97706}
.badge.LOW{background:#0284c7}.badge.INFO{background:#64748b}
code{background:#f1f5f9;padding:1px 5px;border-radius:4px;font-size:12.5px;font-family:"SF Mono",Menlo,Consolas,monospace}
.fix{display:inline-block;margin-top:4px;color:#047857;font-size:12px}
.cwe{color:#0f766e;font-size:12px;white-space:nowrap}
pre{background:#0f172a;color:#e2e8f0;padding:14px 16px;border-radius:10px;overflow:auto;font-size:12.5px;line-height:1.6}
pre code{background:none;color:inherit;padding:0;font-size:inherit}
.ai{background:#fff;border:1px solid var(--border);border-radius:12px;padding:8px 26px 22px;margin-top:8px}
.ai h2,.ai h3{margin-top:22px}
.ai table{border-collapse:collapse;width:100%;font-size:13px;margin:12px 0}
.ai table th,.ai table td{border:1px solid var(--border);padding:6px 10px;text-align:left}
.ai table th{background:#f8fafc}
footer.report{margin-top:40px;padding-top:16px;border-top:1px solid var(--border);color:var(--muted);font-size:12px}
.empty{color:var(--muted)}
@media print{body{background:#fff}.page{max-width:none;padding:0}.ai,.card,table.findings{break-inside:avoid}}
""".strip()


def render_report(findings: list[dict], ai_markdown: str, meta: dict) -> str:
    counts = summarize(findings)
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    target = meta.get("source") or meta.get("url") or "—"

    cards = "".join(
        f'<div class="card {severity.lower()}">'
        f'<div class="num">{counts.get(severity, 0)}</div>'
        f'<div class="label">{severity} · {SEVERITY_LABELS[severity]}</div></div>'
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    )

    if findings:
        rows = []
        for item in findings:
            location = item.get("file") or item.get("url") or ""
            if item.get("line"):
                location = f"{location}:{item['line']}"
            evidence = item.get("evidence") or ""
            given = ""
            if evidence:
                given += f"<br><code>{html.escape(evidence)}</code>"
            if item.get("fix"):
                given += f'<br><span class="fix">建议：{html.escape(item["fix"])}</span>'
            rows.append(
                "<tr>"
                f'<td><span class="badge {item["severity"]}">{item["severity"]}</span></td>'
                f'<td>{html.escape(item["id"])}</td>'
                f'<td><span class="cwe">{html.escape(item.get("cwe") or "—")}</span></td>'
                f"<td>{html.escape(item['name'])}</td>"
                f"<td>{html.escape(location)}</td>"
                f"<td>{html.escape(item.get('message', ''))}{given}</td></tr>"
            )
        table = (
            '<table class="findings"><thead><tr><th>级别</th><th>编号</th><th>CWE</th>'
            "<th>问题</th><th>位置</th><th>说明</th></tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table>"
        )
    else:
        table = '<p class="empty">本次扫描未发现问题。</p>'

    ai_section = ""
    if ai_markdown.strip():
        ai_section = (
            '<h2 class="section">AI 安全分析</h2>'
            f'<div class="ai">{markdown_to_html(ai_markdown)}</div>'
        )

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>安全扫描报告 · {html.escape(Path(str(target)).name or 'target')}</title>
<style>{REPORT_CSS}</style>
</head>
<body>
<div class="page">
  <header class="report">
    <h1>软件安全性测试报告</h1>
    <p>扫描目标：{html.escape(str(target))}</p>
    <p>生成时间：{generated}　·　结果总数：{len(findings)}　·　耗时：{meta.get('elapsed_ms', 0)} ms</p>
  </header>
  <div class="summary">{cards}</div>
  <h2 class="section">扫描结果</h2>
  {table}
  {ai_section}
  <footer class="report">
    本报告由 Security Toolkit 自动生成，规则为行级正则匹配，可能存在误报；
    AI 结论基于扫描片段，需人工复核。仅用于对自有或已获授权系统的安全自查。
  </footer>
</div>
</body>
</html>
"""


# --------------------------------------------------------------------------
# HTTP 服务
# --------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "SecurityToolkitUI/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # 保持终端干净
        pass

    # ---- 路由 ----
    def do_GET(self):  # noqa: N802
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            self._serve_index()
        elif path.startswith("/reports/"):
            self._serve_report(path[len("/reports/"):])
        else:
            self._json({"error": "接口不存在"}, 404)

    def do_POST(self):  # noqa: N802
        path = urlparse(self.path).path
        if self.headers.get("X-Token") != TOKEN:
            self._json({"error": "会话令牌无效，请刷新页面"}, 403)
            return
        handlers = {
            "/api/scan": self._scan,
            "/api/ai": self._ai,
            "/api/export": self._export,
        }
        handler = handlers.get(path)
        if handler is None:
            self._json({"error": "接口不存在"}, 404)
            return
        payload = self._read_json()
        if payload is None:
            return
        try:
            handler(payload)
        except Exception as error:  # noqa: BLE001 - 兜底避免连接被重置
            self._json({"error": f"服务端异常：{error}"}, 500)

    # ---- 响应工具 ----
    def _json(self, data: dict, status: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _html(self, body: str, status: int = 200) -> None:
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _read_json(self) -> dict | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._json({"error": "请求长度非法"}, 400)
            return None
        if length > MAX_BODY_BYTES:
            self._json({"error": "请求体过大"}, 413)
            return None
        if length <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(length))
        except json.JSONDecodeError:
            self._json({"error": "请求体不是合法 JSON"}, 400)
            return None

    # ---- 页面 ----
    def _serve_index(self) -> None:
        if not INDEX_FILE.is_file():
            self._html("<h1>缺少 web/index.html</h1>", 500)
            return
        config = ai_advisor.AIConfig.from_env()
        app_config = {
            "token": TOKEN,
            "aiReady": config.is_configured,
            "model": config.model,
            "baseUrl": config.base_url,
            "cwd": str(Path.cwd()),
        }
        template = INDEX_FILE.read_text(encoding="utf-8")
        page = template.replace(
            "/*__CONFIG__*/", "window.APP = " + json.dumps(app_config, ensure_ascii=False) + ";"
        )
        self._html(page)

    def _serve_report(self, name: str) -> None:
        name = name.split("?", 1)[0]
        if not REPORT_NAME_RE.match(name):
            self._json({"error": "报告名称非法"}, 400)
            return
        path = REPORT_DIR / name
        if not path.is_file():
            self._json({"error": "报告不存在"}, 404)
            return
        self._html(path.read_text(encoding="utf-8"))

    # ---- API ----
    def _scan(self, payload: dict) -> None:
        source = str(payload.get("source") or "").strip()
        url = str(payload.get("url") or "").strip()
        if not source and not url:
            self._json({"error": "请填写源码路径或目标 URL"}, 400)
            return

        started = time.perf_counter()
        findings: list[dict] = []
        try:
            if source:
                path = Path(source).expanduser()
                if not path.exists():
                    self._json({"error": f"路径不存在：{source}"}, 400)
                    return
                findings.extend(
                    source_findings(path, payload.get("exclude") or [], MAX_FILE_BYTES)
                )
            if url:
                timeout = float(payload.get("timeout") or 5)
                findings.extend(http_findings(url, timeout))
        except ValueError as error:
            self._json({"error": str(error)}, 400)
            return

        findings = filter_findings(findings, str(payload.get("min_severity") or "INFO"))
        self._json({
            "findings": findings,
            "summary": summarize(findings),
            "count": len(findings),
            "elapsed_ms": int((time.perf_counter() - started) * 1000),
            "source": source,
            "url": url,
        })

    def _ai(self, payload: dict) -> None:
        findings = payload.get("findings") or []
        review_file = str(payload.get("review_file") or "").strip()
        question = str(payload.get("question") or "").strip()
        analysis = str(payload.get("analysis") or "")

        if not findings and not review_file:
            self._json({"error": "没有可分析的结果，请先扫描"}, 400)
            return

        config = ai_advisor.AIConfig.from_env(
            base_url=str(payload.get("base_url") or "") or None,
            model=str(payload.get("model") or "") or None,
        )
        if not config.is_configured:
            self._json({
                "error": "未检测到 API Key：请设置 SECURITY_AI_API_KEY（或 OPENAI_API_KEY / "
                         "DEEPSEEK_API_KEY）后重启本页面服务。"
            }, 400)
            return

        try:
            if review_file and not findings:
                text = ai_advisor.review_source(Path(review_file), config)
            else:
                messages = ai_advisor.build_messages(
                    findings,
                    max_findings=int(payload.get("max_findings") or 20),
                    context_lines=int(payload.get("context_lines") or 2),
                )
                if question:
                    if not analysis:
                        self._json({"error": "请先生成一次分析再追问"}, 400)
                        return
                    messages.append({"role": "assistant", "content": analysis})
                    messages.append({"role": "user", "content": question})
                text = ai_advisor.AIClient(config).chat(messages)
        except ai_advisor.AIError as error:
            self._json({"error": str(error)}, 400)
            return
        except (OSError, ValueError) as error:
            self._json({"error": f"调用 AI 失败：{error}"}, 400)
            return

        self._json({
            "markdown": text,
            "html": markdown_to_html(text),
            "model": config.model,
        })

    def _export(self, payload: dict) -> None:
        findings = payload.get("findings") or []
        ai_text = str(payload.get("ai_analysis") or "")
        meta = payload.get("meta") if isinstance(payload.get("meta"), dict) else {}
        document = render_report(findings, ai_text, meta)
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        name = f"security-report-{datetime.now():%Y%m%d-%H%M%S}.html"
        path = REPORT_DIR / name
        path.write_text(document, encoding="utf-8")
        self._json({"path": str(path), "url": f"/reports/{name}"})


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="启动本地安全扫描 Web 界面")
    parser.add_argument("--port", type=int, default=8765, help="监听端口（默认 8765）")
    parser.add_argument("--open", action="store_true", help="启动后自动打开浏览器")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not INDEX_FILE.is_file():
        print(f"错误：找不到界面文件 {INDEX_FILE}", file=sys.stderr)
        return 2
    try:
        server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    except OSError as error:
        print(f"错误：端口 {args.port} 无法监听（{error}），可换一个 --port", file=sys.stderr)
        return 2

    url = f"http://127.0.0.1:{args.port}"
    print(f"安全扫描界面已启动：{url}")
    print("按 Ctrl-C 停止。仅监听本机回环地址，不对外网开放。")
    if args.open:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止。")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
