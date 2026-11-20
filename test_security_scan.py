import contextlib
import http.server
import io
import ipaddress
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from security_scan import (
    SOURCE_RULES,
    _cookie_findings,
    apply_baseline,
    filter_findings,
    fingerprint,
    http_findings,
    load_baseline,
    main,
    render_json,
    render_markdown,
    render_sarif,
    scan_file,
    should_fail,
    source_findings,
    strip_c_comments,
    write_baseline,
)

EXAMPLES = Path(__file__).resolve().parent / "examples"


class SourceScanTests(unittest.TestCase):
    def scan_text(self, name: str, content: str) -> list[dict]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / name
            path.write_text(content, encoding="utf-8")
            return scan_file(path)

    @staticmethod
    def ids(findings: list[dict]) -> set[str]:
        return {item["id"] for item in findings}

    # ---- 通用规则 ----
    def test_source_finds_hardcoded_secret(self):
        findings = self.scan_text("config.py", 'api_key = "test-only-key"\n')
        self.assertIn("SEC-001", self.ids(findings))

    def test_source_findings_include_line_number(self):
        findings = self.scan_text("unsafe.cpp", "int main() {\n  eval(input);\n}\n")
        dangerous = [item for item in findings if item["id"] == "SEC-004"]
        self.assertEqual(dangerous[0]["line"], 2)

    # ---- C/C++ 规则 ----
    def test_c_gets_is_critical(self):
        findings = self.scan_text("login.c", "int main(void) {\n  gets(buf);\n}\n")
        gets = [item for item in findings if item["id"] == "SEC-101"]
        self.assertEqual(gets[0]["severity"], "CRITICAL")
        self.assertEqual(gets[0]["line"], 2)

    def test_c_unbounded_copy_functions(self):
        findings = self.scan_text("copy.c", 'strcpy(dst, src);\nsprintf(buf, "%s", src);\n')
        self.assertIn("SEC-102", self.ids(findings))

    def test_c_scanf_width_is_respected(self):
        unsafe = self.scan_text("a.c", 'scanf("%s", name);\n')
        self.assertIn("SEC-103", self.ids(unsafe))
        safe = self.scan_text("b.c", 'scanf("%15s", name);\n')
        self.assertNotIn("SEC-103", self.ids(safe))

    def test_c_rules_do_not_apply_to_python_files(self):
        findings = self.scan_text("note.py", "buffer = gets(user_input)\n")
        self.assertNotIn("SEC-101", self.ids(findings))

    def test_comment_only_code_is_not_reported(self):
        findings = self.scan_text("doc.c", "// gets(buf);\n/* strcpy(dst, src); */\nint x = 0;\n")
        self.assertFalse({"SEC-101", "SEC-102"} & self.ids(findings))

    def test_comment_marker_inside_string_literal_is_preserved(self):
        findings = self.scan_text("s.c", 'printf("/* gets(buf); */");\n')
        self.assertIn("SEC-101", self.ids(findings))

    def test_inline_suppression(self):
        findings = self.scan_text("ok.c", "gets(buf); // security-scan: ignore\n")
        self.assertNotIn("SEC-101", self.ids(findings))

    def test_suppression_on_previous_line(self):
        findings = self.scan_text("ok.c", "/* security-scan: ignore */\ngets(buf);\n")
        self.assertNotIn("SEC-101", self.ids(findings))

    def test_comment_stripping_keeps_line_numbers(self):
        source = "/* a\n b */\nint x;\n"
        self.assertEqual(len(strip_c_comments(source).splitlines()), len(source.splitlines()))

    # ---- .securityignore ----
    def test_securityignore_skips_matching_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".securityignore").write_text("# 演示\nskip.c\n", encoding="utf-8")
            (root / "skip.c").write_text("gets(buf);\n", encoding="utf-8")
            (root / "keep.c").write_text("strcpy(a, b);\n", encoding="utf-8")
            findings = source_findings(root)
            self.assertEqual({Path(item["file"]).name for item in findings}, {"keep.c"})

    def test_securityignore_in_subdirectory_uses_local_base(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sub = root / "vendor"
            sub.mkdir()
            (sub / ".securityignore").write_text("skip.c\n", encoding="utf-8")
            (sub / "skip.c").write_text("gets(buf);\n", encoding="utf-8")
            (root / "skip.c").write_text("gets(buf);\n", encoding="utf-8")
            findings = source_findings(root)
            self.assertEqual([Path(item["file"]).name for item in findings], ["skip.c"])
            self.assertEqual(Path(findings[0]["file"]).parent, root)


class RuleMetadataTests(unittest.TestCase):
    def test_every_rule_has_cwe_and_fix(self):
        for rule in SOURCE_RULES:
            self.assertRegex(rule.cwe, r"^CWE-\d+$", rule.id)
            self.assertTrue(rule.fix, rule.id)

    def test_finding_carries_cwe_and_fix(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "demo.c"
            path.write_text("int main(void) { gets(buf); }\n", encoding="utf-8")
            finding = scan_file(path)[0]
        self.assertEqual(finding["cwe"], "CWE-242")
        self.assertIn("fgets", finding["fix"])

    def test_text_report_shows_cwe_and_fix(self):
        from security_scan import render_text
        finding = {"id": "SEC-101", "name": "禁用 gets", "severity": "CRITICAL",
                   "file": "a.c", "line": 1, "message": "溢出", "evidence": "gets(b);",
                   "cwe": "CWE-242", "fix": "fgets(...)"}
        rendered = render_text([finding])
        self.assertIn("CWE-242", rendered)
        self.assertIn("修复：fgets(...)", rendered)

    def test_sarif_output_structure(self):
        findings = [{"id": "SEC-101", "name": "禁用 gets", "severity": "CRITICAL",
                     "file": "a.c", "line": 3, "message": "溢出",
                     "evidence": "gets(b);", "cwe": "CWE-242", "fix": "fgets(...)"}]
        payload = json.loads(render_sarif(findings))
        self.assertEqual(payload["version"], "2.1.0")
        run = payload["runs"][0]
        self.assertEqual(run["results"][0]["ruleId"], "SEC-101")
        self.assertEqual(run["results"][0]["level"], "error")
        self.assertEqual(run["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"], 3)
        self.assertEqual(run["tool"]["driver"]["rules"][0]["properties"]["cwe"], "CWE-242")

    def test_list_rules_needs_no_authorization(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["--list-rules"])
        self.assertEqual(code, 0)
        self.assertIn("SEC-101", output.getvalue())
        self.assertIn("CWE-242", output.getvalue())

    def test_list_rules_markdown_to_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rules.md"
            with contextlib.redirect_stderr(io.StringIO()):
                code = main(["--list-rules", "--format", "markdown", "--output", str(path)])
            content = path.read_text(encoding="utf-8")
        self.assertEqual(code, 0)
        self.assertIn("| SEC-101 | CRITICAL | CWE-242 |", content)

    def test_examples_demonstrate_detection_and_clean_code(self):
        vulnerable = {item["id"] for item in source_findings(EXAMPLES / "vulnerable_demo.c")}
        self.assertTrue(
            {"SEC-101", "SEC-102", "SEC-103", "SEC-104",
             "SEC-105", "SEC-107", "SEC-108", "SEC-110"} <= vulnerable
        )
        self.assertEqual(source_findings(EXAMPLES / "safe_demo.c"), [])


class BaselineTests(unittest.TestCase):
    FINDING = {"id": "SEC-101", "name": "禁用 gets", "severity": "CRITICAL",
               "file": "a.c", "line": 3, "message": "溢出", "evidence": "gets(s1);"}

    def test_fingerprint_ignores_line_number(self):
        moved = dict(self.FINDING, line=99)
        self.assertEqual(fingerprint(self.FINDING), fingerprint(moved))

    def test_fingerprint_changes_with_evidence(self):
        other = dict(self.FINDING, evidence="gets(s2);")
        self.assertNotEqual(fingerprint(self.FINDING), fingerprint(other))

    def test_write_load_apply_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "baseline.json"
            count = write_baseline(path, [self.FINDING])
            marks = load_baseline(path)
        self.assertEqual(count, 1)
        self.assertEqual(apply_baseline([self.FINDING], marks), ([], 1))

    def test_invalid_baseline_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text("{not json", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_baseline(path)
        with self.assertRaises(ValueError):
            load_baseline(Path("/nonexistent/baseline.json"))

    def test_fail_on_threshold(self):
        critical = [self.FINDING]
        high = [dict(self.FINDING, severity="HIGH")]
        self.assertTrue(should_fail(critical, "high"))
        self.assertFalse(should_fail(high, "critical"))
        self.assertTrue(should_fail(high, "medium"))
        self.assertFalse(should_fail(critical, "none"))


class BaselineCommandLineTests(unittest.TestCase):
    def test_write_then_ignore(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "bad.c"
            source.write_text("int main(void) { gets(buf); }\n", encoding="utf-8")
            baseline = Path(directory) / "baseline.json"

            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(
                    main(["--authorized", "--source", str(source),
                          "--write-baseline", str(baseline)]), 0
                )
            self.assertTrue(baseline.is_file())

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(["--authorized", "--source", str(source),
                             "--baseline", str(baseline)])
            self.assertEqual(code, 0)
            self.assertIn("已按基线忽略 1 条", output.getvalue())

    def test_fail_on_none_never_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "bad.c"
            source.write_text("int main(void) { gets(buf); }\n", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(
                    main(["--authorized", "--source", str(source), "--fail-on", "none"]), 0
                )

    def test_fail_on_critical_ignores_high(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "copy.c"
            source.write_text("strcpy(dst, src);\n", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(
                    main(["--authorized", "--source", str(source), "--fail-on", "critical"]), 0
                )


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.findings = [
            {"id": "SEC-101", "name": "禁用 gets", "severity": "CRITICAL",
             "file": "a.c", "line": 3, "message": "溢出", "evidence": "gets(buf);"},
            {"id": "HTTP-003", "name": "暴露技术栈", "severity": "LOW",
             "url": "https://example.com", "message": "Server 头"},
        ]

    def test_filter_by_min_severity(self):
        filtered = filter_findings(self.findings, "HIGH")
        self.assertEqual([item["id"] for item in filtered], ["SEC-101"])

    def test_filter_sorts_by_severity(self):
        ordered = filter_findings(list(reversed(self.findings)))
        self.assertEqual([item["severity"] for item in ordered], ["CRITICAL", "LOW"])

    def test_markdown_report_contains_summary_and_rows(self):
        report = render_markdown(self.findings)
        self.assertIn("| CRITICAL | SEC-101 |", report)
        self.assertIn("结果总数：2", report)

    def test_json_report_has_summary(self):
        self.assertIn('"CRITICAL": 1', render_json(self.findings))


class HttpRuleTests(unittest.TestCase):
    def test_private_http_target_is_rejected(self):
        with self.assertRaises(ValueError):
            http_findings("http://127.0.0.1")

    def test_private_url_is_rejected_for_ssrf_safety(self):
        with self.assertRaises(ValueError):
            http_findings("http://localhost")

    def test_cookie_without_flags_is_reported(self):
        findings = _cookie_findings(["sid=abc"], "https", "https://example.com")
        self.assertEqual({item["id"] for item in findings},
                         {"COOKIE-001", "COOKIE-002", "COOKIE-003"})

    def test_hardened_cookie_passes(self):
        findings = _cookie_findings(
            ["sid=abc; Secure; HttpOnly; SameSite=Lax"], "https", "https://example.com"
        )
        self.assertEqual(findings, [])


class _RedirectHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/start":
            self.send_response(302)
            self.send_header("Location", "/final")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Set-Cookie", "sid=1")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):  # 静默测试期日志
        pass


class RedirectTests(unittest.TestCase):
    """用本地服务验证逐跳重定向逻辑；测试内显式放行回环地址。"""

    def test_follows_redirect_and_reports_final_url(self):
        server = http.server.HTTPServer(("127.0.0.1", 0), _RedirectHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            allowed = [ipaddress.ip_address("127.0.0.1")]
            with mock.patch("security_scan._resolve_public", return_value=allowed):
                findings = http_findings(f"http://127.0.0.1:{port}/start", timeout=2)
        finally:
            server.shutdown()
            server.server_close()

        info = [item for item in findings if item["id"] == "INFO-001"][0]
        self.assertEqual(info["details"]["status"], 200)
        self.assertTrue(info["url"].endswith("/final"))


class CommandLineTests(unittest.TestCase):
    def test_missing_authorization_is_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["--url", "https://example.com"]), 2)

    def test_critical_finding_sets_exit_code(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.py"
            path.write_text("eval(user_input)\n", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--authorized", "--source", str(path)]), 1)

    def test_clean_file_sets_exit_code_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ok.c"
            path.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--authorized", "--source", str(path)]), 0)

    def test_min_severity_filter_does_not_mask_exit_code(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "copy.c"
            path.write_text("strcpy(dst, src);\n", encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(["--authorized", "--source", str(path),
                             "--min-severity", "CRITICAL"])
            self.assertEqual(code, 1)
            self.assertIn("未发现任何结果", output.getvalue())


if __name__ == "__main__":
    unittest.main()
