#!/usr/bin/env python3
"""安全测试套件：C/C++ 与多语言源码静态检查 + 授权目标的基础 HTTP/TLS 检查。

可选接入 AI（`--ai` / `--ai-review` / `--ai-chat`），把扫描结果交给大模型生成
风险解释与修复代码。设计目标是「教学 + 自查」：
- 静态规则覆盖 C 语言最常见的危险 API（gets/strcpy/sprintf/scanf("%s") 等）
- 网络检查默认拒绝内网地址，只允许授权的外网目标
- 只用标准库，便于在课程环境直接运行
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import ipaddress
import json
import re
import socket
import ssl
import sys
import time
import unicodedata
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from http.client import HTTPMessage
from pathlib import Path
from typing import Iterable, Iterator, Sequence
from urllib.parse import urljoin, urlparse


USER_AGENT = "Authorized-Security-Scanner/2.2"
VERSION = "1.1.0"
BASELINE_VERSION = 1
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_REDIRECTS = 5
REDIRECT_CODES = {301, 302, 303, 307, 308}
MIN_HSTS_MAX_AGE = 15552000  # 180 天
CERT_WARN_DAYS = 30

TEXT_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".c", ".h", ".cpp", ".cc",
    ".cxx", ".hpp", ".hh", ".go", ".rs", ".php", ".rb", ".cs", ".swift", ".kt",
    ".kts", ".sh", ".yaml", ".yml", ".json", ".xml", ".properties", ".env",
}

C_FAMILY = frozenset({".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx"})

DEFAULT_EXCLUDED_DIRS = frozenset({
    ".git", ".hg", ".svn", "__pycache__", "node_modules", "venv", ".venv",
    "build", "dist", "target", ".idea", ".vscode", ".dSYM",
})

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

SUPPRESSION_RE = re.compile(r"(?:security-scan|nosec)\s*:\s*ignore", re.IGNORECASE)

IGNORE_FILENAME = ".securityignore"


@dataclass(frozen=True)
class Rule:
    """一条静态检查规则。suffixes 为空表示对所有文本文件生效。"""

    id: str
    name: str
    severity: str
    message: str
    fix: str
    cwe: str
    regexes: tuple[re.Pattern[str], ...]
    suffixes: frozenset[str] = frozenset()


def _rule(
    rule_id: str,
    name: str,
    severity: str,
    message: str,
    patterns: Sequence[str],
    *,
    fix: str = "",
    cwe: str = "",
    suffixes: Iterable[str] = (),
) -> Rule:
    return Rule(
        id=rule_id,
        name=name,
        severity=severity,
        message=message,
        fix=fix,
        cwe=cwe,
        regexes=tuple(re.compile(pattern, re.IGNORECASE) for pattern in patterns),
        suffixes=frozenset(suffixes),
    )


SOURCE_RULES: tuple[Rule, ...] = (
    # ---------- 通用规则（所有语言） ----------
    _rule("SEC-001", "硬编码密钥", "HIGH",
          "源代码中可能包含密码、API 密钥或访问令牌。",
          (r"\b(passwd|password|pwd|secret|token|api[_-]?key|access[_-]?key)"
           r"\s*[=:]\s*[\"'][^\"'\s]{4,}[\"']",),
          cwe="CWE-798", fix="改从环境变量或密钥管理服务读取，如 getenv(\"DB_PASSWORD\")"),
    _rule("SEC-002", "危险 SQL 拼接", "HIGH",
          "SQL 语句可能由未校验的输入拼接而成，存在注入风险。",
          (r"\bexecute\s*\(\s*[^)]*\+", r"\bexecutemany\s*\(\s*[^)]*\+",
           r"\bquery\s*=\s*[^;\n]*\+",),
          cwe="CWE-89", fix="改用参数化查询，如 cursor.execute(sql, (user_id,))"),
    _rule("SEC-003", "禁用 TLS 验证", "HIGH",
          "检测到禁用证书或主机名校验的配置，连接可被中间人劫持。",
          (r"\bverify\s*=\s*False", r"CURLOPT_SSL_VERIFYPEER\s*,\s*0",
           r"\bcheck_hostname\s*=\s*False", r"rejectUnauthorized\s*:\s*false",
           r"CURLOPT_SSL_VERIFYHOST\s*,\s*0"),
          cwe="CWE-295", fix="保持证书与主机名校验开启，并配置受信任的 CA"),
    _rule("SEC-004", "危险代码执行", "CRITICAL",
          "检测到可能执行任意代码的动态执行调用。",
          (r"\beval\s*\(", r"\bexec\s*\(", r"\bos\.system\s*\(",
           r"\bshell\s*=\s*True", r"Runtime\.getRuntime\s*\(\s*\)\s*\.exec",
           r"child_process\.exec\s*\("),
          cwe="CWE-94", fix="避免拼接执行；必须执行外部命令时用参数数组并做白名单校验"),
    _rule("SEC-005", "弱加密算法", "MEDIUM",
          "检测到弱哈希或弱加密算法，不应用于口令或完整性保护。",
          (r"\bhashlib\.md5\b", r"\bmd5\s*\(", r"\bMD5\b", r"\bsha1\s*\(",
           r"\bSHA1\b", r"\bDES\b", r"\bRC4\b", r"\bECB\b"),
          cwe="CWE-327", fix="口令用 bcrypt/scrypt/Argon2，完整性用 SHA-256 及以上"),
    _rule("SEC-006", "不安全的临时文件", "MEDIUM",
          "检测到存在竞态风险的临时文件 API（CWE-377）。",
          (r"\btempnam\s*\(", r"\btmpnam\s*\(", r"\bmktemp\s*\("),
          cwe="CWE-377", fix="改用 mkstemp() 创建并立即设置为 0600 权限"),
    _rule("SEC-007", "私钥泄漏", "CRITICAL",
          "文件中出现私钥内容，私钥不应提交到代码仓库。",
          (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",),
          cwe="CWE-321", fix="从密钥库读取，并把已泄漏的私钥立即吊销重签"),

    # ---------- C / C++ 规则（课程重点） ----------
    _rule("SEC-101", "禁用 gets", "CRITICAL",
          "gets 无法限制输入长度，必然导致缓冲区溢出，C11 起已被移除。",
          (r"\bgets\s*\(",),
          cwe="CWE-242", fix="fgets(buf, sizeof buf, stdin) 并检查返回值",
          suffixes=C_FAMILY),
    _rule("SEC-102", "无边界字符串拷贝", "HIGH",
          "strcpy/strcat/sprintf 不检查目标缓冲区大小，易被长输入溢出。",
          (r"\b(?:strcpy|strcat|stpcpy|wcscpy|wcscat|sprintf|vsprintf)\s*\(",),
          cwe="CWE-120", fix="snprintf(buf, sizeof buf, \"%s\", src)，或 strlcpy/strlcat",
          suffixes=C_FAMILY),
    _rule("SEC-103", "scanf 读取字符串未限宽", "HIGH",
          "scanf 的 %s 未指定宽度时等同于 gets，会写越界。",
          (r"\b(?:scanf|fscanf|sscanf)\s*\(\s*\"[^\"]*%(?!\d)[a-zA-Z]*s",),
          cwe="CWE-120", fix="明确宽度：scanf(\"%15s\", name)，且不超过缓冲区容量减一",
          suffixes=C_FAMILY),
    _rule("SEC-104", "命令执行函数", "HIGH",
          "system/popen 会把字符串交给 shell，拼接外部输入时可被注入命令。",
          (r"\b(?:system|popen)\s*\(",),
          cwe="CWE-78", fix="用 execve 传参数数组，避免拼接 shell 命令",
          suffixes=C_FAMILY),
    _rule("SEC-105", "非字面量格式串", "MEDIUM",
          "printf 家族使用变量作格式串，可被 %n/%s 利用读写内存。",
          (r"\b(?:printf|vprintf)\s*\(\s*[A-Za-z_]\w*\s*[,)]",
           r"\b(?:fprintf|sprintf|snprintf|vfprintf|vsnprintf|syslog)\s*\([^,()]+,\s*[A-Za-z_]\w*\s*[,)]"),
          cwe="CWE-134", fix="固定格式串：printf(\"%s\", buf)",
          suffixes=C_FAMILY),
    _rule("SEC-106", "栈上动态分配", "MEDIUM",
          "alloca/变长数组按不可信长度分配会耗尽栈空间，导致崩溃。",
          (r"\balloca\s*\(",),
          cwe="CWE-770", fix="改为堆分配，并对长度设置上限",
          suffixes=C_FAMILY),
    _rule("SEC-107", "整数溢出风险分配", "MEDIUM",
          "malloc 参数含乘法时可能整数溢出，分配出远小于预期的缓冲区。",
          (r"\b(?:malloc|calloc|realloc)\s*\(\s*[\w.\[\]]+\s*\*\s*[\w.\[\]]+",),
          cwe="CWE-190", fix="先判断 a > SIZE_MAX / b 再加一，或用 calloc 自动检查",
          suffixes=C_FAMILY),
    _rule("SEC-108", "可预测的随机数", "MEDIUM",
          "rand/srand(time(NULL)) 不是密码学安全随机源，不能用于令牌或盐值。",
          (r"\bsrand\s*\(\s*(?:\(unsigned\)\s*)?time\s*\(",),
          cwe="CWE-338", fix="用 getrandom() 或读取 /dev/urandom",
          suffixes=C_FAMILY),
    _rule("SEC-109", "格式串写内存", "HIGH",
          "格式串中的 %n 会向内存写入数据，是典型的格式化字符串漏洞。",
          (r"\b(?:printf|fprintf|sprintf|snprintf)\s*\(\s*\"[^\"]*%n",),
          cwe="CWE-134", fix="禁止外部输入进入格式串，必要时过滤 %n",
          suffixes=C_FAMILY),
    _rule("SEC-110", "过宽的权限设置", "MEDIUM",
          "0777/0666 或 umask(0) 会让文件对所有用户可读写执行。",
          (r"\bchmod\s*\([^,]+,\s*0?[0-7]?777\b", r"\bumask\s*\(\s*0\s*\)"),
          cwe="CWE-732", fix="最小权限：普通文件 0644、私密数据 0600",
          suffixes=C_FAMILY),
)

# HTTP/TLS 类结果的分类与整改建议（按规则编号补齐）
HTTP_CWE = {
    "PROTO-001": "CWE-319", "HTTP-001": "CWE-693", "HTTP-002": "CWE-319",
    "HTTP-003": "CWE-200", "HTTP-004": "CWE-693", "TLS-001": "CWE-295",
    "TLS-002": "CWE-298", "TLS-003": "CWE-326", "TLS-004": "CWE-298",
    "COOKIE-001": "CWE-1275", "COOKIE-002": "CWE-614", "COOKIE-003": "CWE-1004",
    "REDIR-001": "CWE-601", "REDIR-002": "CWE-319", "REDIR-003": "CWE-918",
}

HTTP_FIX = {
    "PROTO-001": "全站启用 HTTPS，并把 HTTP 301 跳转到 HTTPS",
    "HTTP-001": "补全 CSP、HSTS、X-Content-Type-Options、X-Frame-Options、Referrer-Policy",
    "HTTP-002": "HSTS 的 max-age 设为 31536000（一年）并考虑 includeSubDomains",
    "HTTP-003": "移除或改写 Server / X-Powered-By 响应头",
    "HTTP-004": "设置 X-Content-Type-Options: nosniff",
    "TLS-001": "修复证书链与主机名配置，确保使用受信任 CA",
    "TLS-002": "更换有效证书并设置到期提醒",
    "TLS-003": "禁用 TLS 1.0/1.1，最低要求 TLS 1.2",
    "TLS-004": "提前续签证书，建议自动化续期",
    "COOKIE-001": "敏感 Cookie 设置 SameSite=Lax 或 Strict",
    "COOKIE-002": "HTTPS 场景下为 Cookie 增加 Secure",
    "COOKIE-003": "为会话 Cookie 增加 HttpOnly",
    "REDIR-001": "只允许跳转到 http/https 协议",
    "REDIR-002": "避免 HTTPS 降级跳转，全站统一 HTTPS",
    "REDIR-003": "校验跳转目标，禁止指向内网或保留地址",
}


# --------------------------------------------------------------------------
# 源码扫描
# --------------------------------------------------------------------------

def _read_text(path: Path, max_bytes: int) -> str | None:
    """读取文本文件；跳过超大文件、二进制文件和无法解码的内容。"""
    try:
        if path.stat().st_size > max_bytes:
            return None
        raw = path.read_bytes()
    except OSError:
        return None
    if not raw or b"\x00" in raw[:4096]:
        return None
    for encoding in ("utf-8", "gb18030"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1")


def strip_c_comments(text: str) -> str:
    """去掉 C/C++ 注释，保留字符串字面量与行数，减少注释导致的误报。"""
    out: list[str] = []
    index, length = 0, len(text)
    state = "code"
    while index < length:
        char = text[index]
        nxt = text[index + 1] if index + 1 < length else ""
        if state == "code":
            if char == "/" and nxt == "/":
                state = "line"
                index += 2
                continue
            if char == "/" and nxt == "*":
                state = "block"
                out.append(" ")
                index += 2
                continue
            if char in "\"'":
                state = "string" if char == '"' else "char"
            out.append(char)
            index += 1
            continue
        if state == "line":
            if char == "\n":
                out.append("\n")
                state = "code"
            index += 1
            continue
        if state == "block":
            if char == "*" and nxt == "/":
                state = "code"
                index += 2
                continue
            if char == "\n":
                out.append("\n")
            index += 1
            continue
        # 字符串/字符字面量内部：跳过转义，避免误判注释起始
        if char == "\\":
            out.append(text[index:index + 2])
            index += 2
            continue
        if (state == "string" and char == '"') or (state == "char" and char == "'"):
            state = "code"
        out.append(char)
        index += 1
    return "".join(out)


def _is_suppressed(lines: Sequence[str], line_number: int) -> bool:
    """支持在当行或上一行写 `security-scan: ignore` 忽略告警。"""
    for candidate in (line_number, line_number - 1):
        if 1 <= candidate <= len(lines) and SUPPRESSION_RE.search(lines[candidate - 1]):
            return True
    return False


def iter_source_files(root: Path, exclude: Sequence[str] = ()) -> Iterator[Path]:
    if root.is_file():
        yield root
        return
    ignores: list[tuple[str, str]] = [("", pattern) for pattern in exclude]
    yield from _walk_source(root, root, ignores)


def _ignore_patterns(directory: Path, root: Path) -> list[tuple[str, str]]:
    """读取目录下的 .securityignore，返回 (基准前缀, 通配符) 列表。"""
    path = directory / IGNORE_FILENAME
    if not path.is_file():
        return []
    base = directory.relative_to(root).as_posix()
    base = "" if base == "." else base + "/"
    patterns: list[tuple[str, str]] = []
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    for line in content.splitlines():
        entry = line.split("#", 1)[0].strip()
        if entry:
            patterns.append((base, entry))
    return patterns


def _is_ignored(relative: Path, ignores: Sequence[tuple[str, str]]) -> bool:
    text = relative.as_posix()
    for base, pattern in ignores:
        if base:
            if not text.startswith(base):
                continue
            candidate = text[len(base):]
        else:
            candidate = text
        target = pattern.rstrip("/")
        if fnmatch.fnmatch(candidate, pattern) or candidate == target:
            return True
        if candidate.startswith(target + "/"):
            return True
        if "/" not in target and target in candidate.split("/"):
            return True
    return False


def _walk_source(directory: Path, root: Path, ignores: list[tuple[str, str]]) -> Iterator[Path]:
    ignores = ignores + _ignore_patterns(directory, root)
    try:
        entries = sorted(directory.iterdir())
    except OSError:
        return
    for entry in entries:
        relative = entry.relative_to(root)
        if entry.is_symlink():
            continue
        if entry.is_dir():
            if entry.name in DEFAULT_EXCLUDED_DIRS or entry.name.startswith("."):
                continue
            if _is_ignored(relative, ignores):
                continue
            yield from _walk_source(entry, root, ignores)
            continue
        if not entry.is_file() or entry.suffix.lower() not in TEXT_SUFFIXES:
            continue
        if _is_ignored(relative, ignores):
            continue
        yield entry


def scan_file(path: Path, max_bytes: int = MAX_FILE_BYTES) -> list[dict]:
    text = _read_text(path, max_bytes)
    if text is None:
        return []
    suffix = path.suffix.lower()
    original = text.splitlines()
    scannable = strip_c_comments(text).splitlines() if suffix in C_FAMILY else original

    findings: list[dict] = []
    for rule in SOURCE_RULES:
        if rule.suffixes and suffix not in rule.suffixes:
            continue
        for line_number, line in enumerate(scannable, 1):
            if _is_suppressed(original, line_number):
                continue
            if not any(regex.search(line) for regex in rule.regexes):
                continue
            source_line = original[line_number - 1] if line_number <= len(original) else line
            findings.append({
                "id": rule.id,
                "name": rule.name,
                "severity": rule.severity,
                "file": str(path),
                "line": line_number,
                "message": rule.message,
                "evidence": source_line.strip()[:240],
                "cwe": rule.cwe,
                "fix": rule.fix,
            })
    return findings


def source_findings(
    root: Path,
    exclude: Sequence[str] = (),
    max_bytes: int = MAX_FILE_BYTES,
) -> list[dict]:
    findings: list[dict] = []
    for path in iter_source_files(root, exclude):
        findings.extend(scan_file(path, max_bytes))
    return findings


# --------------------------------------------------------------------------
# HTTP / TLS 检查
# --------------------------------------------------------------------------

class _NetworkError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """关闭自动跳转，由调用方逐跳校验，防止 302 绕过内网限制。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def _resolve_public(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as error:
        raise ValueError("无法解析目标主机名") from error
    addresses = []
    for info in infos:
        try:
            addresses.append(ipaddress.ip_address(info[4][0].split("%")[0]))
        except ValueError:
            continue
    if not addresses:
        raise ValueError("无法解析目标主机名")
    if any(not address.is_global for address in addresses):
        raise ValueError("出于安全限制，禁止扫描私网、回环、链路本地或保留地址")
    return addresses


def _host_is_public(host: str) -> bool:
    try:
        return bool(_resolve_public(host))
    except ValueError:
        return False


def _validate_url(url: str):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("目标必须是有效的 http:// 或 https:// URL")
    _resolve_public(parsed.hostname)
    return parsed


def _fetch(url: str, timeout: float) -> tuple[int, HTTPMessage, str, list[dict]]:
    """发起 GET 并逐跳校验重定向。返回 (状态码, 响应头, 最终 URL, 重定向告警)。"""
    opener = urllib.request.build_opener(_NoRedirectHandler)
    extra: list[dict] = []
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        parsed = _validate_url(current)
        request = urllib.request.Request(
            current, headers={"User-Agent": USER_AGENT}, method="GET"
        )
        try:
            with opener.open(request, timeout=timeout) as response:
                return response.status, response.headers, current, extra
        except urllib.error.HTTPError as error:
            headers = error.headers or HTTPMessage()
            location = headers.get("Location")
            if error.code in REDIRECT_CODES and location:
                error.close()
                target = urljoin(current, location)
                target_parsed = urlparse(target)
                if target_parsed.scheme not in ("http", "https"):
                    extra.append({
                        "id": "REDIR-001",
                        "name": "重定向到非 HTTP 协议",
                        "severity": "HIGH",
                        "url": current,
                        "message": f"重定向目标是 {target_parsed.scheme or '未知'} 协议：{target}",
                    })
                    return error.code, headers, current, extra
                if parsed.scheme == "https" and target_parsed.scheme == "http":
                    extra.append({
                        "id": "REDIR-002",
                        "name": "HTTPS 降级重定向",
                        "severity": "HIGH",
                        "url": current,
                        "message": f"从 HTTPS 跳转到明文 HTTP：{target}",
                    })
                try:
                    _validate_url(target)
                except ValueError as exc:
                    extra.append({
                        "id": "REDIR-003",
                        "name": "重定向指向受保护地址",
                        "severity": "HIGH",
                        "url": current,
                        "message": f"跳转目标被拒绝：{exc}（{target}）",
                    })
                    return error.code, headers, current, extra
                current = target
                continue
            status = error.code
            error.close()
            return status, headers, current, extra
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise _NetworkError(str(getattr(error, "reason", error))) from error
    raise _NetworkError("重定向次数过多")


def _tls_findings(parsed, timeout: float) -> list[dict]:
    host = parsed.hostname
    port = parsed.port or 443
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                certificate = tls.getpeercert() or {}
                version = tls.version() or ""
    except ssl.SSLCertVerificationError as error:
        return [{
            "id": "TLS-001",
            "name": "证书校验失败",
            "severity": "HIGH",
            "url": parsed.geturl(),
            "message": getattr(error, "verify_message", None) or str(error),
        }]
    except (ssl.SSLError, OSError) as error:
        return [{
            "id": "TLS-001",
            "name": "TLS 握手失败",
            "severity": "HIGH",
            "url": parsed.geturl(),
            "message": str(error),
        }]

    findings: list[dict] = []
    if version in {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}:
        findings.append({
            "id": "TLS-003",
            "name": "协议版本过低",
            "severity": "MEDIUM",
            "url": parsed.geturl(),
            "message": f"协商出的协议版本为 {version}，应至少使用 TLS 1.2。",
        })
    not_after = certificate.get("notAfter")
    if not_after:
        expires = ssl.cert_time_to_seconds(not_after)
        remaining = (expires - time.time()) / 86400
        if remaining < 0:
            findings.append({
                "id": "TLS-002",
                "name": "证书已过期",
                "severity": "HIGH",
                "url": parsed.geturl(),
                "message": f"证书已于 {not_after} 过期。",
            })
        elif remaining < CERT_WARN_DAYS:
            findings.append({
                "id": "TLS-004",
                "name": "证书即将过期",
                "severity": "LOW",
                "url": parsed.geturl(),
                "message": f"证书将在 {remaining:.0f} 天后过期（{not_after}）。",
            })
    return findings


def _cookie_findings(cookies: Sequence[str], scheme: str, url: str) -> list[dict]:
    findings: list[dict] = []
    for cookie in cookies:
        lowered = cookie.lower()
        name = cookie.split("=", 1)[0].strip() or "cookie"
        if "samesite" not in lowered:
            findings.append({
                "id": "COOKIE-001",
                "name": "Cookie 缺少 SameSite",
                "severity": "MEDIUM",
                "url": url,
                "message": f"Cookie {name} 未声明 SameSite，可能被跨站请求携带。",
            })
        if scheme == "https" and "secure" not in lowered:
            findings.append({
                "id": "COOKIE-002",
                "name": "Cookie 缺少 Secure",
                "severity": "MEDIUM",
                "url": url,
                "message": f"HTTPS 站点下 Cookie {name} 缺少 Secure 属性。",
            })
        if "httponly" not in lowered:
            findings.append({
                "id": "COOKIE-003",
                "name": "Cookie 缺少 HttpOnly",
                "severity": "LOW",
                "url": url,
                "message": f"Cookie {name} 未设置 HttpOnly，可被脚本读取。",
            })
    return findings


def http_findings(url: str, timeout: float = 5.0) -> list[dict]:
    parsed = _validate_url(url)
    findings: list[dict] = []
    if parsed.scheme == "http":
        findings.append({
            "id": "PROTO-001",
            "name": "明文 HTTP 传输",
            "severity": "MEDIUM",
            "url": url,
            "message": "目标使用 HTTP，数据在传输过程中可能被窃听或篡改。",
        })

    try:
        status, message, final_url, redirect_findings = _fetch(url, timeout)
    except _NetworkError as error:
        findings.append({
            "id": "NET-001",
            "name": "目标不可访问",
            "severity": "INFO",
            "url": url,
            "message": f"无法连接目标：{error.reason}",
        })
        return findings

    findings.extend(redirect_findings)
    headers = {key.lower(): value for key, value in message.items()}
    cookies = message.get_all("Set-Cookie") or []

    required = (
        "content-security-policy",
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
    )
    missing = [header for header in required if header not in headers]
    if missing:
        findings.append({
            "id": "HTTP-001",
            "name": "缺少安全响应头",
            "severity": "MEDIUM",
            "url": final_url,
            "message": "响应缺少常见安全头，浏览器侧防护被削弱。",
            "details": missing,
        })

    hsts = headers.get("strict-transport-security")
    if hsts:
        match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
        max_age = int(match.group(1)) if match else 0
        if max_age < MIN_HSTS_MAX_AGE:
            findings.append({
                "id": "HTTP-002",
                "name": "HSTS 有效期过短",
                "severity": "LOW",
                "url": final_url,
                "message": f"HSTS max-age={max_age}，建议不少于 {MIN_HSTS_MAX_AGE}（180 天）。",
            })

    disclosed = [header for header in ("server", "x-powered-by") if header in headers]
    if disclosed:
        findings.append({
            "id": "HTTP-003",
            "name": "响应头暴露技术栈",
            "severity": "LOW",
            "url": final_url,
            "message": "响应头泄漏了服务端软件信息。",
            "details": {header: headers[header] for header in disclosed},
        })

    if "x-content-type-options" in headers:
        if "nosniff" not in headers["x-content-type-options"].lower():
            findings.append({
                "id": "HTTP-004",
                "name": "X-Content-Type-Options 取值异常",
                "severity": "LOW",
                "url": final_url,
                "message": "该头存在但未设置为 nosniff，MIME 嗅探仍可能发生。",
            })

    final_parsed = urlparse(final_url)
    findings.extend(_cookie_findings(cookies, final_parsed.scheme, final_url))

    if final_parsed.scheme == "https":
        findings.extend(_tls_findings(final_parsed, timeout))

    if status:
        findings.append({
            "id": "INFO-001",
            "name": "HTTP 响应状态",
            "severity": "INFO",
            "url": final_url,
            "details": {"status": status},
            "message": f"目标返回 HTTP {status}。",
        })

    for item in findings:
        item.setdefault("cwe", HTTP_CWE.get(item["id"], ""))
        item.setdefault("fix", HTTP_FIX.get(item["id"], ""))
    return findings


# --------------------------------------------------------------------------
# 结果处理与输出
# --------------------------------------------------------------------------

def _sort_key(finding: dict) -> tuple[int, str, int, str]:
    return (
        SEVERITY_ORDER.get(finding.get("severity", "INFO"), 9),
        finding.get("file") or finding.get("url") or "",
        finding.get("line", 0),
        finding.get("id", ""),
    )


def filter_findings(findings: Sequence[dict], min_severity: str = "INFO") -> list[dict]:
    threshold = SEVERITY_ORDER.get(min_severity.upper(), 4)
    selected = [item for item in findings
                if SEVERITY_ORDER.get(item.get("severity", "INFO"), 9) <= threshold]
    return sorted(selected, key=_sort_key)


def summarize(findings: Sequence[dict]) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        severity = finding.get("severity", "INFO")
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def fingerprint(finding: dict) -> str:
    """指纹只取规则、文件名和命中代码，行号移动不会让基线失效。"""
    source = Path(finding["file"]).name if finding.get("file") else finding.get("url", "")
    evidence = re.sub(r"\s+", " ", finding.get("evidence", "")).strip()[:160]
    basis = "|".join([finding.get("id", ""), source, evidence])
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def write_baseline(path: Path, findings: Sequence[dict]) -> int:
    entries: list[dict] = []
    seen: set[str] = set()
    for item in findings:
        mark = fingerprint(item)
        if mark in seen:
            continue
        seen.add(mark)
        entries.append({
            "fingerprint": mark,
            "id": item.get("id", ""),
            "file": item.get("file") or item.get("url", ""),
            "evidence": item.get("evidence", ""),
        })
    payload = {
        "version": BASELINE_VERSION,
        "generated_at": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        "entries": entries,
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return len(entries)


def load_baseline(path: Path) -> set[str]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ValueError(f"无法读取基线文件 {path}：{error}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"基线文件不是合法 JSON：{path}") from error
    if not isinstance(payload, dict) or "entries" not in payload:
        raise ValueError(f"基线文件格式不正确：{path}")
    marks: set[str] = set()
    for entry in payload.get("entries") or []:
        if isinstance(entry, dict) and entry.get("fingerprint"):
            marks.add(str(entry["fingerprint"]))
    return marks


def apply_baseline(findings: Sequence[dict], fingerprints: set[str]) -> tuple[list[dict], int]:
    kept: list[dict] = []
    suppressed = 0
    for item in findings:
        if fingerprint(item) in fingerprints:
            suppressed += 1
        else:
            kept.append(item)
    return kept, suppressed


def should_fail(findings: Sequence[dict], threshold: str = "high") -> bool:
    """达到阈值即返回失败，用于 CI 卡口。"""
    if threshold == "none":
        return False
    limit = SEVERITY_ORDER.get(threshold.upper(), SEVERITY_ORDER["HIGH"])
    return any(
        SEVERITY_ORDER.get(item.get("severity", "INFO"), 9) <= limit for item in findings
    )


def _location(finding: dict) -> str:
    if finding.get("file"):
        suffix = f":{finding['line']}" if finding.get("line") else ""
        return f"{finding['file']}{suffix}"
    return finding.get("url", "")


def render_text(findings: Sequence[dict], suppressed: int = 0) -> str:
    if not findings:
        if suppressed:
            return f"未发现新问题（已按基线忽略 {suppressed} 条）。"
        return "未发现任何结果。"
    counts = summarize(findings)
    summary = "，".join(f"{severity} {count}" for severity, count in counts.items() if count)
    header = f"共发现 {len(findings)} 条结果（{summary}）"
    if suppressed:
        header += f"，已按基线忽略 {suppressed} 条"
    lines = [header, ""]
    for finding in findings:
        lines.append(
            f"[{finding['severity']}] {finding['id']} {finding['name']} {_location(finding)}".rstrip()
        )
        if finding.get("message"):
            lines.append(f"  {finding['message']}")
        if finding.get("evidence"):
            lines.append(f"  代码：{finding['evidence']}")
        meta_bits = []
        if finding.get("cwe"):
            meta_bits.append(finding["cwe"])
        if finding.get("fix"):
            meta_bits.append(f"修复：{finding['fix']}")
        if meta_bits:
            lines.append("  " + " · ".join(meta_bits))
        if "details" in finding:
            lines.append(f"  详情：{finding['details']}")
    return "\n".join(lines)


def render_json(findings: Sequence[dict], suppressed: int = 0) -> str:
    payload = {
        "summary": summarize(findings),
        "suppressed": suppressed,
        "findings": list(findings),
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def _md_cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_markdown(findings: Sequence[dict]) -> str:
    counts = summarize(findings)
    lines = [
        "# 安全检查报告",
        "",
        f"- 生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"- 结果总数：{len(findings)}",
        "- 严重级别：" + "，".join(f"{severity} {count}"
                                for severity, count in counts.items() if count),
        "",
    ]
    if not findings:
        lines.append("未发现任何结果。")
        return "\n".join(lines)
    lines.extend([
        "| 级别 | 编号 | CWE | 问题 | 位置 | 说明 |",
        "| --- | --- | --- | --- | --- | --- |",
    ])
    for finding in findings:
        lines.append(
            "| {severity} | {id} | {cwe} | {name} | {location} | {message} |".format(
                severity=finding["severity"],
                id=finding["id"],
                cwe=finding.get("cwe", "") or "—",
                name=_md_cell(finding["name"]),
                location=_md_cell(_location(finding)),
                message=_md_cell(finding.get("message", "")),
            )
        )
    return "\n".join(lines)


SARIF_LEVEL = {
    "CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
    "LOW": "note", "INFO": "note",
}

SARIF_SCORE = {
    "CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.5", "LOW": "3.0", "INFO": "0.0",
}


def render_sarif(findings: Sequence[dict]) -> str:
    """输出 SARIF 2.1.0，便于接入 GitHub Code Scanning、SonarQube 等平台。"""
    rules: list[dict] = []
    seen: set[str] = set()
    for item in findings:
        if item["id"] in seen:
            continue
        seen.add(item["id"])
        rule = {
            "id": item["id"],
            "name": _md_cell(item.get("name", "")),
            "shortDescription": {"text": item.get("name", "")},
            "fullDescription": {"text": item.get("message", "")},
            "defaultConfiguration": {"level": SARIF_LEVEL.get(item["severity"], "note")},
            "properties": {
                "severity": item["severity"],
                "security-severity": SARIF_SCORE.get(item["severity"], "0.0"),
                "tags": ["security"],
            },
        }
        if item.get("cwe"):
            rule["properties"]["cwe"] = item["cwe"]
        if item.get("fix"):
            rule["properties"]["remediation"] = item["fix"]
        rules.append(rule)

    results: list[dict] = []
    for item in findings:
        result = {
            "ruleId": item["id"],
            "level": SARIF_LEVEL.get(item["severity"], "note"),
            "message": {"text": item.get("message", "")},
        }
        location: dict = {}
        if item.get("file"):
            location = {
                "physicalLocation": {
                    "artifactLocation": {"uri": Path(item["file"]).as_posix()},
                    "region": {"startLine": max(1, int(item.get("line") or 1))},
                }
            }
        elif item.get("url"):
            location = {"physicalLocation": {"artifactLocation": {"uri": item["url"]}}}
        if location:
            result["locations"] = [location]
        properties = {}
        if item.get("evidence"):
            properties["evidence"] = item["evidence"]
        if item.get("fix"):
            properties["remediation"] = item["fix"]
        if properties:
            result["properties"] = properties
        results.append(result)

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "SecurityToolkit",
                "informationUri": "https://example.invalid/security-toolkit",
                "rules": rules,
            }},
            "results": results,
        }],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def _display_width(text: str) -> int:
    return sum(2 if unicodedata.east_asian_width(char) in ("W", "F") else 1 for char in text)


def _pad(text: str, width: int) -> str:
    return text + " " * max(0, width - _display_width(text))


def render_rules_text() -> str:
    lines = [
        _pad("编号", 10) + _pad("级别", 10) + _pad("CWE", 12) + "规则与建议",
        "-" * 80,
    ]
    for rule in SOURCE_RULES:
        scope = "C/C++" if rule.suffixes == C_FAMILY else "通用"
        lines.append(
            _pad(rule.id, 10) + _pad(rule.severity, 10) + _pad(rule.cwe or "—", 12)
            + f"{rule.name}（{scope}）"
        )
        if rule.fix:
            lines.append(_pad("", 32) + f"建议：{rule.fix}")
    lines.append("")
    lines.append(f"共 {len(SOURCE_RULES)} 条静态规则；另有 HTTP/TLS/Cookie 检查 16 项，见 README。")
    return "\n".join(lines)


def render_rules_markdown() -> str:
    lines = [
        "# 检查规则清单",
        "",
        "| 编号 | 级别 | CWE | 规则 | 适用范围 | 修复建议 |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for rule in SOURCE_RULES:
        scope = "C/C++" if rule.suffixes == C_FAMILY else "通用"
        lines.append(
            f"| {rule.id} | {rule.severity} | {rule.cwe or '—'} | {_md_cell(rule.name)} "
            f"| {scope} | {_md_cell(rule.fix)} |"
        )
    return "\n".join(lines)


# --------------------------------------------------------------------------
# AI 分析
# --------------------------------------------------------------------------

def _run_ai(args, findings: list[dict]):
    """调用 AI 生成分析文本，返回 (文本, 会话)；失败时降级为无 AI 结果。"""
    try:
        import ai_advisor
    except ImportError as error:
        print(f"错误：无法加载 ai_advisor.py（{error}）", file=sys.stderr)
        return None, None

    config = ai_advisor.AIConfig.from_env(
        api_key=args.ai_key,
        base_url=args.ai_base_url,
        model=args.ai_model,
        timeout=args.ai_timeout,
    )
    if not config.is_configured:
        print(
            "提示：未检测到 AI 凭证，已跳过 AI 分析。\n"
            "      可设置 SECURITY_AI_API_KEY（或 OPENAI_API_KEY / DEEPSEEK_API_KEY），\n"
            "      再用 --ai-base-url、--ai-model 指向 DeepSeek、通义、Ollama 等服务。",
            file=sys.stderr,
        )
        return None, None

    sections: list[str] = []
    session = None

    if args.ai_review:
        try:
            sections.append(ai_advisor.review_source(args.ai_review, config))
        except ai_advisor.AIError as error:
            print(f"AI 代码审查失败：{error}", file=sys.stderr)

    if args.ai:
        if not findings:
            print("提示：本次扫描没有发现问题，跳过 AI 分析。", file=sys.stderr)
        else:
            try:
                session = ai_advisor.AISession(
                    ai_advisor.build_messages(
                        findings,
                        max_findings=args.ai_max_findings,
                        context_lines=args.ai_context_lines,
                    ),
                    config,
                )
                sections.append(session.start())
            except ai_advisor.AIError as error:
                print(f"AI 分析失败：{error}", file=sys.stderr)
                session = None

    text = "\n\n".join(section for section in sections if section)
    return (text or None), session


def _chat_loop(session) -> None:
    """AI 追问模式。"""
    print("\n已进入追问模式，直接回车或 Ctrl-D 结束。", file=sys.stderr)
    while True:
        try:
            question = input("追问> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if not question:
            return
        try:
            print("\n" + session.ask(question) + "\n")
        except Exception as error:  # noqa: BLE001 - 网络异常不应中断主流程
            print(f"AI 请求失败：{error}", file=sys.stderr)
            return


def _merge_ai(rendered: str, ai_text: str, output_format: str) -> str:
    if output_format == "json":
        try:
            payload = json.loads(rendered)
        except json.JSONDecodeError:
            return rendered
        payload["ai_analysis"] = ai_text
        return json.dumps(payload, ensure_ascii=False, indent=2)
    if output_format == "markdown":
        return rendered + "\n\n## AI 安全分析\n\n" + ai_text
    return rendered + "\n\n" + "-" * 60 + "\nAI 安全分析\n" + "-" * 60 + "\n\n" + ai_text


# --------------------------------------------------------------------------
# 命令行入口
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="对授权目标进行静态代码与基础 HTTP/TLS 安全检查，可选用 AI 生成修复建议",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例：\n"
               "  python3 security_scan.py --authorized --source ./src\n"
               "  python3 security_scan.py --authorized --source ./src --fail-on high\n"
               "  python3 security_scan.py --authorized --source ./src --baseline .security-baseline.json\n"
               "  python3 security_scan.py --authorized --source ./src --ai\n"
               "  python3 security_scan.py --authorized --source ./src --ai --ai-chat\n"
               "  python3 security_scan.py --authorized --url https://example.com --format markdown\n",
    )
    parser.add_argument("--source", type=Path, help="要扫描的源码文件或目录")
    parser.add_argument("--url", help="要检查的授权 HTTP/HTTPS URL")
    parser.add_argument("--authorized", action="store_true", help="确认目标由你拥有或已获授权")
    parser.add_argument("--timeout", type=float, default=5.0, help="网络超时秒数（默认 5）")
    parser.add_argument("--format", choices=("text", "json", "markdown", "sarif"), default="text",
                        help="输出格式（默认 text；sarif 便于接入 CI 平台）")
    parser.add_argument("--json", action="store_true", help="等同于 --format json")
    parser.add_argument("--output", type=Path, help="把结果写入指定文件")
    parser.add_argument("--min-severity", default="INFO",
                        choices=tuple(SEVERITY_ORDER), help="只输出不低于该级别的结果")
    parser.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                        help="跳过匹配的路径（可重复，如 --exclude 'test/*'）")
    parser.add_argument("--max-file-size", type=int, default=MAX_FILE_BYTES,
                        help="单文件扫描上限字节数")
    parser.add_argument("--list-rules", action="store_true",
                        help="打印全部静态规则后退出（配合 --format markdown 生成文档）")
    parser.add_argument("--baseline", type=Path, metavar="FILE",
                        help="按基线文件忽略已接受的历史问题")
    parser.add_argument("--write-baseline", type=Path, metavar="FILE",
                        help="把当前结果写成基线后退出，便于存量项目逐步接入")
    parser.add_argument("--fail-on", choices=("none", "info", "low", "medium", "high", "critical"),
                        default="high", help="达到该级别即返回退出码 1（默认 high）")
    parser.add_argument("--version", action="version", version=f"Security Toolkit {VERSION}")

    ai_group = parser.add_argument_group("AI 分析（可选）")
    ai_group.add_argument("--ai", action="store_true",
                          help="把扫描结果交给 AI 生成风险解释与修复建议")
    ai_group.add_argument("--ai-review", type=Path, metavar="FILE",
                          help="让 AI 直接审查指定源码文件")
    ai_group.add_argument("--ai-chat", action="store_true",
                          help="AI 分析后进入追问模式（回车或 Ctrl-D 退出）")
    ai_group.add_argument("--ai-model", help="模型名，如 deepseek-chat、qwen2.5-coder:7b")
    ai_group.add_argument("--ai-base-url",
                          help="OpenAI 兼容接口地址，如 https://api.deepseek.com/v1")
    ai_group.add_argument("--ai-key", help="API Key（建议改用环境变量 SECURITY_AI_API_KEY）")
    ai_group.add_argument("--ai-timeout", type=float, default=90.0, help="AI 请求超时秒数")
    ai_group.add_argument("--ai-max-findings", type=int, default=20, help="最多送分析的条目数")
    ai_group.add_argument("--ai-context-lines", type=int, default=2, help="每条结果附带的上下文行数")
    ai_group.add_argument("--ai-output", type=Path, help="把 AI 分析单独写入文件")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_rules:
        rendered = render_rules_markdown() if args.format == "markdown" else render_rules_text()
        if args.output:
            try:
                args.output.write_text(rendered + "\n", encoding="utf-8")
            except OSError as error:
                print(f"错误：无法写入 {args.output}：{error}", file=sys.stderr)
                return 2
            print(f"规则清单已写入 {args.output}", file=sys.stderr)
        else:
            print(rendered)
        return 0

    fingerprints: set[str] = set()
    if args.baseline:
        try:
            fingerprints = load_baseline(args.baseline)
        except ValueError as error:
            print(f"错误：{error}", file=sys.stderr)
            return 2

    if not args.authorized:
        print("错误：必须使用 --authorized 确认目标已获得授权。", file=sys.stderr)
        return 2
    if not args.source and not args.url:
        print("错误：请提供 --source 或 --url。", file=sys.stderr)
        return 2

    findings: list[dict] = []
    try:
        if args.source:
            if not args.source.exists():
                raise ValueError(f"源码路径不存在：{args.source}")
            findings.extend(source_findings(args.source, args.exclude, args.max_file_size))
        if args.url:
            findings.extend(http_findings(args.url, args.timeout))
    except ValueError as error:
        print(f"错误：{error}", file=sys.stderr)
        return 2

    suppressed = 0
    if fingerprints:
        findings, suppressed = apply_baseline(findings, fingerprints)

    if args.write_baseline:
        try:
            count = write_baseline(args.write_baseline, findings)
        except OSError as error:
            print(f"错误：无法写入基线 {args.write_baseline}：{error}", file=sys.stderr)
            return 2
        print(f"基线已写入 {args.write_baseline}（{count} 条）", file=sys.stderr)
        return 0

    # 退出码看的是「基线之外、显示过滤之前」的问题：
    # 基线是显式接受风险，而 --min-severity 只是控制输出噪声
    decision_findings = findings
    findings = filter_findings(findings, args.min_severity)

    output_format = "json" if args.json else args.format
    if output_format == "text":
        rendered = render_text(findings, suppressed)
    elif output_format == "json":
        rendered = render_json(findings, suppressed)
    elif output_format == "markdown":
        rendered = render_markdown(findings)
    else:
        rendered = render_sarif(findings)

    ai_text, ai_session = (None, None)
    if args.ai or args.ai_review:
        ai_text, ai_session = _run_ai(args, findings)
        if ai_text:
            if output_format == "sarif":
                print("提示：SARIF 结果不合并 AI 文本，可用 --ai-output 单独保存。", file=sys.stderr)
            else:
                rendered = _merge_ai(rendered, ai_text, output_format)

    if args.ai_output and ai_text:
        try:
            args.ai_output.write_text(ai_text + "\n", encoding="utf-8")
        except OSError as error:
            print(f"错误：无法写入 {args.ai_output}：{error}", file=sys.stderr)

    if args.output:
        try:
            args.output.write_text(rendered + "\n", encoding="utf-8")
        except OSError as error:
            print(f"错误：无法写入 {args.output}：{error}", file=sys.stderr)
            return 2
        print(f"结果已写入 {args.output}", file=sys.stderr)
    else:
        print(rendered)

    if args.ai_chat and ai_session is not None:
        _chat_loop(ai_session)

    return 1 if should_fail(decision_findings, args.fail_on) else 0


if __name__ == "__main__":
    raise SystemExit(main())
