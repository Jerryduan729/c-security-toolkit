#!/usr/bin/env python3
"""AI 分析模块：把静态扫描结果交给大模型，生成风险解释与可落地的修复建议。

兼容 OpenAI 风格的 `/chat/completions` 接口，因此可以接 OpenAI、DeepSeek、
通义千问（DashScope 兼容模式）、Kimi、智谱、Ollama、LM Studio 等服务。
只依赖标准库，不引入第三方 SDK。

配置优先级：命令行参数 > 环境变量 > 默认值
    SECURITY_AI_API_KEY   API Key（兼容 OPENAI_API_KEY / DEEPSEEK_API_KEY）
    SECURITY_AI_BASE_URL  接口地址（如 https://api.deepseek.com/v1）
    SECURITY_AI_MODEL     模型名（如 deepseek-chat、qwen2.5-coder:7b）
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence
from urllib.parse import urlparse


DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_MODEL = "gpt-4o-mini"
MAX_PROMPT_CHARS = 14000
MAX_REVIEW_CHARS = 12000
MAX_LINE_CHARS = 180

SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

SECRET_PATTERN = re.compile(
    r"((?:passwd|password|pwd|secret|token|api[_-]?key|access[_-]?key)"
    r"\s*[=:]\s*[\"'])([^\"'\n]{1,200})([\"'])",
    re.IGNORECASE,
)
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN ([A-Z ]*PRIVATE KEY)-----.*?-----END \1-----",
    re.DOTALL,
)

SYSTEM_PROMPT = """你是一名资深应用安全工程师，正在评审一个 C 语言课程项目的自动扫描结果。

输出要求：
1. 开头用 2~3 句话给出总体风险判断，并明确指出「最该先修的一项」。
2. 逐条分析：攻击者如何利用（结合给出的具体代码）、可能后果、修复方案。
3. 修复方案必须给出可直接替换的 C 代码，而不是泛泛而谈；涉及函数替换时写出完整调用，
   并尽量引用规则给出的 CWE 编号说明漏洞类型。
4. 按修复优先级排序，标注「立即修复 / 本周修复 / 可延后」。
5. 若某条判断为误报，说明理由，不要硬凑风险。
6. 只依据给出的代码和扫描结果，不要编造未出现的文件、函数或行号；信息不足时说明还需要什么。
7. 使用简体中文，Markdown 输出，不要重复粘贴原始 JSON。"""

USER_TEMPLATE = """下面是一次静态代码扫描的结果（C 语言课程项目，规则为行级正则，可能存在误报）：

{findings}

请按系统要求输出 Markdown 分析。"""

REVIEW_TEMPLATE = """请审查下面这份源代码文件，找出其中的安全性问题（缓冲区溢出、格式化字符串、
命令注入、整数溢出、权限、密钥硬编码等）。

文件：{name}

```c
{code}
```

按以下结构输出 Markdown：
1. 总体结论（是否存在高危问题）
2. 问题清单：位置（行号）、风险、攻击方式、修复代码
3. 若没有发现问题，说明这份代码在安全上的可取之处与仍建议加固的点"""


class AIError(RuntimeError):
    """调用 AI 服务失败。"""


class _Retryable(AIError):
    """可重试的临时故障（限流、5xx、网络抖动）。"""


# --------------------------------------------------------------------------
# 配置
# --------------------------------------------------------------------------

@dataclass
class AIConfig:
    api_key: str = ""
    base_url: str = DEFAULT_BASE_URL
    model: str = DEFAULT_MODEL
    timeout: float = 90.0
    max_tokens: int = 1600
    temperature: float = 0.2
    retries: int = 2

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key and self.model)

    @classmethod
    def from_env(
        cls,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        timeout: float | None = None,
    ) -> "AIConfig":
        env = os.environ
        env_key = env.get("SECURITY_AI_API_KEY") or env.get("OPENAI_API_KEY")
        env_base = env.get("SECURITY_AI_BASE_URL") or env.get("OPENAI_BASE_URL")
        env_model = env.get("SECURITY_AI_MODEL")

        # 只配了 DeepSeek Key 时自动切到 DeepSeek 的兼容接口
        if not env_key and env.get("DEEPSEEK_API_KEY"):
            env_key = env["DEEPSEEK_API_KEY"]
            env_base = env_base or "https://api.deepseek.com/v1"
            env_model = env_model or "deepseek-chat"

        return cls(
            api_key=api_key or env_key or "",
            base_url=base_url or env_base or DEFAULT_BASE_URL,
            model=model or env_model or DEFAULT_MODEL,
            timeout=timeout if timeout is not None else 90.0,
        )


def _normalize_endpoint(base_url: str) -> str:
    parsed = urlparse(base_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise AIError(f"AI 接口地址无效：{base_url}")
    if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise AIError("为避免 API Key 明文传输，远程接口必须使用 https；本地模型可用 http://localhost")
    return base_url.rstrip("/")


# --------------------------------------------------------------------------
# HTTP 客户端
# --------------------------------------------------------------------------

class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """禁止自动跳转，避免把 Authorization 头带到别的主机。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _error_detail(error: urllib.error.HTTPError) -> str:
    try:
        raw = error.read().decode("utf-8", "replace")
    except Exception:  # noqa: BLE001 - 读取失败不影响主流程
        return error.reason or ""
    try:
        payload = json.loads(raw)
        message = payload.get("error", {}).get("message") if isinstance(payload, dict) else None
        return (message or raw).strip()[:300]
    except json.JSONDecodeError:
        return raw.strip()[:300]


def _extract_content(payload: dict) -> str:
    try:
        choice = payload["choices"][0]
    except (KeyError, IndexError, TypeError) as error:
        raise AIError("AI 返回结构异常，缺少 choices 字段") from error
    message = choice.get("message") or {}
    content = message.get("content")
    if isinstance(content, list):
        content = "".join(
            part.get("text", "") for part in content if isinstance(part, dict)
        )
    if not content:
        content = choice.get("text", "")
    if not content:
        raise AIError("AI 返回了空内容，请稍后重试或更换模型")
    return str(content).strip()


class AIClient:
    def __init__(self, config: AIConfig) -> None:
        self.config = config
        self._endpoint = _normalize_endpoint(config.base_url) + "/chat/completions"

    def chat(self, messages: Sequence[dict]) -> str:
        if not self.config.api_key:
            raise AIError("未配置 API Key")
        payload = {
            "model": self.config.model,
            "messages": list(messages),
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "stream": False,
        }
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.config.api_key}",
            "User-Agent": "Security-Scanner-AI/1.0",
        }

        last_error: AIError | None = None
        for attempt in range(self.config.retries + 1):
            try:
                return self._post(body, headers)
            except _Retryable as error:
                last_error = error
                if attempt < self.config.retries:
                    time.sleep(min(2 ** attempt, 4))
        raise AIError(str(last_error) if last_error else "AI 调用失败")

    def _post(self, body: bytes, headers: dict) -> str:
        request = urllib.request.Request(
            self._endpoint, data=body, headers=headers, method="POST"
        )
        opener = urllib.request.build_opener(_NoRedirectHandler)
        try:
            with opener.open(request, timeout=self.config.timeout) as response:
                raw = response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as error:
            detail = _error_detail(error)
            if error.code in (401, 403):
                raise AIError(f"认证失败（HTTP {error.code}），请检查 API Key：{detail}")
            if error.code == 404:
                raise AIError(
                    f"接口或模型不存在（HTTP 404），请检查 --ai-base-url 与 --ai-model：{detail}"
                )
            if error.code in (408, 409, 429) or error.code >= 500:
                raise _Retryable(f"AI 服务暂时不可用（HTTP {error.code}）：{detail}")
            raise AIError(f"AI 请求失败（HTTP {error.code}）：{detail}")
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise _Retryable(f"无法连接 AI 服务：{getattr(error, 'reason', error)}")

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as error:
            raise AIError("AI 返回内容不是 JSON，可能被代理或网关改写") from error
        return _extract_content(payload)


# --------------------------------------------------------------------------
# 提示词构建
# --------------------------------------------------------------------------

def redact(text: str) -> str:
    """脱敏：密钥值、私钥内容不进模型上下文。"""
    text = SECRET_PATTERN.sub(r"\1***\3", text)
    return PRIVATE_KEY_PATTERN.sub(r"-----BEGIN \1-----（已脱敏）-----END \1-----", text)


def _read_lines(path: Path) -> list[str]:
    try:
        raw = path.read_bytes()
    except OSError:
        return []
    for encoding in ("utf-8", "gb18030"):
        try:
            return raw.decode(encoding).splitlines()
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1", "replace").splitlines()


def _context_block(path: Path, line: int, radius: int) -> str:
    if radius <= 0 or line <= 0:
        return ""
    lines = _read_lines(path)
    if not lines or line > len(lines):
        return ""
    start = max(1, line - radius)
    end = min(len(lines), line + radius)
    rendered = []
    for number in range(start, end + 1):
        text = redact(lines[number - 1].rstrip())[:MAX_LINE_CHARS]
        marker = ">" if number == line else " "
        rendered.append(f"{marker} {number:>4} | {text}")
    return "\n".join(rendered)


def _format_finding(index: int, finding: dict, context_lines: int) -> str:
    location = finding.get("file") or finding.get("url") or ""
    if finding.get("line"):
        location = f"{location}:{finding['line']}"
    parts = [
        f"### {index}. [{finding.get('severity', 'INFO')}] "
        f"{finding.get('id', '')} {finding.get('name', '')}",
        f"- 位置：{location or '未知'}",
        f"- 说明：{redact(finding.get('message', ''))}",
    ]
    if finding.get("cwe"):
        parts.append(f"- 分类：{finding['cwe']}")
    if finding.get("fix"):
        parts.append(f"- 工具建议：{redact(finding['fix'])}")
    if finding.get("evidence"):
        parts.append(f"- 命中代码：`{redact(finding['evidence'])}`")
    if finding.get("file") and finding.get("line"):
        block = _context_block(Path(finding["file"]), int(finding["line"]), context_lines)
        if block:
            parts.append("- 上下文：\n```c\n" + block + "\n```")
    return "\n".join(parts)


def build_messages(
    findings: Sequence[dict],
    *,
    max_findings: int = 20,
    context_lines: int = 2,
) -> list[dict]:
    ordered = sorted(
        findings, key=lambda item: SEVERITY_RANK.get(item.get("severity", "INFO"), 9)
    )[: max(1, max_findings)]

    blocks: list[str] = []
    total = 0
    for index, finding in enumerate(ordered, 1):
        block = _format_finding(index, finding, context_lines)
        if total + len(block) > MAX_PROMPT_CHARS:
            break
        blocks.append(block)
        total += len(block)

    body = "\n\n".join(blocks) if blocks else "（本次扫描没有发现问题）"
    if len(ordered) > len(blocks):
        body += f"\n\n（篇幅限制，仅列出前 {len(blocks)} 条，共 {len(findings)} 条。）"
    elif len(findings) > len(ordered):
        body += f"\n\n（仅列出最严重的 {len(ordered)} 条，共 {len(findings)} 条。）"

    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": USER_TEMPLATE.format(findings=body)},
    ]


def build_review_messages(path: Path, code: str) -> list[dict]:
    truncated = ""
    if len(code) > MAX_REVIEW_CHARS:
        code = code[:MAX_REVIEW_CHARS]
        truncated = "\n\n（文件过长，仅提供前 12000 个字符。）"
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": REVIEW_TEMPLATE.format(name=path.name, code=redact(code) + truncated)},
    ]


# --------------------------------------------------------------------------
# 会话与高层接口
# --------------------------------------------------------------------------

class AISession:
    """保存对话上下文，支持分析后继续追问。"""

    def __init__(self, messages: Sequence[dict], config: AIConfig | None = None) -> None:
        self.config = config or AIConfig.from_env()
        self.client = AIClient(self.config)
        self.messages: list[dict] = list(messages)

    def start(self) -> str:
        return self._send()

    def ask(self, question: str) -> str:
        self.messages.append({"role": "user", "content": question})
        return self._send()

    def _send(self) -> str:
        answer = self.client.chat(self.messages)
        self.messages.append({"role": "assistant", "content": answer})
        return answer


def analyze(
    findings: Sequence[dict],
    config: AIConfig | None = None,
    *,
    max_findings: int = 20,
    context_lines: int = 2,
) -> str:
    session = AISession(
        build_messages(findings, max_findings=max_findings, context_lines=context_lines),
        config,
    )
    return session.start()


def review_source(path: Path, config: AIConfig | None = None) -> str:
    if not path.is_file():
        raise AIError(f"待审查文件不存在：{path}")
    lines = _read_lines(path)
    if not lines:
        raise AIError(f"无法读取文件内容：{path}")
    session = AISession(build_review_messages(path, "\n".join(lines)), config)
    return session.start()
