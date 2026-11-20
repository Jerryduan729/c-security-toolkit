# Security Toolkit

面向 C 语言课程项目的**软件安全性测试工具**：源码静态检查、授权目标的 HTTP/TLS 检查，
可选接入大模型生成修复建议，并提供网页界面与可打印的 HTML 报告。

只依赖 Python 标准库。所有代码、示例、文档、报告都在本目录内，拷贝整个 `安全/` 就能运行。

## 项目结构

```
安全/
├── security_scan.py        主程序：规则引擎、HTTP/TLS 检查、报告输出、AI 入口
├── ai_advisor.py           AI 客户端：提示词构建、密钥脱敏、追问会话
├── web_app.py              本地网页服务
├── web/index.html          网页界面（样式脚本内联，零依赖）
├── run.sh                  一键启动网页界面
├── examples/               教学示例：vulnerable_demo.c / safe_demo.c
├── docs/                   规则清单、答辩演示脚本
├── reports/                导出的 HTML 报告
├── .securityignore         扫描忽略清单
├── test_security_scan.py   扫描与报告测试（41 项）
├── test_ai_advisor.py      AI 模块测试（15 项）
├── test_web_app.py         网页接口测试（12 项）
└── README.md
```

共 68 项单元测试，`python3 -m unittest` 一键运行。

## 快速开始

```bash
./run.sh                                                        # 打开网页界面
python3 security_scan.py --authorized --source examples         # 扫描教学示例（9 条结果）
python3 security_scan.py --authorized --source ../test          # 扫描课程 C 源码
python3 security_scan.py --authorized --url https://example.com # 检查授权站点
python3 security_scan.py --list-rules                           # 查看全部规则与修复建议
python3 security_scan.py --authorized --source examples --format sarif   # 输出给 CI
python3 -m unittest -v                                          # 运行 68 项测试
```

`--authorized` 是强制项，用于确认目标由你拥有或已获得书面授权。

实测输出（本课程 `test/` 目录）：

```
共发现 1 条结果（CRITICAL 1）

[CRITICAL] SEC-101 禁用 gets ../test/2.1.3.c:7
  gets 无法限制输入长度，必然导致缓冲区溢出，C11 起已被移除。
  代码：gets(s1);
  CWE-242 · 修复：fgets(buf, sizeof buf, stdin) 并检查返回值
```

退出码为 `1`，可直接接入 CI 或提交前钩子。

## 示例与文档

| 路径 | 说明 |
| --- | --- |
| `examples/vulnerable_demo.c` | 故意保留 8 类问题的教学代码，扫描得 9 条结果（CRITICAL 1 / HIGH 4 / MEDIUM 4） |
| `examples/safe_demo.c` | 加固后的写法，扫描零结果，用来证明不是「见谁咬谁」 |
| `docs/规则清单.md` | 17 条静态规则的 CWE 编号与修复建议，由 `--list-rules` 生成，不会和代码走偏 |
| `docs/答辩演示.md` | 5 分钟演示脚本：操作步骤、要讲的话、常见提问的回答 |

示例目录被 `.securityignore` 排除，所以扫描整个 `安全/` 不会把故意留的漏洞算进来；
需要演示时显式 `--source examples` 即可。

## 接入 AI

扫描器只认「行级正则」，能发现问题但说不清危害。加上 `--ai` 后，工具会把扫描结果、命中代码
和上下文行交给大模型，生成一段可直接写进实验报告的分析：

```
共发现 1 条结果（CRITICAL 1）
[CRITICAL] SEC-101 禁用 gets ../test/2.1.3.c:7
  ...
------------------------------------------------------------
AI 安全分析
------------------------------------------------------------

## 总体判断
最该先修的是 test/2.1.3.c:7 的 gets：它在 char s1[80] 上无长度限制读取，
输入超过 79 字节即可覆盖栈上返回地址，属于可稳定触发的栈溢出。

### 1. 立即修复：禁用 gets
- 攻击方式：……
- 修复：
```c
if (fgets(s1, sizeof s1, stdin) == NULL) { return 1; }
s1[strcspn(s1, "\n")] = '\0';
```
```

### 支持的模型服务

接口按 OpenAI 的 `/chat/completions` 协议实现，因此主流服务都能直接接：

| 服务 | `--ai-base-url` | 模型示例 | Key 环境变量 |
| --- | --- | --- | --- |
| OpenAI | `https://api.openai.com/v1` | `gpt-4o-mini` | `OPENAI_API_KEY` |
| DeepSeek | `https://api.deepseek.com/v1` | `deepseek-chat` | `DEEPSEEK_API_KEY` |
| 通义千问 | `https://dashscope.aliyuncs.com/compatible-mode/v1` | `qwen-plus` | `SECURITY_AI_API_KEY` |
| Kimi | `https://api.moonshot.cn/v1` | `moonshot-v1-8k` | `SECURITY_AI_API_KEY` |
| 智谱 GLM | `https://open.bigmodel.cn/api/paas/v4` | `glm-4-flash` | `SECURITY_AI_API_KEY` |
| Ollama 本地 | `http://localhost:11434/v1` | `qwen2.5-coder:7b` | 任意值，如 `ollama` |

地址与模型名以各厂商文档为准；本地模型用 `http://localhost` 即可，远程地址强制 HTTPS。

### 配置与用法

```bash
# 1) 用环境变量（推荐，避免 Key 进入 shell 历史）
export SECURITY_AI_API_KEY=sk-xxxxxxxx
python3 security_scan.py --authorized --source ../test --ai

# 2) 只配了 DeepSeek Key 时会自动切到 DeepSeek 接口
export DEEPSEEK_API_KEY=sk-xxxxxxxx
python3 security_scan.py --authorized --source ../test --ai

# 3) 指定服务与模型
python3 security_scan.py --authorized --source ../test --ai \
  --ai-base-url https://api.deepseek.com/v1 --ai-model deepseek-chat

# 4) 本地 Ollama，不联网、不花钱
python3 security_scan.py --authorized --source ../test --ai \
  --ai-base-url http://localhost:11434/v1 --ai-model qwen2.5-coder:7b --ai-key ollama
```

三种 AI 能力：

| 参数 | 作用 |
| --- | --- |
| `--ai` | 分析扫描结果，给出总体判断、逐条攻击路径与修复代码 |
| `--ai-review FILE` | 跳过规则，让 AI 直接通读一个源码文件做安全审查 |
| `--ai-chat` | 分析结束后进入追问模式，可继续问「怎么改」「有没有误报」 |
| `--ai-output FILE` | 把 AI 分析单独写一份文件，便于贴进实验报告 |

`--ai` 可与 `--format markdown/json` 组合：Markdown 报告会自动追加「## AI 安全分析」章节，
JSON 结果会多一个 `ai_analysis` 字段。

### 隐私与成本

- **只发必要内容**：扫描结果 + 命中行 ±2 行上下文（`--ai-context-lines` 可调），不上传整个仓库；
  只有 `--ai-review` 才会发送整份文件（超过 12000 字符会截断）。
- **自动脱敏**：`password="..."`、`api_key="..."` 的值和 PEM 私钥块在进入提示词前替换为 `***`，
  API Key 本身也从不写入提示词。
- **传输安全**：远程接口必须 HTTPS；关闭 HTTP 自动跳转，避免 `Authorization` 头被带到其他主机。
- **成本可控**：默认最多送 20 条（`--ai-max-findings`），提示词总长上限约 1.4 万字符。
- **失败不影响扫描**：未配置 Key、网络不通、限流时只在 stderr 提示，扫描结果照常输出，退出码不变。

## 网页界面（答辩演示）

```bash
python3 web_app.py --port 8765 --open
```

左侧填源码路径、目标 URL、最低级别，点「开始扫描」；右侧出现汇总卡片与结果列表（含命中代码）。
点「生成 AI 分析」把结果交给模型，可继续在下方追问；点「导出 HTML 报告」生成
`reports/security-report-YYYYMMDD-HHMMSS.html`，自带打印样式，可直接交作业或全屏演示。

| 区域 | 说明 |
| --- | --- |
| 扫描配置 | 源码路径 / URL、最低级别、AI 开关、模型与接口地址 |
| 结果汇总 | CRITICAL / HIGH / MEDIUM / LOW / INFO 五档计数 |
| 结果列表 | 规则编号、名称、文件:行号、命中代码 |
| AI 面板 | 模型名、分析正文（含代码块）、追问输入 |
| 导出 | 独立 HTML 报告：扫描目标、耗时、结果表、AI 章节 |

安全设计：

- 只监听 `127.0.0.1`，不对外网开放；
- 每次启动生成一次性令牌并注入页面，所有写接口校验 `X-Token`，同机其他网页无法调用；
- 报告文件名白名单校验，杜绝 `../` 目录穿越；
- API Key 只从环境变量读取，不在网页输入、不进入前端代码。

> 没有联网环境时，界面照样能扫描和导出报告，只是 AI 面板会提示未配置 Key。

## 静态检查规则

17 条静态规则都带 CWE 编号和修复建议，代码里定义、`--list-rules` 输出、报告展示三处一致；
完整清单见 [`docs/规则清单.md`](docs/规则清单.md)（由 `--list-rules --format markdown` 生成）。

### 通用规则（所有语言）

| 编号 | 级别 | 问题 |
| --- | --- | --- |
| SEC-001 | HIGH | 硬编码密码、API Key、Token |
| SEC-002 | HIGH | SQL 语句拼接 |
| SEC-003 | HIGH | 禁用 TLS 证书/主机名校验 |
| SEC-004 | CRITICAL | `eval` / `exec` / `os.system` / `shell=True` 等动态执行 |
| SEC-005 | MEDIUM | MD5、SHA1、DES、RC4、ECB 等弱算法 |
| SEC-006 | MEDIUM | `tmpnam` / `tempnam` / `mktemp` 竞态风险 |
| SEC-007 | CRITICAL | 私钥内容被写入源码 |

### C / C++ 规则（`.c .h .cpp .cc .cxx .hpp .hh`）

| 编号 | 级别 | 问题 | 安全写法 |
| --- | --- | --- | --- |
| SEC-101 | CRITICAL | `gets()` 无法限长，C11 已移除 | `fgets(buf, sizeof buf, stdin)` |
| SEC-102 | HIGH | `strcpy` / `strcat` / `sprintf` 不检查目标容量 | `snprintf`、`strlcpy`、先判长度 |
| SEC-103 | HIGH | `scanf("%s")` 未指定宽度 | `scanf("%15s", name)` |
| SEC-104 | HIGH | `system` / `popen` 拼接外部输入 | `execve` + 参数数组，或白名单校验 |
| SEC-105 | MEDIUM | 用变量当格式串 | `printf("%s", buf)` |
| SEC-106 | MEDIUM | `alloca` 按不可信长度分配 | 改用堆分配并检查返回值 |
| SEC-107 | MEDIUM | `malloc(a * b)` 乘法整数溢出 | 先判断 `a > SIZE_MAX / b` |
| SEC-108 | MEDIUM | `srand(time(NULL))` 生成令牌 | 用 `/dev/urandom` 或 `getrandom()` |
| SEC-109 | HIGH | 格式串含 `%n` | 禁止外部输入进入格式串 |
| SEC-110 | MEDIUM | `chmod 0777` / `umask(0)` | 最小权限（0644 / 0600） |

C 规则只对 C/C++ 后缀生效，不会把 Python 里的同名标识符误判。

## 网络检查项

| 编号 | 级别 | 检查内容 |
| --- | --- | --- |
| PROTO-001 | MEDIUM | 目标使用明文 HTTP |
| HTTP-001 | MEDIUM | 缺少 CSP / HSTS / X-Content-Type-Options / X-Frame-Options / Referrer-Policy |
| HTTP-002 | LOW | HSTS `max-age` 小于 180 天 |
| HTTP-003 | LOW | `Server` / `X-Powered-By` 泄漏技术栈 |
| HTTP-004 | LOW | `X-Content-Type-Options` 存在但不是 `nosniff` |
| TLS-001 | HIGH | 证书校验失败或握手失败 |
| TLS-002 | HIGH | 证书已过期 |
| TLS-003 | MEDIUM | 协商出 TLS 1.0/1.1 或 SSL |
| TLS-004 | LOW | 证书 30 天内过期 |
| COOKIE-001/002/003 | MEDIUM/LOW | Cookie 缺少 SameSite / Secure / HttpOnly |
| REDIR-001/002/003 | HIGH | 重定向到非 HTTP 协议、HTTPS 降级、跳向内网 |
| NET-001 / INFO-001 | INFO | 目标不可访问 / 最终响应状态码 |

### SSRF 防护

- 解析出的**任意**一个 IP 不是全局地址（私网、回环、链路本地、保留、组播）即拒绝；
- 关闭 urllib 的自动跳转，逐跳重新校验，防止 `302 → 127.0.0.1` 绕过；
- 最多跟随 5 跳，跳转目标必须是 http/https。

## 命令行参数

| 参数 | 说明 |
| --- | --- |
| `--source PATH` | 扫描源码文件或目录（递归） |
| `--url URL` | 检查授权的 HTTP/HTTPS 地址 |
| `--authorized` | **必填**，确认已获授权 |
| `--format {text,json,markdown,sarif}` | 输出格式，默认 `text`；`sarif` 可接 GitHub Code Scanning / SonarQube |
| `--json` | 等价于 `--format json`（兼容旧用法） |
| `--output PATH` | 结果写入文件 |
| `--list-rules` | 打印全部规则与修复建议后退出（不需 `--authorized`） |
| `--baseline FILE` | 按基线文件忽略已接受的历史问题 |
| `--write-baseline FILE` | 把当前结果写成基线后退出 |
| `--fail-on LEVEL` | 达到该级别返回退出码 1，默认 `high` |
| `--version` | 打印版本号 |
| `--min-severity LEVEL` | 只输出不低于该级别的结果 |
| `--exclude GLOB` | 跳过路径，可重复，如 `--exclude 'test/*'` |
| `--max-file-size N` | 单文件扫描上限，默认 2 MiB |
| `--timeout N` | 网络超时秒数，默认 5 |
| `--ai` / `--ai-review` / `--ai-chat` | AI 分析 / 整文件审查 / 追问 |
| `--ai-model` / `--ai-base-url` / `--ai-key` | 模型与接口配置 |
| `--ai-max-findings` / `--ai-context-lines` | 送分析的条目数、附带的上下文行数 |
| `--ai-timeout` / `--ai-output` | AI 超时、单独输出文件 |

退出码：`0` 未达到 `--fail-on` 阈值，`1` 达到阈值，`2` 参数或目标非法。
阈值判断基于「基线之外、显示过滤之前」的结果：`--min-severity` 只影响输出内容，不会把风险过滤成 0；
`--baseline` 则是**显式接受风险**，对应条目不再触发失败。

## 接入 CI：阈值与基线

三道闸门可以组合使用：

```bash
# 1) 新代码：HIGH 及以上失败（默认），MEDIUM 只提示不拦
python3 security_scan.py --authorized --source src --fail-on high

# 2) 存量项目：先把现有问题记成基线，之后只对新增问题报警
python3 security_scan.py --authorized --source src --write-baseline .security-baseline.json
python3 security_scan.py --authorized --source src --baseline .security-baseline.json

# 3) 输出 SARIF 交给平台（GitHub Code Scanning / SonarQube）
python3 security_scan.py --authorized --source src --format sarif --output report.sarif
```

带基线扫描时的输出会明确写出忽略了多少条：

```
未发现新问题（已按基线忽略 9 条）。
```

基线指纹由「规则编号 + 文件名 + 命中代码」计算，**行号移动不会失效**，适合持续迭代的代码；
同一文件里两处完全相同的写法会被视为同一条，这是简化方案的取舍。

## 忽略机制

**单行忽略**（当行或上一行，C 用 `//`，Python 用 `#`）：

```c
gets(buf);              // security-scan: ignore
```

**目录级忽略**：在任意目录放 `.securityignore`，写法同 `.gitignore`，支持 `#` 注释、通配符和目录名：

```
vendor/
build/*.c
legacy_*.c
```

本目录的 `.securityignore` 排除了扫描器自身与测试用例——规则表和测试数据里写着 `md5`、`eval`、`gets`
这些**待检测字符串**，属于样例数据，不排除会造成自检误报。

## 已知局限

- 规则是**行级正则**，不做 AST、控制流或数据流分析，无法发现释放后使用、堆溢出、竞态等需要语义判断的问题；
- `examples/` 里的代码**故意保留漏洞**，只用于演示检出效果，不要照抄进作业或项目；
- 注释会被剥离以减少误报，但字符串内的内容仍按原文匹配，可能存在少量误报，用 `security-scan: ignore` 标注即可；
- AI 分析基于扫描片段，可能给出不准确或过度保守的结论，**必须人工复核**后再写进报告或提交代码；
- 基线指纹只取「规则 + 文件名 + 命中代码」，同一文件里两处完全相同的写法会被视为同一条；
  重命名文件或改写代码会让对应基线失效，需要重新生成；
- 网络检查只请求入口页面，不爬取、不爆破、不尝试利用；
- 结果用于自查和课程演示，不能替代人工代码审计或专业渗透测试。

仅对你拥有或已获明确授权的系统使用本工具。
