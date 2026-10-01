# Real-Project Diagnostics / Failure Semantics 验收报告

本轮仅修改 diagnostics、failure semantics、capability aggregation、network reporting 和非 Git release scan。所有验收项目均隔离创建；真实引擎执行与 mock 明确区分。

## A. 起始 HEAD

`e50e9a6c0bac44056330c38c8670272001519696`。起点 `feature/runtime-mvp`，工作区干净；baseline：86 passed / 6 skipped / 5 subtests passed。

## B. 最终 HEAD

包含本报告的 `feature/runtime-mvp` 提交即交付 HEAD；确切 SHA 在最终交付消息中列出，可用 `git rev-parse HEAD` 获取。未修改、merge 或 rebase main。

## C. 修改文件

- `README.md`
- `README.zh-CN.md`
- `docs/REAL_PROJECT_DIAGNOSTICS.md`
- `docs/diagnostics-evidence.json`
- `docs/jeepay-diagnostics-evidence.json`
- `scripts/diagnostics_acceptance.py`
- `src/security_runtime/cli.py`
- `src/security_runtime/diagnostics.py`
- `src/security_runtime/integration_state.py`
- `src/security_runtime/mcp_server.py`
- `src/security_runtime/models.py`
- `src/security_runtime/processes.py`
- `src/security_runtime/runtime.py`
- `src/security_runtime/scanners.py`
- `src/security_runtime/toolchain.py`
- `src/security_runtime/workspace.py`
- `tests/test_diagnostics.py`
- `tests/test_doctor.py`
- `tests/test_tool_resolution.py`

## D. 新 Error Model

ScannerRun 保留 status、error，增加 error_code、error_summary、remediation、retry_after_seconds、diagnostic_detail、source、http_proxy、https_proxy。准备失败通过 ResolvedTool.diagnostic 使用同一模型。ProcessResult 内部携带 return_code、stdout、stderr、duration_ms；每个流最多 4 MB，版本检查最多 16 KB，超时/输出溢出 kill 进程。原始 stderr 不进入历史或 MCP；diagnostic_detail 仅保留规范化 return code。

## E. Network Error 分类表

| 分类 | 含义 |
|---|---|
| `NETWORK_TIMEOUT` | 连接、socket 或下载超时 |
| `CONNECTION_REFUSED` | 远端拒绝连接 |
| `DNS_RESOLUTION_FAILED` | 主机名解析失败 |
| `PROXY_CONNECTION_FAILED` | 代理连接失败 |
| `TLS_ERROR` | TLS 握手或证书验证失败 |
| `HTTP_401` | 远端认证失败 |
| `HTTP_403` | 远端拒绝访问 |
| `HTTP_404` | 资源不存在 |
| `HTTP_429` | 远端请求限流 |
| `HTTP_5XX` | 远端服务错误 |
| `DOWNLOAD_INTERRUPTED` | 连接重置、EOF 或不完整下载 |
| `OFFLINE_MODE` | 离线且缺少所需引擎/数据 |
| `CHECKSUM_MISMATCH` | 下载校验失败，拒绝使用 |
| `UNKNOWN_NETWORK_ERROR` | 无法进一步分类的网络失败 |
| `MAVEN_RATE_LIMITED` | 解析项目依赖时 Maven 仓库 HTTP 429 |

urllib、socket、TLS、pip/scanner stderr 共用分类器。Retry-After 支持秒数和 HTTP date。源 URL 仅展示 hostname。其他进程错误包括 PROCESS_TIMEOUT、OUTPUT_LIMIT_EXCEEDED、SCANNER_OUTPUT_OR_CONFIG_ERROR 等。

## F. Trivy Maven 429 输出

明确模拟：Java + pom.xml + application.yml，Semgrep SUCCESS、Gitleaks SUCCESS + 1 finding、Trivy 返回 Maven 429 和 Retry-After 1299。不是重新扫描真实 Jeepay。

```json
{
  "scanner": "trivy",
  "version": "mock",
  "status": "FAILED",
  "duration_ms": 7,
  "finding_count": 0,
  "error": "Maven repository returned HTTP 429 while resolving project dependencies.",
  "error_code": "MAVEN_RATE_LIMITED",
  "error_summary": "Maven repository returned HTTP 429 while resolving project dependencies.",
  "remediation": "Populate the local Maven cache, configure a Maven mirror, or retry after the repository rate limit clears.",
  "retry_after_seconds": 1299,
  "diagnostic_detail": "Return code: 1.",
  "source": "repo.maven.apache.org",
  "http_proxy": "not configured",
  "https_proxy": "not configured"
}
```

真实本机 Downloads/jeepay-master/jeepay-master 也已复验：doctor 和 doctor --verbose 通过；release 的 Semgrep/Gitleaks SUCCESS，9 个 findings 保留，scan/coverage PARTIAL。Trivy 真实 Maven 429，Retry-After 为 1692 秒（实际限流时间与 mock 1299 不同）。Source 为 repo.maven.apache.org，不是日志中的文档链接。详见 [jeepay-diagnostics-evidence.json](jeepay-diagnostics-evidence.json)。

```json
{
  "scanner": "trivy",
  "version": "0.74.0",
  "status": "FAILED",
  "duration_ms": 3325,
  "finding_count": 0,
  "error": "Maven repository returned HTTP 429 while resolving project dependencies.",
  "error_code": "MAVEN_RATE_LIMITED",
  "error_summary": "Maven repository returned HTTP 429 while resolving project dependencies.",
  "remediation": "Populate the local Maven cache, configure a Maven mirror, or retry after the repository rate limit clears.",
  "retry_after_seconds": 1692,
  "diagnostic_detail": "Return code: 1.",
  "source": "repo.maven.apache.org",
  "http_proxy": "not configured",
  "https_proxy": "not configured"
}
```

## G. Managed Tool 首次下载超时输出

GitHub urlopen mock TimeoutError，真实 ToolManager.ensure / tools install 路径：

```text
Gitleaks     BROKEN  Connection timed out while contacting the remote source.
Reason: Connection timed out while contacting the remote source.
Category: NETWORK_TIMEOUT
Source: github.com
HTTP proxy: not configured
HTTPS proxy: not configured
Suggestion: Check network connectivity, HTTPS_PROXY and remote service availability, then retry. Do not disable TLS verification.
Retry: security-check tools install gitleaks
```

## H. Proxy configured / not configured

未配置输出见 G；配置包含用户名、密码和 query 的测试代理后只显示配置标志：

```text
Gitleaks     BROKEN  Connection timed out while contacting the remote source.
Reason: Connection timed out while contacting the remote source.
Category: NETWORK_TIMEOUT
Source: github.com
HTTP proxy: not configured
HTTPS proxy: configured
Suggestion: Check network connectivity, HTTPS_PROXY and remote service availability, then retry. Do not disable TLS verification.
Retry: security-check tools install gitleaks
```

证据 JSON 不含测试代理凭据或原始 URL。

## I. Capability PARTIAL 聚合

```json
{
  "CODE_SAST": "EXECUTED",
  "SECRET_SCAN": "PARTIAL",
  "DEPENDENCY_VULN": "FAILED",
  "IAC_MISCONFIG": "FAILED"
}
```

Gitleaks 成功、Trivy 失败，因此 SECRET_SCAN 为 PARTIAL。IaC 没有完整完成证据，为 FAILED。1 finding 保留，status/coverage 均 PARTIAL，recommendation 为 BLOCKED。

真实 Jeepay 的 capability_results：

```json
{
  "CODE_SAST": "EXECUTED",
  "SECRET_SCAN": "PARTIAL",
  "DEPENDENCY_VULN": "FAILED",
  "IAC_MISCONFIG": "FAILED"
}
```

## J. Jeepay 风格 human output

以下是隔离 mock Maven fixture（1 个 synthetic finding）：

```text
AI Security Check

检查完成。
发现 1 个需要处理的问题。

HIGH
代码中包含一个可能有效的密钥
位置：application.yml:1
为什么危险：密钥泄露可能让他人访问系统或数据。
建议：立即撤销密钥，并改用环境变量或密钥管理服务。

结果：
建议先处理以下问题再继续；Security check completed with limited coverage.
Coverage: PARTIAL (planned files and checks only)

耗时：53 ms

Security checks

Executed
Code Security          EXECUTED

Partial
Secret Security        PARTIAL

Failed
Dependency Security    FAILED
IaC Security           FAILED

Why partial?
The 1 findings reported by completed checks remain valid. Failed or unavailable checks may leave additional issues undetected.
trivy mock: FAILED Maven repository returned HTTP 429 while resolving project dependencies.
Reason: Maven repository returned HTTP 429 while resolving project dependencies.
Category: MAVEN_RATE_LIMITED
Source: repo.maven.apache.org
Retry after: 1299 seconds
HTTP proxy: not configured
HTTPS proxy: not configured
Suggestion: Populate the local Maven cache, configure a Maven mirror, or retry after the repository rate limit clears.
Retry: security-check scan --mode release --path <project>
```

## K. JSON 输出

完整 CLI JSON 见 [diagnostics-evidence.json](diagnostics-evidence.json) 的 mock_maven_cli 最后一个记录。结果包含 capability_results 和 scanner_runs 结构化诊断；findings evidence 保持 `[REDACTED_SECRET]`。

## L. MCP 输出

真实 stdio MCP SDK 初始化并调用 scan_project，mock 引擎后端；返回以下 scanner diagnostic：

```json
{
  "scanner": "trivy",
  "version": "mock",
  "status": "FAILED",
  "duration_ms": 8,
  "finding_count": 0,
  "error": "Maven repository returned HTTP 429 while resolving project dependencies.",
  "error_code": "MAVEN_RATE_LIMITED",
  "error_summary": "Maven repository returned HTTP 429 while resolving project dependencies.",
  "remediation": "Populate the local Maven cache, configure a Maven mirror, or retry after the repository rate limit clears.",
  "retry_after_seconds": 1299,
  "diagnostic_detail": "Return code: 1.",
  "source": "repo.maven.apache.org",
  "http_proxy": "not configured",
  "https_proxy": "not configured"
}
```

SDK 能完整解码协议，未出现 scanner stdout 污染。现有五个工具保留；绑定 generic MCP 的非 Git scan_project 已测试，跨 workspace 请求仍拒绝。

## M. 非 Git release scan

实际 Git 与非 Git Python/requirements 示例分别执行 --version、doctor、doctor --verbose、tools status、release JSON 和 human 扫描。Semgrep 1.178.0、Gitleaks 8.30.0、Trivy 0.74.0 均 SUCCESS，真实 findings 保留。详情见 evidence.real_cli。Windows frozen Runtime 也分别对 Git / 非 Git 项目运行真实三引擎 release 并通过；预装引擎使用显式路径。

## N. 非 Git quick / feature

```text
Quick, feature and staged scans require Git. Use security-check scan --mode release --path <project> for a source directory.
```

模式要求 Git 的检查发生在引擎准备之前。Home、drive/system roots、symlink/junction、文件/目录数量、深度、大小和 ignored directories 保护保留。

## O. stderr redaction

Authorization、Proxy-Authorization、password/token/API key、XML Maven password、JSON 字段、URL userinfo/query、测试 secret 均有正式用例。Maven fixture 故意把 private markers 放入 stderr，断言 human、JSON、SQLite history、MCP 全部不含这些标记。两个真实子进程输出流各自有上限，超时子进程无法完成后续 sentinel 写入。

## P. pytest

最终完整 pytest：148 passed / 6 skipped / 5 subtests passed。新增诊断测试 62 个，含 macOS 平台父目录别名回归。6 个旧 E2E 因 managed Gitleaks/Trivy 不在全局 PATH 而 skip；独立实际验收通过 ToolManager 解析执行三个真实引擎。上一轮 alpha acceptance 脚本已通过：NO_CHANGES、Git 深目录 scope、稳定 fingerprint、verify before/after、MCP、集成状态、owned config exclude。

## Q. Compliance

licenses --check-distribution、generate_notices.py --check、tests/test_compliance.py 均通过。原有 engine licensing、first-party rules 和 source offer 保留。

## R. Package integrity

python -m build 成功产出 wheel/sdist；check_wheel.py 通过；verify_package.py 在干净 venv 安装 wheel 并验证 CLI / licensing 通过。

## S. Standalone / distribution

Windows x64 PyInstaller 构建、package_artifact.py、verify_artifact.py 解压 CLI/licensing/真实 MCP 五工具 smoke 通过。额外 frozen Git/non-Git 项目真实三引擎 release 均 SUCCESS；distribution 和 acceptance 单元回归通过。此次本地没有重新下载全新的 managed Semgrep/CPython，使用预装引擎。Linux/macOS native artifacts 由提交后的 Actions 验证，最终状态在交付消息中注明。

## T. 尚未解决 / 边界

Java DB 仅检查本地文件，不新增自动下载；checks 保守 UNKNOWN。READY 表示基础本地前提而非项目扫描成功。分类器对常见异常和 stderr 尽力分类，未识别的网络错误用 UNKNOWN_NETWORK_ERROR。原始 stderr 不持久化，无法通过历史重新阅读任意工具日志；可恢复动作和 return code 保留。没有运行目标项目构建/依赖安装命令，没有发布 WinGet/Homebrew 或加入新 scanner。
