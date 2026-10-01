# CLI Progress / Feedback UX 验收（A–X）

## A. 起始 HEAD

`1d628ac3209a88d7be06442fa28c9ffe1e4fcb11`，`feature/runtime-mvp`。
开始时执行 status、branch、log -5，工作区干净。baseline：148 passed、6 skipped、5 subtests。

## B. 最终 HEAD

最终提交 SHA 随交付回复提供；本报告与实现同一提交，可用 `git rev-parse HEAD` 核对。
仅提交并 push `feature/runtime-mvp`，不修改、merge 或 rebase main。

## C. 修改文件

- `src/security_runtime/progress.py`、`cli_progress.py`、`human.py`
- `src/security_runtime/cli.py`、`runtime.py`、`scanners.py`、`toolchain.py`、`processes.py`、`models.py`
- `tests/test_progress.py`、`test_alpha_acceptance.py`、`test_diagnostics.py`
- `scripts/progress_acceptance.py`、两份 README
- 本报告、`progress-evidence.json`、`jeepay-progress-stderr.txt`、`jeepay-progress-stdout.txt`

## D. Progress Event 模型

不可变结构化事件：event_type、UTC timestamp、component、message、elapsed_ms、scanner、
scanner_version、capability、duration_ms、finding_count、error_code、source。
支持 SCAN、WORKSPACE_DISCOVERY、TARGET_DISCOVERY、PLANNING、PLAN、ENGINE、SCANNER 生命周期，
以及引擎下载、Python 环境准备、漏洞库准备和取消事件。字符串有界脱敏，不包含 ANSI、原始 scanner 日志或凭据。
ProgressReporter 通过 ContextVar 隔离调用，worker 复制上下文；默认 NullProgressReporter 无输出。
进度事件不持久化、不上传。原有 findings、coverage 和诊断字段保持语义，ScannerRun 新增 capabilities 元数据。

## E. CLI Renderer

标准库实现，唯一目标流是 stderr。500 ms 延迟和 128 条有界事件缓冲使短任务安静。
一条后台 heartbeat 线程，100 ms 等待 tick；只展示真实计划中的引擎。
事件由完成的 worker 立即发出，不等待注册顺序中的慢引擎。UI sink 失败不影响扫描结果。
不增加文件发现或版本命令，不写进度磁盘、不预测百分比。

## F. TTY 示例

```text
/ trivy 0.74.0 · 正在运行 · 5s
- trivy 0.74.0 · 正在运行 · 10s
\ trivy 0.74.0 · 正在运行 · 15s
trivy 0.74.0 失败 · 16.0s · MAVEN_RATE_LIMITED
```

stderr.isatty() 选择模式；每秒用 CR 清理并刷新一行，按终端列数和中文字宽截断。
上例为内存 TTY renderer 演示与单元测试，不宣称真实 Jeepay 在交互终端录屏验收。

## G. 非 TTY 示例

```text
[17:52:37]  正在检查代码 · 模式：release
[17:52:37]  正在识别项目
[17:52:37]  项目识别完成 · 项目：jeepay-master
[17:52:37]  正在发现扫描文件
[17:52:38]  扫描文件发现完成 · 650 个扫描文件
[17:52:38]  正在规划安全检查
[17:52:38]  安全检查计划已准备 · 将执行 3 个安全引擎
[17:52:38] semgrep 1.178.0 正在准备引擎
[17:52:38] gitleaks 8.30.0 正在准备引擎
[17:52:38] trivy 0.74.0 正在准备引擎
[17:52:38] trivy 0.74.0 引擎已就绪
[17:52:38] trivy 0.74.0 正在运行
[17:52:38] gitleaks 8.30.0 引擎已就绪
[17:52:38] gitleaks 8.30.0 正在运行
[17:52:40] semgrep 1.178.0 引擎已就绪
[17:52:40] semgrep 1.178.0 正在运行
[17:52:41] gitleaks 8.30.0 完成 · 9 个问题 · 2.6s
[17:52:41] trivy 0.74.0 失败 · 0 个问题 · 3.4s · MAVEN_RATE_LIMITED · 来源：repo.maven.apache.org
仍在处理 semgrep 1.178.0 · 正在运行 · 8s
仍在处理 semgrep 1.178.0 · 正在运行 · 18s
仍在处理 semgrep 1.178.0 · 正在运行 · 28s
[17:53:16] semgrep 1.178.0 完成 · 0 个问题 · 38.2s
[17:53:16]  检查结束 · 9 个问题 · 39.1s

```

一行一个事件，没有 CR/ANSI 控制字符。长任务每 10 秒一条 heartbeat。

## H. --json 流隔离

真实普通源码 fixture 使用 Semgrep/Gitleaks/Trivy 执行 release，stdout 可直接 json.loads，
包含 findings 和英文状态枚举；progress 仅在 stderr。证据 `progress-evidence.json` 的 json 节。
MCP 默认不开启 renderer；现有五工具与官方 stdio initialize/list_tools/scan_diff 回归保持通过。

## I. --no-progress

相同 fixture 的 `--json --no-progress` stdout 仍为纯 JSON，stderr 为空。
human/JSON × 有/无 progress 四种组合均覆盖。致命 CLI 错误和取消仍可写 stderr。

## J. 首次引擎准备与下载

独立临时 ToolManager data dir + 官方 provider 的安全 timeout mock，无真实凭据。

```text
[17:53:24] gitleaks 8.30.0 正在准备引擎
[17:53:24] gitleaks 8.30.0 正在下载引擎
[17:53:24] gitleaks 8.30.0 引擎下载失败 · NETWORK_TIMEOUT · 来源：github.com
[17:53:24] gitleaks 8.30.0 引擎准备失败 · NETWORK_TIMEOUT · 来源：github.com

```

下载成功、准备成功和失败分别测试。漏洞库实际准备发 DATA_PREPARING 和终态；READY 本地库保持安静。
下载完成后恢复父准备阶段 heartbeat，避免解压或 Python 环境准备期间错误地静默。

## K. 网络失败

复用 ErrorDiagnostic/classify_network_error；mock 验证 NETWORK_TIMEOUT/source github.com，
HTTP/HTTPS 代理仅展示是否配置，不展示 URL、账号、密码或 query。

```text
原因：连接或下载超时。
错误类别：NETWORK_TIMEOUT
来源：github.com
HTTP 代理：未配置
HTTPS 代理：已配置
建议：检查网络、HTTPS_PROXY、远端服务及本地引擎配置后重试，不要关闭 TLS 验证。
重试：security-check tools install gitleaks
```

## L. SUCCESS

Jeepay 的 Gitleaks 真实发现 9 个问题，Semgrep 真实完成且 0 个问题。
终态显示版本、实际耗时、finding_count。JSON fixture 的 Trivy 也真实成功并产生 3 个问题。

## M. FAILED

Jeepay Trivy 仍为 MAVEN_RATE_LIMITED；没有改镜像、缓存或跳过解析以绕过该项目限流。
失败立即显示耗时、code、source，其他 scanner 继续执行。已完成 findings 保留。

## N. TIMEOUT

结构化 SCANNER_TIMEOUT 映射、中文超时 renderer、PROCESS_TIMEOUT 诊断及原有进程时限回归覆盖。
演示格式：`engine 超时 · 30.0s · PROCESS_TIMEOUT`；此示例非 Jeepay 真实超时。

## O. 并行

Barrier 测试要求两 worker 同时进入，慢引擎注册在前，完成事件顺序仍为 fast、slow。
Jeepay 实际 Gitleaks 先完成，Trivy 先失败，Semgrep 继续运行，不将执行改成串行。

## P. heartbeat

Jeepay 实际产生三条 Semgrep heartbeat，间隔约 10 秒，真实阶段耗时约 8、18、28 秒。
不推断 Maven 等内部阶段。TTY 每秒刷新；非 TTY 节流测试保证前 10 秒不会刷屏。

## Q. Ctrl+C

CLI 捕获 KeyboardInterrupt，打印“扫描已取消。”并返回 130，无 Python traceback。
主线程以短 timeout 等待 Future，及时传播取消标志；run_process 检查标志并终止外部进程树。
Windows 使用系统 taskkill /T /F，POSIX 使用独立进程组 killpg。
测试覆盖正在等待的 CLI、外部 worker、辅助子进程、工具解析和阻塞 HTTP 连接；受控 CLI 取消 <2 秒。
下载在后台只读网络线程进行，主线程响应取消、关闭并删除目标文件；不会晚写目标文件。

## R. 中文最终结果

扫描 human 输出的检查标题、能力组、诊断、覆盖不完整说明和 retry 使用中文。
NOT_APPLICABLE 默认隐藏，--verbose 才显示；英文 JSON 枚举和原诊断数据保持不变。
ScannerRun.capabilities 计算失败影响，不硬编码 Trivy 关联。重试为原模式命令，无 `<project>`。
Severity、引擎名、HTTP/HTTPS、错误代码及 coverage 枚举保留技术原值。

## S. Jeepay 完整执行

在 `C:\Users\Administrator\Downloads\jeepay-master\jeepay-master` 执行实际
`security-check scan --mode release`。完整分流输出见两个 jeepay-progress 文本，逐行到达时间见 JSON。
首条反馈 767 ms；总 wall time 39438 ms；exit code 1。
650 个扫描文件，9 个发现；代码 EXECUTED、敏感信息 PARTIAL、依赖/IaC FAILED。
已安装引擎：Semgrep 1.178.0、Gitleaks 8.30.0、Trivy 0.74.0。

## T. pytest

最终全量：183 passed、6 skipped、5 subtests，74.22 秒。
新增 progress suite 35 cases；原 Alpha/diagnostics 的 human 断言随中文 renderer 更新。
显式 progress-first → WorkBuddy 官方 MCP 顺序也通过；修正 SDK 首次导入绑定 pytest 临时 stderr 的测试污染。
6 skipped 为既有独立 E2E 的全局 PATH 前提；另以 ToolManager 和独立程序进行真实引擎验证。

## U. Compliance

licenses --check-distribution、generate_notices.py --check、既有 compliance/distribution pytest 均通过。
未新增 Scanner、规则、AI、云服务或第三方 UI 依赖，许可证 metadata 未变。

## V. Package integrity

python -m build、check_wheel.py、verify_package.py：wheel/sdist 构建、许可证/规则/下载清单、
干净 venv 安装、入口版本与法律文件完整性通过。build 与最终 tool-resolution 取消修正同步。

## W. Standalone / distribution

Windows x64 PyInstaller 构建、归档基本完整性/MCP 验证通过，真实已安装引擎的 Git/非 Git release 均成功。
全新 --full 第一次在 mirror.gcr.io 漏洞库下载出现 NETWORK_TIMEOUT，保持真实失败，不掩盖。
使用已有官方 GHCR 数据库配置重试 --full 成功，三个 managed 引擎与真实扫描均通过。
最终工具解析取消修正之后重新构建并复验基本归档及真实 Git/非 Git 扫描。
Linux/macOS 由本提交 GitHub Actions 验证。
原 Alpha acceptance 脚本通过，保留 no-change、scope、verify 和 integration self-test 的约束。

## X. 尚未解决与边界

- Jeepay Maven HTTP 429 仍未解决，进度不会伪称依赖安全完成。
- 未提供无法观察的引擎内部阶段、下载百分比或 ETA。
- 阻塞 urllib 网络线程是 daemon，取消后仍可能等待当前 socket 的 60 秒超时；不会阻塞 CLI 退出或写目标文件。
- 任意第三方插件的非合作式纯 Python 无限循环无法安全强制终止线程；内置外部进程可取消。
- 来源网络波动会影响全新数据库准备；真实失败和官方源重试分别记录。
