# AI Security Runtime

[English](README.md) | 简体中文

在 AI 编程过程中检查本次开发改动，结合静态检查与 Agent 对关联代码的复核，说明具体风险、已有防护和未知范围。用户选择修复、稍后处理或排除；Agent 在授权范围内编辑，Runtime 保存原问题与复查记录。

当前源码版本为 **0.3.9 / 正式版**，公开安装包以 [v0.3.9 Release](https://github.com/pikachu-cxy/Ai-security-check/releases/tag/v0.3.9) 的实际资产为准，开发分支为 **feature/runtime-mvp**。三平台发行包来自同一发布提交，实际构建身份以 `build_id` 为准。主要验收宿主是 Codex，Cursor 自动连接器仍需独立桌面验收。源码同步、安装包发布、接入成功与项目检查完成分别认定。

## 产品与使用文档

**默认完整接入 Runtime + MCP + Skill + Hook**，不需要在安装时选择版本；仅需要 MCP 时可手动配置，不执行完整接入。

- [产品介绍](website/guide/overview.md)、[快速开始](website/guide/quickstart.md)、[安装与升级](website/guide/installation.md)、[仅 MCP 接入](website/guide/mcp.md)。
- [工作流程](website/guide/workflow.md)、[风险处置](website/guide/risk-handling.md)、[支持范围](website/reference/support.md)、[隐私与联网](website/reference/privacy.md)、[常见问题](website/reference/faq.md)。
- [当前安装包状态与校验](website/downloads.md)、[版本进展](website/reference/changelog.md)。

独立文档站：[中文产品与使用文档](https://pikachu-cxy.github.io/Ai-security-check/) · [English documentation](https://pikachu-cxy.github.io/Ai-security-check/en/)。使用 **VitePress + GitHub Pages**，源码在 `website/`，配套语言切换、导航、站内搜索与移动端布局。后续维护见[部署指南](website/contributing/deployment.md)。

## 当前源码状态

0.3.9 包含一键启动当前聊天的消耗监控、自动关联可验证的 Codex 会话，以及结束后一键导出 HTML / JSON 报告。无需试用者手动找日志。用法与计量边界见[实时监控指南](docs/guides/LIVE_MONITORING.zh-CN.md)。

监控是可选模块：失败、停止或从源码交付中整体移除，不改变扫描、任务复核和修复授权。报告区分聊天 token、工具耗时和观察窗口时长；不能可靠拆分的纯开发 / 纯安全 token 保持未知。

本版同时修复长行证据截断：新任务完整保存原文代码（包括其中的密钥、密码和 Token），超大单行按实际响应大小分片，全部字符交付后才满足整行覆盖。保留响应和存储容量上限、源码版本校验；原文证据可能进入报告和宿主模型上下文；旧任务已经丢失的前像不补造。相关变更见[版本与进展](website/reference/changelog.md)。

保留 0.3.8 已有的指导按需加载、紧凑摘要、分页、明确文件范围和有证据的扫描结果复用。复用不代替必要复核或修复授权。Windows/macOS、Codex/Cursor 共用核心实现，宿主实际 token 适配目前仅实现 Codex 本机日志。

发行流程先运行 Windows/macOS 回归、合规和包完整性检查，再执行 Windows x64、Mac Apple Silicon 与 Mac Intel 三平台构建和原生验收，最后上传九项 Release 资产。公开完成状态以 Release 与 Actions 为准，不把源码提交或候选构建当作安装包发布。

该版本同时包含已有兼容与恢复修复：

- Windows 扫描私有输入路径过长导致进程启动失败；固定输入、规则和产物继续保留权限、身份与清理校验。
- Windows Semgrep 使用独立的短私有临时目录，处理超长或中文 TEMP；就绪探测包含有界合成扫描，区分本地通信权限与组件下载失败。
- macOS 托管 Semgrep 的解释器链接仅允许指向匹配固定版本、清单与实际字节校验的托管 Python；外部链接仍被拒绝。
- Cursor 会话基线捕获失败时保留明确失败原因，不重复捕获或发布不可核验基线。
- 执行初始化、发布锁竞争、中断及取消后的恢复；已完成结果沿原任务恢复，不重复扫描或消耗预算。
- 风险交付保留位置、问题、可能影响、建议与未知，随用户语言自然表达；历史查询不重复索取处置选择。
- 静态发现与代码复核风险共用当前处置投影；处置暂时不可读时保留详情并标记未知。
- 升级事务覆盖退役受管 Skill 文件；保护用户修改。补齐超长 Hook 上下文和打包规则身份校验。

[开发进度](docs/DEVELOPMENT_PROGRESS.md)记录当前验证边界，[架构说明](docs/ARCHITECTURE_UNIFICATION_COMPLETION.zh-CN.md)记录执行链与耦合边界，[手工验收](docs/RUNTIME_CHAIN_REGRESSION_ACCEPTANCE.zh-CN.md)覆盖发现、影响分析、修复、复查和误报。

## 安装当前开发源码（Windows）

需要 Python 3.12 或更高版本、Git。完全退出 Codex 后，在普通 PowerShell 中执行：

~~~powershell
git clone --branch feature/runtime-mvp https://github.com/pikachu-cxy/Ai-security-check.git
Set-Location .\Ai-security-check
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\security-check.exe install codex --dev
if ($LASTEXITCODE -ne 0) { throw '接入未完成，请保留诊断' }
.\.venv\Scripts\security-check.exe preparation watch
~~~

已有源码目录先保存自己的改动，再更新分支；开发安装使用可编辑源码，目录应保持稳定。开发安装的 --dev 是显式开发模式，不等同于完整发行包安装。

重新打开 Codex，在实际项目的新聊天中发送：

> 请只核对已连接的 ai_security_runtime 的版本、构建身份、v3 任务工具及 task-result-delivery-v1 能力，不扫描、不修改代码。

应确认同一 Runtime 提供 task-review-plan-v3、task-result-delivery-v1 和九项必需任务工具。版本号相同也可能是不同构建；以实际能力、build_id 和配套 Skill 为准。

首次准备需要下载扫描组件和漏洞数据，不安装你的项目依赖或启动项目服务。preparation status / watch 显示准备状态；准备成功不代表项目已检查。

Windows 无需修改系统 TEMP/TMP。Semgrep 自动使用当前用户本地临时目录中的短私有子目录；特殊账户可将 `SECURITY_RUNTIME_ENGINE_TEMP_ROOT` 指向项目外已存在的短本地目录。路径仍超限或权限不足时会返回具体诊断。沙箱拒绝本地通信时，应在获准支持该能力的环境执行检查。[设计与边界](docs/ARCHITECTURE.md#windows-native-engine-execution)

## 使用完整安装包

[v0.3.9 正式版](https://github.com/pikachu-cxy/Ai-security-check/releases/tag/v0.3.9) 通过[发布流程](https://github.com/pikachu-cxy/Ai-security-check/actions/workflows/release.yml)的全部检查后公开以下平台包：

- [Windows x64](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.9/ai-security-runtime-v0.3.9-windows-x64.zip)
- [Mac Apple Silicon](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.9/ai-security-runtime-v0.3.9-macos-arm64.tar.gz)
- [Mac Intel](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.9/ai-security-runtime-v0.3.9-macos-x64.tar.gz)

三平台包来自同一发布提交，实际源码身份和校验值见 [release-manifest.json](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.9/release-manifest.json) 与 [SHA256SUMS.txt](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.9/SHA256SUMS.txt)。升级时重新下载完整包和配套校验文件，重启宿主并核对 `version`、`source_commit`、`build_id`。签名、公证、macOS 真机和 Cursor 桌面验收仍分别记录。

拿到与所需能力匹配的完整包后，保留全部 security-check 目录，在解压目录执行下列命令。由 Codex 辅助安装时保留当前聊天，安装及准备完成后再退出并重启，使新连接生效：

~~~powershell
.\security-check\security-check.exe install codex
.\security-check\security-check.exe preparation watch
~~~

完整包自带 Python，无需另装 Python、pip 或 venv。不要只复制一个可执行文件。Windows、macOS、SHA256 校验及仅 MCP 模式见[详细安装指南](docs/PILOT_INSTALL_AND_USE.zh-CN.md)。macOS CI、候选构建和真机验收分别记录；Linux 暂不发行。

首次组件准备仍可能下载漏洞数据库；用户可选在线 / 本地双模式尚未交付。Mac 已提供按编辑器选择的一条命令安装，Windows 使用解压后 `install codex` / `install cursor` 入口；当前完整包不要求 Node.js，也没有正式 `npx` 或远程 PowerShell 安装入口。

## 日常流程

1. 在项目聊天中正常提出开发需求。编辑前保存真实任务基线，开发后检查当前改动和必要关联代码；不要求用户先提交 Git。
2. 风险说明保留位置、防护、触发条件和未知。明确选择具体风险后批准修复；已有同范围授权不重复确认。
3. 只问修复影响时不编辑。稍后处理保留风险，明确误报或不再提醒保存为排除；用户决定与 AI 技术评估分别记录。
4. 修复后沿原风险复查。新任务零发现、普通测试通过、暂缓或排除都不等于原漏洞已验证修复。
5. 历史查询只读，不重扫、不重复追问。普通聊天、只读操作和无改动不追加通用安全提示。

## 语言与检测覆盖

0.3.9 自带规则包 `ai-security-core 1.3.2`，共 **56 条独立代码规则，48 条默认启用**：

| 语言 / 文件 | 默认启用 / 已安装 | 覆盖边界 |
| --- | --- | --- |
| Java `.java` | 26 / 34 | 部分 JDK、Spring、MyBatis、JPA / Hibernate、Apache API；适用的 MyBatis XML 规则计入 Java |
| Python `.py` | 16 / 16 | 部分标准库、Flask、Django、Requests / HTTPX、PyYAML、PyJWT、lxml 模式 |
| JavaScript `.js` / `.jsx`、TypeScript `.ts` / `.tsx` | 共用 6 / 6 | 部分 Express / Node.js 的 SQL、命令、SSRF、路径与文件读写；共享规则只计一次 |
| Vue `.vue`、Go、PHP、C / C++、C#、Ruby、Rust 等 | 无自带对应 SAST 规则 | 宿主 AI 可以分析代码，但不能据此认为已执行这些语言的扫描规则 |

Java 的 8 条实验规则默认关闭。规则数量不代表完整语言、框架、OWASP 或生产准确率覆盖。Gitleaks 按模式检查纳入范围的文本文件，与代码语言规则分开；依赖输入当前包括 Python、npm/Yarn/pnpm、Maven/Gradle、Go 的清单或锁文件，识别文件名不保证完整依赖图。Composer、Cargo、Bundler、.NET 清单尚未纳入本产品依赖输入清单。

完整规则方向、文件范围和依据见[当前产品覆盖说明](docs/PRODUCT_COVERAGE.zh-CN.md)及[文档站语言矩阵](website/reference/support.md#语言覆盖)。零发现不证明项目安全；不完整范围和失败原因应如实保留。检查在本机运行，语义分析由宿主 Agent 完成。

## 开发与支持

文档本地预览：进入 `website/` 后执行 `npm ci`、`npm run docs:dev`；构建使用 `npm run docs:build`。Node.js 仅为文档开发依赖。GitHub 默认分支推送会按变更路径触发文档工作流；三平台包工作流也支持独立手动构建，不必触发 Release 发布。

- [开发进度](docs/DEVELOPMENT_PROGRESS.md)、[近期计划](docs/NEXT_DEVELOPMENT_PLAN.zh-CN.md)、[开发交接](docs/DEVELOPMENT_HANDOFF.zh-CN.md)。
- [架构与恢复](docs/ARCHITECTURE_UNIFICATION_COMPLETION.zh-CN.md)、[持久化契约](docs/PERSISTENCE_TRANSACTION_RECOVERY.zh-CN.md)、[v3 升级边界](docs/TASK_REVIEW_V3_ONLY.zh-CN.md)。
- [Cursor 安装测试](docs/guides/CURSOR_INSTALL_AND_TEST.zh-CN.md)、[宿主支持状态](docs/HOST_SUPPORT.md)。
- [文档导航](docs/README.md)、[规则范围](docs/design/RULE_FOUNDATION.md)、[覆盖矩阵](docs/design/RULE_COVERAGE_MATRIX.md)。
- [许可](LICENSING.md)、[使用条款](EULA.md)、[第三方声明](THIRD_PARTY_NOTICES.md)。

反馈到 [Issues](https://github.com/pikachu-cxy/Ai-security-check/issues)时提供系统、实际构建身份、失败步骤和脱敏诊断。扫描记录、原始聊天、凭据、缓存、临时样例与构建产物不进入 Git。自动回归需要的合成 fixture 和测试保留；已淘汰的手工实验及重复阶段文档从工作树移除，历史可通过 Git 查阅。
