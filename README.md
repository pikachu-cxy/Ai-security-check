# AI Security Runtime

在 AI 编程过程中检查本次开发改动，结合静态检查与 Agent 对关联代码的复核，说明具体风险、已有防护和未知范围。用户选择修复、稍后处理或排除；Agent 在授权范围内编辑，Runtime 保存原问题与复查记录。

当前源码为 **0.3.6 / Developer Alpha**，开发分支为 **feature/runtime-mvp**。主要验收宿主是 Codex，Cursor 自动连接器仍需独立桌面验收。源码同步、安装包发布、接入成功与项目检查完成分别认定。

## 产品与使用文档

**默认完整接入 Runtime + MCP + Skill + Hook**，不需要在安装时选择版本；仅需要 MCP 时可手动配置，不执行完整接入。

- [产品介绍](website/guide/overview.md)、[快速开始](website/guide/quickstart.md)、[安装与升级](website/guide/installation.md)、[仅 MCP 接入](website/guide/mcp.md)。
- [工作流程](website/guide/workflow.md)、[风险处置](website/guide/risk-handling.md)、[支持范围](website/reference/support.md)、[隐私与联网](website/reference/privacy.md)、[常见问题](website/reference/faq.md)。
- [当前安装包状态与校验](website/downloads.md)、[版本进展](website/reference/changelog.md)。

独立文档站已上线：[AI Security Runtime 产品与使用文档](https://pikachu-cxy.github.io/Ai-security-check/)。使用 **VitePress + GitHub Pages**，源码在 `website/`，配套导航、站内搜索与移动端布局。后续维护见[部署指南](website/contributing/deployment.md)。

## 当前源码状态

本次修复包括：

- Windows 扫描私有输入路径过长导致进程启动失败；固定输入、规则和产物继续保留权限、身份与清理校验。
- Windows Semgrep 使用独立的短私有临时目录，处理超长或中文 TEMP；就绪探测包含有界合成扫描，区分本地通信权限与组件下载失败。
- macOS 托管 Semgrep 的解释器链接仅允许指向匹配固定版本、清单与实际字节校验的托管 Python；外部链接仍被拒绝。
- Cursor 会话基线捕获失败时保留明确失败原因，不重复捕获或发布不可核验基线。
- 执行初始化、发布锁竞争、中断及取消后的恢复；已完成结果沿原任务恢复，不重复扫描或消耗预算。
- 本轮风险交付恢复位置及“问题／可能影响／建议修复／尚未确认”四段说明；历史查询不重复索取处置选择。
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

本版平台资产命名如下；列出文件名不表示已公开发行，实际下载以 Releases 中通过验收的版本为准。

- Windows x64：`ai-security-runtime-v0.3.6-windows-x64.zip`
- Mac Apple Silicon：`ai-security-runtime-v0.3.6-macos-arm64.tar.gz`
- Mac Intel：`ai-security-runtime-v0.3.6-macos-x64.tar.gz`

[Releases](https://github.com/pikachu-cxy/Ai-security-check/releases)是公开完整包入口，只有验收通过的候选才会发布。此前本地 Windows 0.3.6 候选基于固定提交 `c526cdd3d6c6923e04d64334c5dc19c0908cef31`，仅供历史构建核对；后续修正版应以 Release 的实际源码提交、资产和校验为准，不能仅凭版本号混用。文件与校验见[下载状态](website/downloads.md)。[v0.3.4](https://github.com/pikachu-cxy/Ai-security-check/releases/tag/v0.3.4)是旧发行，不包含后续 v3 与恢复修复，不能与新版 Skill 混用。

拿到与所需能力匹配的完整包后，保留全部 security-check 目录，退出 Codex，在解压目录执行：

~~~powershell
.\security-check\security-check.exe install codex
.\security-check\security-check.exe preparation watch
~~~

完整包自带 Python，无需另装 Python、pip 或 venv。不要只复制一个可执行文件。Windows、macOS、SHA256 校验及仅 MCP 模式见[详细安装指南](docs/PILOT_INSTALL_AND_USE.zh-CN.md)。macOS CI、候选构建和真机验收分别记录；Linux 暂不发行。

首次组件准备仍可能下载漏洞数据库；在线 / 本地双模式与一条命令安装尚未交付，不作为本版宣传能力。当前完整包不要求 Node.js，也没有正式 `npx` 安装入口。

## 日常流程

1. 在项目聊天中正常提出开发需求。编辑前保存真实任务基线，开发后检查当前改动和必要关联代码；不要求用户先提交 Git。
2. 风险说明保留位置、防护、触发条件和未知。明确选择具体风险后批准修复；已有同范围授权不重复确认。
3. 只问修复影响时不编辑。稍后处理保留风险，明确误报或不再提醒保存为排除；用户决定与 AI 技术评估分别记录。
4. 修复后沿原风险复查。新任务零发现、普通测试通过、暂缓或排除都不等于原漏洞已验证修复。
5. 历史查询只读，不重扫、不重复追问。普通聊天、只读操作和无改动不追加通用安全提示。

支持 Java、Python、JavaScript / TypeScript 的已安装规则子集、密钥检查、可识别依赖及有界关联分析。零发现不证明项目安全；不完整范围和失败原因应如实保留。检查在本机运行，语义分析由宿主 Agent 完成。

## 开发与支持

文档本地预览：进入 `website/` 后执行 `npm ci`、`npm run docs:dev`；构建使用 `npm run docs:build`。Node.js 仅为文档开发依赖。GitHub 默认分支推送会按变更路径触发文档工作流；三平台包工作流也支持独立手动构建，不必触发 Release 发布。

- [开发进度](docs/DEVELOPMENT_PROGRESS.md)、[近期计划](docs/NEXT_DEVELOPMENT_PLAN.zh-CN.md)、[开发交接](docs/DEVELOPMENT_HANDOFF.zh-CN.md)。
- [架构与恢复](docs/ARCHITECTURE_UNIFICATION_COMPLETION.zh-CN.md)、[持久化契约](docs/PERSISTENCE_TRANSACTION_RECOVERY.zh-CN.md)、[v3 升级边界](docs/TASK_REVIEW_V3_ONLY.zh-CN.md)。
- [Cursor 安装测试](docs/guides/CURSOR_INSTALL_AND_TEST.zh-CN.md)、[宿主支持状态](docs/HOST_SUPPORT.md)。
- [文档导航](docs/README.md)、[规则范围](docs/design/RULE_FOUNDATION.md)、[覆盖矩阵](docs/design/RULE_COVERAGE_MATRIX.md)。
- [许可](LICENSING.md)、[使用条款](EULA.md)、[第三方声明](THIRD_PARTY_NOTICES.md)。

反馈到 [Issues](https://github.com/pikachu-cxy/Ai-security-check/issues)时提供系统、实际构建身份、失败步骤和脱敏诊断。扫描记录、原始聊天、凭据、缓存、临时样例与构建产物不进入 Git。自动回归需要的合成 fixture 和测试保留；已淘汰的手工实验及重复阶段文档从工作树移除，历史可通过 Git 查阅。
