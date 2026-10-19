# AI Security Runtime

在 AI 编程过程中检查本次开发改动，结合静态检查与 Agent 对关联代码的复核，说明具体风险、已有防护和未知范围。用户选择修复、稍后处理或排除；Agent 在授权范围内编辑，Runtime 保存原问题与复查记录。

当前源码为 **0.3.6 / Developer Alpha**，开发分支为 **feature/runtime-mvp**。主要验收宿主是 Codex，Cursor 自动连接器仍需独立桌面验收。源码同步、安装包发布、接入成功与项目检查完成分别认定。

## 当前源码状态

本次修复包括：

- Windows 扫描私有输入路径过长导致进程启动失败；固定输入、规则和产物继续保留权限、身份与清理校验。
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

## 使用完整安装包

[Releases](https://github.com/pikachu-cxy/Ai-security-check/releases)是完整包入口。仓库保留的 [v0.3.4 下载页](https://github.com/pikachu-cxy/Ai-security-check/releases/tag/v0.3.4)属于旧发行，不包含本分支后续 v3 与恢复修复，不能与本分支新版 Skill 混用。本次 Git 推送不发布新的安装包。

拿到与所需能力匹配的完整包后，保留全部 security-check 目录，退出 Codex，在解压目录执行：

~~~powershell
.\security-check\security-check.exe install codex
.\security-check\security-check.exe preparation watch
~~~

完整包自带 Python，无需另装 Python、pip 或 venv。不要只复制一个可执行文件。Windows、macOS、SHA256 校验及仅 MCP 模式见[详细安装指南](docs/PILOT_INSTALL_AND_USE.zh-CN.md)。macOS CI、候选构建和真机验收分别记录；Linux 暂不发行。

## 日常流程

1. 在项目聊天中正常提出开发需求。编辑前保存真实任务基线，开发后检查当前改动和必要关联代码；不要求用户先提交 Git。
2. 风险说明保留位置、防护、触发条件和未知。明确选择具体风险后批准修复；已有同范围授权不重复确认。
3. 只问修复影响时不编辑。稍后处理保留风险，明确误报或不再提醒保存为排除；用户决定与 AI 技术评估分别记录。
4. 修复后沿原风险复查。新任务零发现、普通测试通过、暂缓或排除都不等于原漏洞已验证修复。
5. 历史查询只读，不重扫、不重复追问。普通聊天、只读操作和无改动不追加通用安全提示。

支持 Java、Python、JavaScript / TypeScript 的已安装规则子集、密钥检查、可识别依赖及有界关联分析。零发现不证明项目安全；不完整范围和失败原因应如实保留。检查在本机运行，语义分析由宿主 Agent 完成。

## 开发与支持

- [开发进度](docs/DEVELOPMENT_PROGRESS.md)、[近期计划](docs/NEXT_DEVELOPMENT_PLAN.zh-CN.md)、[开发交接](docs/DEVELOPMENT_HANDOFF.zh-CN.md)。
- [架构与恢复](docs/ARCHITECTURE_UNIFICATION_COMPLETION.zh-CN.md)、[持久化契约](docs/PERSISTENCE_TRANSACTION_RECOVERY.zh-CN.md)、[v3 升级边界](docs/TASK_REVIEW_V3_ONLY.zh-CN.md)。
- [Cursor 安装测试](docs/guides/CURSOR_INSTALL_AND_TEST.zh-CN.md)、[宿主支持状态](docs/HOST_SUPPORT.md)。
- [文档导航](docs/README.md)、[规则范围](docs/design/RULE_FOUNDATION.md)、[覆盖矩阵](docs/design/RULE_COVERAGE_MATRIX.md)。
- [许可](LICENSING.md)、[使用条款](EULA.md)、[第三方声明](THIRD_PARTY_NOTICES.md)。

反馈到 [Issues](https://github.com/pikachu-cxy/Ai-security-check/issues)时提供系统、实际构建身份、失败步骤和脱敏诊断。扫描记录、原始聊天、凭据、缓存、临时样例与构建产物不进入 Git。自动回归需要的合成 fixture 和测试保留；已淘汰的手工实验及重复阶段文档从工作树移除，历史可通过 Git 查阅。
