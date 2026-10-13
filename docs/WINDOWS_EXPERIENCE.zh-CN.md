# Windows 本地升级与安全核查体验

[English](WINDOWS_EXPERIENCE.md) | 简体中文

## 新安装入口：Runtime、全局连接和专业 Skill 一起安装

本轮构建在已解压、来源可信的完整 `security-check` 文件夹中执行一条命令：

```powershell
.\security-check.exe install codex
.\security-check.exe prepare-scanners
```

命令开始后立即显示中文提示，安装核对程序、全局连接/Skill 和已有缓存；扫描能力另行准备。
联网准备显示实际传输量、尝试次数及超时原因，未知进度不伪造百分比。校验包、复制程序、自检等阶段
都有反馈；长步骤每约 5 秒显示当前阶段和累计等待时间，不显示虚假的完成百分比。
完成、失败和取消分别说明状态。反馈实时刷新并写到标准错误流；`--json` 的标准输出
仍只有最终 JSON 回执，不混入进度。反馈不输出配置、秘密或子程序原始错误内容。

程序自动放入用户本地固定安装目录，协同部署用户级 MCP、Hook 和
`%USERPROFILE%\.agents\skills\ai-security-review`，包括专业深审参考文件。
安装只等待本地程序和连接自检，不等待联网准备。安装返回 0 只证明本地安装通过，
`scan_ready` 单独说明扫描就绪。`prepare-scanners` 在不完整时返回 2，取消返回 130，
保留已安装的配置和可用缓存；处理提示后只重跑准备入口即可。
`setup codex` 也会安装/升级同一 Skill，但只配置连接和 Skill，不下载工具或证明检查已就绪。
扫描准备复用兼容缓存，补齐缺失、损坏或不兼容的默认工具，并刷新过期数据。
保留其他工具和用户附加文件，不安装或运行受保护项目的依赖与代码。
同名自定义 Skill 或未知旧配置不会被强行覆盖，会说明阻断原因；配置/Skill 写入失败
时仅安全撤回本次事务，无法安全恢复时停下并给恢复诊断。

安装完成后完全退出并重启 Codex，按宿主提示审核 Hook 信任，并确认 Skill 可见。
安装成功、扫描准备通过、当前项目检查和宿主实际连接分别核对，修复仍需用户选定授权。
安装程序不能代替用户批准 Hook。工具下载的许可和测试成功也不能冒充本机实际联网下载证据。
默认安装目录是 `%LOCALAPPDATA%\AI-Security-Runtime-install`。
这是“已有本地完整包的一条安装命令”；尚未发布可以在全新机器上直接下载安装的公网命令。
旧 ZIP 不含本入口，不能用旧包验证本轮变更。

离线安装执行 `.\security-check.exe install codex --offline`，只验证并复用本机可用缓存。
缺失、损坏或过期时仍报告未就绪，联网后运行 `prepare-scanners`。
默认准备预算 300 秒，无进展限制 30 秒，默认无整包自动重试；可显式设置预算和一次重试。
`prepare-scanners --status --json` 只读核对本地状态。尚无后台周期更新服务；快速依赖检查和自动 Hook
继续使用本地离线工具与数据。

### 云端专业指南：可扩展，尚未启用远程服务

本地 Skill 是稳定入口；深度审计时优先从 Runtime 的
`get_professional_guidance` 读取有版本号和内容摘要的专业指南，缺少工具时读取随包参考文件。
本轮该接口只返回随包内容，不联网、不读取项目、不上传源码，也不执行扫描或修复。
远程服务、发布签名和下载缓存尚未实现；不能说“云端更新已经生效”。
后续可由 Runtime 获取发布者签名的云端指南并缓存，失败回退到已验证缓存/随包内容。
专业方法文本可独立维护，但改变本地入口、工具、扫描器或授权边界仍需客户端更新/重连。
云端内容不能绕过用户授权或替代真实扫描证据。详见
[个人安装与指南维护设计](PERSONAL_INSTALL_AND_GUIDANCE.zh-CN.md)。

## 2026-10-11 开发源码变化（尚未替换当前全局安装）

所有漏洞都必须先获得用户授权才能修复，包括 TLS。默认先询问；旧 `smart_auto`
设置按 `ask_before_fix` 处理。发现风险、扫描或普通开发请求都不是修复授权。
已明确说“修复这一项”则无需重复询问；只在该项范围内修复，再用原扫描器复测。
拒绝、过期、范围变化或新出现的漏洞不能沿用旧授权。构建、功能测试、网络验证与
漏洞复现不随修复授权自动放行。下文旧版自动修复描述不再代表当前源码策略。

规则库升为 1.3.0：55 条 SAST 规则、47 条默认开启，其中 Python 15 条。
新增 Python SQL 注入、SSRF、路径穿越、反序列化、模板/HTML 注入、TLS、JWT、
Flask/Django 配置和 Java Servlet XSS、Spring CSRF 检测。
规则执行记录与 OWASP 2025 部分覆盖分开显示；不是“覆盖全部 Top 10”或整库安全证明。
不安全设计、日志/告警与异常处理仍需专项审计。

专业深审仍使用同一个 `$ai-security-review`，不会替换你的 Runtime：

> 使用 $ai-security-review 深度审计当前项目全部代码，追踪攻击者输入到敏感操作，
> 检查认证、对象权限、租户边界和防护条件；用中文说明具体文件、真实调用边、
> 缺失证据、可执行修复建议、已完成和未完成的覆盖。先不要修改、运行或修复项目代码。

依赖报告增加本地 POM/父 POM/property 的修改位置、有限范围的 API 使用引用和
逐公告修复版本选项。版本不一致、外部 BOM/profile 未解析时保留未知；引用 API 不等于
已证明漏洞入口可利用。主引擎失败但回退成功，不再一概描述为“依赖扫描失败”。
当前仍未实现完整 Maven 图、跨文件编译级调用图和所有公告的真实可利用性证明。

源码规则门禁和隔离 Python 真实扫描器闭环已验证；新安装后的中文提示、授权交互及
自然语言深审质量仍需桌面实测。下面的旧 ZIP/安装步骤不表示它已包含本轮源码变化。

这是 v0.3.1 的本地体验构建，升级与扫描契约为 `upgrade-and-scan-v1`，未发布 Release。保留 ZIP 中整个 `security-check`
文件夹，无需开发机 Python。首次引擎和漏洞数据库准备需要联网。
`version.json` 给出源码提交和未提交修改标志；用
`Get-FileHash <ZIP> -Algorithm SHA256` 核对旁边 `.sha256`。许可证、NOTICE 和
source offer 随包保留。`build_id` 区分同版本号的不同构建；包内文件摘要是完整性校验，
不是发布者签名。旧 R2.2 ZIP 缺少新文件清单，不能直接作为版本槽候选包。

Release 扫描也支持从 ZIP 解压、没有 Git 的源码目录。已识别的二进制文档、图片和
字体会明确记录为排除项，其内容没有被检查。超限源码、凭据文本和依赖文件仍会以
具体诊断停止发现。当前规则包 1.2.0 包含 40 条规则（32 条默认启用），新增
Java 框架变体及六条共享 JS/TS 规则。实际覆盖取决于执行的文件和规则，不代表
所有语言或所有漏洞都已检查；Vue SFC 和未建模调用链仍有明确限制。
规则范围、授权审核和六步体验清单见 [RULE_FOUNDATION.md](RULE_FOUNDATION.md)。
详见[目标选择](SCAN_TARGET_SELECTION.md)。

## 本轮 Java / JS / TS 规则体验

本地包名称包含 `rule-foundation`；应用仍是 0.3.1，规则包是 1.2.0，
用 `build_id` 区分旧的同版本包。完整规则边界见 [规则基础](RULE_FOUNDATION.md)。
本轮也修复默认 Global Hook 状态目录超过 Windows 传统路径长度时的保存问题，
内部使用同一文件位置的长路径表示，不修改系统设置、工作区边界或 ownership 校验。

安装后，在下方六步清单的隔离项目里，可以向 Agent 这样要求：

> 仅在这个临时项目创建 Java NamedParameterJdbcTemplate、JavaScript
> child_process 和 TypeScript fetch 的合成安全核查样例，不执行代码。
> 使用 $ai-security-review 扫描全部项目代码，列出实际执行规则、文件范围、
> 候选风险和本地证据。先不要修复。

核查后明确授权修复一个合成问题，要求用原规则复扫，并运行已有功能测试。
Hook 体验要先建立安全基线，再引入合成风险；观察自动提示，恢复安全代码后
观察复扫。扫描器不修改代码，发现消失也不等于应用功能兼容性已验证。
代码执行、自然语言修复质量和 Desktop 的实际 Hook 提示需要用户亲自验收。

## 安装与升级

### 个人版：一份全局接入，不逐项目安装

当前源码的 `install codex` 安装用户级接入和专业 Skill；`prepare-scanners` 单独准备检查组件；
内部 `setup codex` 保持仅配置语义。带 `--path` 也不会建立第二份
项目安装。新项目自动隔离扫描记录和修复授权，不要求用户重复配置。显式
`--scope project` 仅保留旧接入／开发兼容入口，不是个人用户的推荐流程。
Codex 自身允许受信任项目覆盖全局设置，但本产品不依赖用户分别管理两套连接。
源码更新不会自动升级已经解压或正在连接的旧包。

若当前项目含旧同名接入，扫描尚未执行时会给出中文原因、具体配置位置和确认问题。
宿主应先取得明确同意，再使用反馈中的产品命令；不能把“扫描一下”当成删除配置授权。
在包含此功能的新构建中，确认后可用一次命令备份并迁移选定项目的旧接入：

```powershell
& $runtimeExe repair --path $reviewProject --approve-user-managed --json
```

其中 `$runtimeExe`、`$reviewProject` 使用下方安装步骤中确定的固定启动器和项目路径。
只移除已诊断的同名 MCP 项，保留其他工具和设置，不修改项目代码或 Skill。未知 Hook、
无效归属凭据仍会阻止迁移；无需试着删除整个 `.codex` 目录。成功后重启 Codex 或
重新连接 Runtime，核对就绪状态，再重新扫描。若迁移中断，按反馈中的恢复入口先恢复；
恢复不会覆盖中断后用户的新修改。备份日志包含本机配置恢复字节，切勿上传或分享。

连接自检失败时，仍会保留已经核实的全局配置和归属状态，不把“配置正确”“已连接”
和“已完成扫描”混为一谈。本流程的自动测试使用隔离配置，不代表你的现有安装已经迁移。

### 以下为旧版手动迁移/高级步骤，不是新安装的默认流程

下列 `rule-foundation` 包是历史构建；本轮新构建应使用上方 `install codex`。
历史包名为 `ai-security-runtime-v0.3.1-rule-foundation-windows-x64.zip`。
解压后，在其 **`security-check` 子目录**打开 PowerShell，此目录包含
`security-check.exe` 和 `version.json`。如果当前在解压外层目录，先执行
`Set-Location .\security-check`：

```powershell
.\security-check.exe --version
.\security-check.exe runtime-info --json
.\security-check.exe status
```

需要手动检查旧安装迁移时，可先把新包放入版本槽，使用固定启动器。以下命令会写入你明确指定的安装目录，
不会自动修改 Codex 配置；目录需固定，不能放在包自身里面：

```powershell
$runtimeInstall = Join-Path $env:LOCALAPPDATA 'AI-Security-Runtime-install'
.\security-check.exe delivery activate --root $runtimeInstall --bundle (Get-Location).Path --json
$runtimeExe = Join-Path $runtimeInstall 'launcher/security-check.exe'
& $runtimeExe delivery status --root $runtimeInstall --json
```

先诊断并阅读计划。`--path` 是需要试用的项目，用于检查会覆盖全局连接的项目级配置。
计划文件必须是新文件，15 分钟内有效；更改了配置或包后需重新生成：

```powershell
$reviewProject = 'C:\your-project'
$upgradePlan = Join-Path $env:TEMP ('runtime-upgrade-' + [guid]::NewGuid() + '.json')
& $runtimeExe upgrade diagnose --path $reviewProject --json
& $runtimeExe upgrade plan --path $reviewProject --output $upgradePlan --json
# 阅读计划、确认路径与变更后执行（托管安装和 Skill 协同更新）
& $runtimeExe upgrade apply --plan $upgradePlan --json
& $runtimeExe review-skill status
```

遇到未知同名 MCP，默认拒绝删除。仅在确认计划中的 `mcp_servers.ai_security_runtime`
确实是准备替换的旧连接后，再执行 `upgrade apply --plan $upgradePlan --approve-user-managed --json`。
这不是批准所有未知 Hook；签名无效、未知相关 Hook、用户改过的托管 Skill 都会停止，
不重建密钥或覆盖用户内容。中断后用 `upgrade recover --json` 恢复；若失败后又有用户
修改，恢复会拒绝覆盖，需人工核对。日志含配置恢复字节，不要上传或分享。

以后升级用新包执行同一 `delivery activate`，再用固定启动器重新生成/应用计划。
`delivery rollback --root $runtimeInstall --json` 可切回已验证的上一构建；扫描状态和
密钥在版本槽外保留，不恢复旧授权能力。损坏或中断复制的槽不会被自动覆盖。

完全退出并重启 Codex Desktop，在新聊天确认 Runtime MCP 连接及 AI Security
Review Skill 可见。按宿主提示审核信任 Hook，Runtime 不替你批准。可以选该
Skill，或明确说：“使用 $ai-security-review 扫描当前项目的整体代码，报告安全风险
和实际扫描覆盖范围。”普通“检查安全风险”可能选择其他 Skill，隐式匹配不保证优先级；
在聊天中明确选择/提及你的 Skill 最可靠。无需输入 Finding ID。

Skill 默认装到用户 `.agents/skills/ai-security-review`。`review-skill` 的
`upgrade`、`repair`、`remove` 和 `status` 管理同一安装。用户修改托管文件时
返回 USER_MODIFIED 并保留；自定义附加文件、其他 Skill 均保留。Skill 移除
独立于 Runtime `uninstall`。宿主禁用设置需用户恢复，安装器不改变它。

## 不碰现有安装的本地试用

CLI 隔离试用不修改真实用户的配置、Skill、密钥、信任设置或项目。选一个不存在的路径：

```powershell
$runtimeTrial = Join-Path $env:TEMP ('runtime-trial-' + [guid]::NewGuid())
.\security-check.exe trial create --root $runtimeTrial --json
.\security-check.exe trial run --root $runtimeTrial -- runtime-info --json
.\security-check.exe trial run --root $runtimeTrial -- setup --scope global
.\security-check.exe trial run --root $runtimeTrial -- status --json
```

子进程清除继承的 Runtime/扫描器绑定，使用独立 Codex home、Skill、状态、引擎数据和
缓存，并默认离线。试用目录保留，且不复用已有目录。缺少引擎或数据库时如实报告，
不会偷偷联网安装。试用 setup 只支持 Codex；其他编辑器入口和缩写参数会在执行前拒绝，
请使用完整参数名。CLI 试用不代表 Desktop 已加载这个隔离 home；桌面验证仍须另行完成。

## Git 提交门禁

Git pre-commit 与 Codex 编辑事件 Hook 是两种独立入口。显式安装到选定 Git 项目：

```powershell
& $runtimeExe hooks install pre-commit --path $reviewProject --gate strict
& $runtimeExe hooks status pre-commit --path $reviewProject
& $runtimeExe hooks repair pre-commit --path $reviewProject --gate strict
# 不需要时，只移除本产品签名托管且未被用户修改的 Hook
& $runtimeExe hooks remove pre-commit --path $reviewProject
```

门禁扫描真实 Git index，不用工作区内容替代暂存内容，不修改 index/工作区，支持
独立 worktree。已有未知 Hook 不覆盖、不自动串联。`strict` 的退出码：0 允许、1
策略阻止、2 扫描未完成；`report` 对未完成发出警告但允许提交。普通 `scan` 的历史
退出码保持兼容，需要门禁语义时显式加 `--gate strict`。暂存扫描仅支持 `quick`。

## 六步体验清单

1. **创建隔离项目。** 在 PowerShell 建唯一临时 Git 仓库，然后在 Desktop 打开：

   ```powershell
   $reviewDemo = Join-Path $env:TEMP ('security-review-' + [guid]::NewGuid())
   New-Item -ItemType Directory -Path $reviewDemo -ErrorAction Stop | Out-Null
   git init $reviewDemo
   New-Item -ItemType Directory -Path (Join-Path $reviewDemo '.codex') | Out-Null
   [IO.File]::WriteAllText((Join-Path $reviewDemo '.codex/config.toml'), "[features]`nhooks = false", [Text.UTF8Encoding]::new($false))
   ```

   确认此演示项目的 Hook 已关闭、MCP 仍连接。不要改正常业务项目，不执行网络样例。
2. **无 Hook 扫描。** 说：“只在此临时项目创建合成样例：Java
   NamedParameterJdbcTemplate 把 servlet 请求参数拼入 SQL；JavaScript 的内联
   Express handler 把请求输入传给 child_process.exec；TypeScript 的内联 Express
   handler 把请求输入传给 fetch。另建一个 Java 信任所有主机名的
   HttpsURLConnection verifier 并安装到 connection，用于原有授权流程体验。
   不执行样例。使用 $ai-security-review 扫描全部项目代码，列出实际文件、执行的
   Java/JS/TS 规则、本地证据与风险，先不要修改代码。”记录 scanner 执行及
   FULL/PARTIAL 原因。FULL 不是项目安全声明，新增 advisory 规则不授予自动修复权限。
3. **核查与续办。** 说：“使用 AI Security Review 核查第一个风险，分批处理，不
   修改代码”，再说“继续这个任务”。观察脱敏证据、需处理风险和待确认项。
   样例位置不能证明误报；旧扫描没有版本证明时只能给当前上下文。
   断开重连后继续应复用有效评审、重新准备 session，不要求用户输入 UUID。
4. **授权修复并验证。** 选择已展示的 TLS 主机名 verifier 任务，保留原有授权
   流程体验。说：“修复这个 TLS 任务，并用原扫描器和规则验证。”观察原任务
   保持一致、代码实际修改与 scanner 重检。其他 Java/JS/TS 候选需分别核查与明确
   选择修复。只有
   SCANNER_VERIFIED_RESOLVED 表示此规则范围内解决；INCONCLUSIVE 要说明原因。
   代码变化须刷新相关结论，验证不代表业务／部署正确。
5. **亲自验证 Hook 自动反馈。** 仅将演示项目配置改为 `hooks = true`，完全重启
   Desktop，审核当前 Runtime Hook 并确认启用。保持已修复的 TLS 代码安全，先在
   同一文件做无害注释修改，确认 Hook 已扫描基线。再说：“仅为隔离演示，把 verifier
   临时改回恒为 true 并安装，不运行网络代码。”观察编辑后自动出现安全反馈。
   当前 remediation 模式决定建议／确认／修复；需只看建议时，先记录
   `remediation status`，自行选择 `remediation configure --mode report_only`，
   体验后恢复原模式。未触发／未信任／不可见均记录失败，不以手动扫描代替。
   新 JS/TS 规则可另选一个明确授权的合成文件，分别体验安全 → 风险 → 安全与
   advisory 提示；不能从这些 Finding 推断自动修复权限。
6. **收尾与记录。** 明确要求修复演示风险并验证，记录覆盖、Finding、未知项、
   原规则验证和 Hook 反馈。保留现场以便复盘，不自动抑制或宣布安全。
   无需发布代码、tag 或 Release；关闭演示项目，再决定下一阶段。

## 已知限制与验收

Runtime 不内置 LLM 核查调用，宿主分析证据。脱敏可能隐藏所需语义，未知项必须
保留。工作区／链接／大小／编码／版本检查失败会给明确原因。原始 Finding、
人工质量评审、AI triage、扫描覆盖和修复验证分别报告。行移动可能改变 quality
finding_id，未实现自动语义关联。宿主可能把脱敏上下文发送给所选模型。

整库请求会新执行 `release` 扫描，增量检查用 `quick`。摘要中的 `scan_context`
报告实际文件数、语言、扫描器结果和源码新鲜度；只读摘要尚不能重新验证引擎/数据库
证明，`full_project_reusable` 保守为 false。旧 Hook 的 FULL 不代替新的整库扫描。

自动 stdio 和隔离脚本只证明工具路径。本轮新包的自然语言选 Skill、无 Hook
桌面核查和 Hook 自动提示可见性，需要你亲自完成六步，记录 PASS/FAIL/未验证及
原因。此前 Desktop 结论不自动继承。官方约定：
[Skills](https://learn.chatgpt.com/docs/build-skills)、[Hooks](https://learn.chatgpt.com/docs/hooks)。
# 2026-10-11 安装体验优化说明

本轮本地试用包统一安装 Runtime、全局连接和专业 Skill，安装过程显示实际阶段。
重复安装复用有效的兼容缓存，需要时自动补齐默认工具和刷新过期漏洞数据；
`--offline` 仅验证本机可用缓存。准备失败保留配置和可用缓存，报告未就绪及非零退出码。
安装成功后不长期保留历史版本；正在使用的旧版本
延后到退出/真实 MCP 重连后清理。安装程序不删除用户下载 ZIP、解压目录或自定义内容。
Windows 固定启动器改为小型原生程序，迁移旧完整启动器时使用 `launcher-v2`，避免覆盖运行中的 EXE。
完整性校验仍保留，重复能力自检合并到同一事务一次；支持本地差分包，但公开自动更新下载服务尚未发布。
漏洞库在安装或升级时按过期时间更新；旧库或新鲜度未知时明确报告部分覆盖。
当前未实现后台周期更新，不把隔离验收描述为本机真实联网下载成功。
安装成功仍需完全退出并重启 Codex。
