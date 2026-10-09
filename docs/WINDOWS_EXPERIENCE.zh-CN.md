# Windows 本地升级与安全核查体验

[English](WINDOWS_EXPERIENCE.md) | 简体中文

这是 v0.3.1 的本地体验构建，升级与扫描契约为 `upgrade-and-scan-v1`，未发布 Release。保留 ZIP 中整个 `security-check`
文件夹，无需开发机 Python。首次引擎和漏洞数据库准备需要联网。
`version.json` 给出源码提交和未提交修改标志；用
`Get-FileHash <ZIP> -Algorithm SHA256` 核对旁边 `.sha256`。许可证、NOTICE 和
source offer 随包保留。`build_id` 区分同版本号的不同构建；包内文件摘要是完整性校验，
不是发布者签名。旧 R2.2 ZIP 缺少新文件清单，不能直接作为版本槽候选包。

## 安装与升级

在解压文件夹打开 PowerShell：

```powershell
.\security-check.exe --version
.\security-check.exe runtime-info --json
.\security-check.exe status
```

推荐先把新包放入版本槽，使用固定启动器。以下命令会写入你明确指定的安装目录，
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
2. **无 Hook 扫描。** 说：“只在此临时项目创建 Java 安全核查样例，使用信任所有
   主机名的 HttpsURLConnection verifier 并安装到 connection。不执行代码。
   使用 $ai-security-review 扫描这个项目，显示实际覆盖和风险。”记录 scanner 执行及 FULL/PARTIAL 原因。
   FULL 不是项目安全声明。
3. **核查与续办。** 说：“使用 AI Security Review 核查第一个风险，分批处理，不
   修改代码”，再说“继续这个任务”。观察脱敏证据、需处理风险和待确认项。
   样例位置不能证明误报；旧扫描没有版本证明时只能给当前上下文。
   断开重连后继续应复用有效评审、重新准备 session，不要求用户输入 UUID。
4. **授权修复并验证。** 说：“修复刚才这个任务，并用原扫描器和规则验证。”
   观察原任务保持一致、代码实际修改与 scanner 重检。只有
   SCANNER_VERIFIED_RESOLVED 表示此规则范围内解决；INCONCLUSIVE 要说明原因。
   代码变化须刷新相关结论，验证不代表业务／部署正确。
5. **亲自验证 Hook 自动反馈。** 仅将演示项目配置改为 `hooks = true`，完全重启
   Desktop，审核当前 Runtime Hook 并确认启用。说：“仅为隔离演示，把 verifier
   临时改回恒为 true 并安装，不运行网络代码。”观察编辑后自动出现安全反馈。
   当前 remediation 模式决定建议／确认／修复；需只看建议时，先记录
   `remediation status`，自行选择 `remediation configure --mode report_only`，
   体验后恢复原模式。未触发／未信任／不可见均记录失败，不以手动扫描代替。
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
