# 修复影响评估真实桌面验收

更新日期：2026-10-18。目标版本：`0.3.6`，目标契约：`repair-impact-v1` 与 `repair-impact-unknowns-v1`。最新实际场景为 A2 修复阻塞、B3/C2 各自场景通过；旧 A/B/C 与 B2 的失败保留。本轮分级修正的三个回归回执按 `classname + name` 去重取最后状态为 **295／295 项通过**，最窄恢复组为 **65 项通过，29.55 秒**，不相加各轮用例数量。完整候选回归与打包按随后对应 `run.json` 和最新指针判定，不由定向回归推定；安装和 A2 新包桌面复验保持 `PENDING_USER`。

用户已明确要求生成安装包用于测试。本机已有构建用虚拟环境和可复用启动器，不需要先安装 Python 或开发依赖。检查反馈现在共用收窄后的授权边界：用户明确要求或原开发任务包含的测试、构建与验收照常执行，无需重复确认；仍禁止伪造结果、重放事件或补建编辑后基线。Agent 可继续已授权的研发流程；以下命令也供用户按需在独立 PowerShell 执行。命令写入文档不等于已经运行，源码修正不表示旧包或旧连接自动更新，验收只覆盖实际记录的候选和宿主。

## 当前状态：A2 未知分级修正待复验

本轮新增 `repair-impact-unknowns-v1`，统一“当前方案真正缺少必要事实”与“结论未覆盖项目外范围”的区别。源码、同源方法及定向回归已更新，三个回执的去重最后状态 295／295 通过；完整候选回归与构建按随后对应 `run.json` 和最新指针判定，不由定向回归推定；安装和分级修正版桌面验收仍为 `PENDING_USER`，不能登记为已经交付或桌面通过。此前实际连接的 `0.3.6 / 55977e7ec17204fe1087e7667bf34b2588e0e6c80f8b129a548197f1c1f27112` 已用于下表场景，但不包含本轮新分级契约；同版本号不能代替新 build_id 和能力核对。

本轮测试原始回执为 `artifacts/a2-classification-targeted-20261018.xml`（196 通过、2 失败）、`artifacts/a2-classification-verification-20261018.xml`（242 通过、2 失败）、`artifacts/a2-classification-recovery-final-20261018.xml`（65 通过，29.55 秒）。前两轮失败原样保留；汇总位置为 `artifacts/a2-classification-validation-20261018.json`，按 `classname + name` 取每项最后结果得到修正后 295／295 通过，不能相加三轮数量或称为完整候选回归通过。

| 后续样例 | 已核对的实际结果 | 当前结论 |
| --- | --- | --- |
| A2 | 四个文件已读，原生风险及影响均有记录；未提供仓储、外层身份及异常显示被归为两项 critical=true，并重复登记 UNDETERMINED，准备未通过、未修复。没有已知合法缺字段数据或本方案改变身份来源的具体依据 | 修复支路被过宽分级阻塞，不能记为完整通过；本轮在原聊天、原风险、原授权下核对新能力后续验，不重建基线绕过 |
| B 场景的新 B3 | owner-only 方案识别到合法共享成员的读取与下载损失；选择保留所有者和共享成员后，局部复用 can_read，影响、修复及原风险的宿主代码复查分别保存 | 该场景通过；宿主代码复查不是扫描器证明，也不替代本轮新分级源码的复验 |
| C2：`01a14e14-3d53-7422-ac42-6c72e127eccf` | 影响提交保存 4 项影响、2 项未知并完整两页回读；明确稍后处理后正式 DEFER，原风险保留，源码未修改。历史回读仍保留影响及 DEFERRED，未重复追问 | 只读分析、暂缓与历史支路通过；一次处置查询参数错误已通过正式复核记录回读恢复。暂缓后影响为 STALE／REASSESS_REQUIRED，如实披露，未冒称可继续编辑 |

新分级不取消真实阻断：只有能说明当前具体正常路径、缺少的必要事实、答案为何会改变方案以及必要下一步，才使用 `BLOCKING_CONTEXT / critical=true`。已读局部路径足以支持复用既有规则时，单纯未提供外部仓储、身份来源或异常显示记作 `SCOPE_LIMITATION / critical=false`，保留范围限制，不能据此声称全局安全或功能正常。范围未知不能再重复放进 UNDETERMINED；后者仍表示当前方案的具体效果无法决定并继续阻断。

两种显式分类都需非空且不超过 800 字符的 `decision_basis`；阻断项至少引用一个本评估实际签发的证据。未读 PARTIAL 保持保守，不虚构证据。旧记录按 legacy critical 与原门槛保留，不能自动降级；只有实际连接声明新能力后才发送新增字段。A2 原记录保留阻塞事实，新结论必须以真实重评提交取得，不能只改最终自然语言。

## 既有 A/B/C 核对结果与修正记录

本表依据真实聊天的工具回执与当前样例源码，不以 Agent 的完成自述代替落库和编辑证据。A、B 实际连接均报告 `0.3.6`，build 为 `d6ac9d9e0eb3842571f5acac713e057701672b459f3ec1df65908aa72bd4d2b5`；C 的版本不由 A/B 推定。

| 样例与聊天 | 实际观察 | 验收结论 |
| --- | --- | --- |
| A：`repair-impact-A-4424956f`；`01a14d37-99d0-7830-b1f8-06c8a14196ef` | 原始 rollout 第 216 行为 DRAFT、impact_count=0，第 254 行最后一次影响提交仍被拒绝，第 276／281 行随后编辑；第 320 行原问题落库为 `CODE_REVIEWED_RESOLVED / HOST_CODE_REVIEW_NOT_SCANNER_PROOF` | 原问题有宿主代码复查记录，但编辑前影响门槛未满足，整体验收失败；宿主复查也不是扫描器证明 |
| B：`repair-impact-B-becca621`；`01a14d43-5422-73d1-8546-3d007dff93d2` | 第 133／138 行确认只新增 download.py 并登记真实原生风险；只问 owner-only 影响时准确识别共享成员读取、下载和共享列表不一致，无编辑或主动索取批准；第 175／194／246／275／300 行影响提交被拒绝，第 254 行将原生 ts1 误传扫描器准备入口得到 `REFRESH_REQUIRED` | 影响解释及只读行为通过；正式分析未保存，明确授权后的修复被阻塞、未执行，无修复后证明，整体验收未通过 |
| C：`repair-impact-C-95dfa550`；`01a14d43-bc1f-7781-914b-d3aac37dd03f` | 第 177／200／207 行影响提交为 `REPAIR_IMPACT_INPUT_INVALID`；第 228 行成功保存 DEFER，第 257 行读回 DEFERRED；第 245 行正式影响数量仍为 0 | 暂缓持久化支路通过；正式影响保存与历史未通过，不能据此登记整体验收通过 |

共同缺口是影响工具的嵌套字段没有充分暴露合法枚举，宿主反复猜测 kind／coverage；另有原生风险误入扫描器修复流程、未接受的影响被普通开发基线绕过。后续源码和候选增加严格参数与字段级修正提示、原生修复准备／取消入口及同归属修复意图守卫；后续场景各自验收，不将首轮失败追记为通过。本轮未知分级修正仍需新的独立回执。

### A2/B2/C2 初始化与本轮任务证据契约修正

三者首次均把 `primary_evidence`／`task_evidence` 写成 `{evidence_id,file_path,start_line,end_line}` 对象，并把 `evidence_refs` 写成这种对象的数组；后端要求已签发证据 ID 字符串，因此同一格式会确定性被拒绝。

| 初始化样例 | 实际纠错与保存结果 | 本轮判断 |
| --- | --- | --- |
| A2 | 第 1 次对象格式被拒绝，第 2 次改字符串 ID 后正式保存为 `COMPLETE / 1 finding` | 初始化恢复成功，不代表后续影响与修复场景整体通过 |
| C2 | 前 2 次对象格式被拒绝，第 3 次改字符串 ID 后正式保存为 `COMPLETE / 1 finding` | 初始化恢复成功，不代表后续影响与暂缓场景整体通过 |
| B2 | 3 次均为对象格式，未纠正，最后记录 `INCOMPLETE` | 初始化失败；保留原目录、聊天与失败现场，不自动重开终态或冒称风险已落库 |

本轮源码新增 typed 候选与 strings-only schema：`primary_evidence` 是本任务签发的证据 ID 字符串；`task_evidence` 若提供也是已签发的改动文件证据 ID 字符串；`evidence_refs` 是这些字符串组成的数组。安全 `field_errors` 给出具体字段和修正建议，不回显提交的源码、凭据或任意字段值。三版快速方法及 packet 提供完整 RELATED_EXISTING 形状示例，所有 ID 和风险叙述都仅为示意，必须改用真实读取的证据与代码事实，不能照抄登记示例风险。

可恢复的格式错误应在同一个**活动**任务、复核会话和源码版本内纠正重试，不重扫、不替换修改前基线；这一修正不自动恢复 B2 的 `INCOMPLETE` 终态。后续独立 B3 已完成初始化、owner-only 业务影响及保留共享成员的修复场景，B2 的失败记录继续保留。

此前证据契约定向组分别 51 项、34 项、8 项通过，不能相加或改写为本轮未知分级完整回归通过；其后实际连接已用于 A2/B3/C2 验收，结果见页首。本轮分级定向回归的最后结果见页首；完整候选回归及构建按对应 `run.json`／`artifacts/repair-impact-latest.json`、源码 manifest 和新能力核对，不由定向结果推定。安装与 A2 桌面复验仍待完成，不提前填写新 build_id 或登记桌面通过。

用户独立运行的 `repair-impact-20261018-061924-4d27e8` 回执记录：pytest 退出码 2，33 个测试收集错误，0 个用例通过；共同原因是 Pydantic 不允许在来源判别字段 `kind` 上使用继承的 `mode='before'` 校验。本次将空白文本校验改为 `mode='after'`，保留严格类型、合法枚举及空白拒绝，并补充两种来源和文本约束的回归用例。随后定向回执 `artifacts/repair-impact-focused-20261018-0741.xml` 为 **38 项通过、16 项失败、10 项错误，0 项跳过**，原收集阻塞已解除；其失败／错误源于临时项目位于主仓库 `artifacts` 下，WorkspaceResolver 正确回溯到父 Git 根，是测试目录隔离问题，不是对应产品功能失败。两组均未改源码或 fixture，移至仓库外独立临时目录后，`artifacts/repair-impact-native-intent-20261018065556-537b2b.xml` 为 **22 项通过**，`artifacts/repair-impact-native-mcp-20261018-081552.xml` 为 **10 项通过**，均为 0 失败、0 错误、0 跳过。旧失败保留，这些重跑不代表完整回归通过，详见[开发进度](DEVELOPMENT_PROGRESS.md)。最终构建证据以本轮 latest 成功回执及对应 manifest、源码摘要和 build_id 为准；旧 latest 不代表当前源码已打包，失败不得覆盖成功指针。参数、来源或分析提交错误应按工具契约修正，不以重装产品解决。

打包脚本已补齐三项 native 回归与字段契约等受影响检查，并在冻结进程工具发现中要求六项工具、嵌套影响类型／coverage 枚举、原生准备必填参数和严格布尔意图。首个用户重建批次在内部回归门槛停止，未到达打包和冻结进程探针；后续每层以独立回执认定。schema 探针本身不代表冻结进程已执行原生修复或裸 begin 守卫。过宽的提示已通过共享 CHECK_OPERATION_BOUNDARIES 收窄，三个提示路径的产品回归、实际包内能力和桌面行为仍分别验收，不能互相替代。

## 1. 构建、核对并安装

先保存工作，停止修改当前仓库并完全退出 Codex，包括仍在使用旧 Runtime 的窗口。打开 **Codex 之外的普通 Windows PowerShell**，一次执行下列命令。它先使用本机已有环境运行本产品研发回归，再生成独立候选并核对后安装；不执行样例项目测试，不安装开发依赖，不下载扫描引擎。任何步骤失败都应停止并保留输出，不能跳过失败改装旧 latest。

显式复用的旧启动器源码摘要和实际二进制摘要已只读核对一致；这不等于复用旧 Runtime。新包仍由当前源码完整构建，脚本还会验证启动器来源包的完整清单。不要自行设置 `PYTHONPATH=src`，以免影响现有环境的依赖许可元数据解析。

```powershell
$repairWorkspace = 'C:\Users\Administrator\Desktop\ai-security\Ai-security-check'
Set-Location -LiteralPath $repairWorkspace -ErrorAction Stop
$repairPython = Join-Path $repairWorkspace '.venv\Scripts\python.exe'
$repairLauncherBundle = Join-Path $repairWorkspace 'dist\repair-impact-20261018-034812-775f80\security-check'
$oldBuildIds = @(
    'd6ac9d9e0eb3842571f5acac713e057701672b459f3ec1df65908aa72bd4d2b5',
    'dd571d41ba8491fa095726216164755b98e5e429cee5467f46c32fd1e91078cf',
    '55977e7ec17204fe1087e7667bf34b2588e0e6c80f8b129a548197f1c1f27112'
)
if (-not (Test-Path -LiteralPath $repairPython -PathType Leaf) -or
    -not (Test-Path -LiteralPath $repairLauncherBundle -PathType Container)) {
    throw '已有构建环境或启动器来源包不存在；停止，不自动安装或换其他来源'
}
& $repairPython .\scripts\rebuild_repair_impact.py --launcher-bundle $repairLauncherBundle
if ($LASTEXITCODE -ne 0) { throw '构建或检查未通过；停止，不安装旧 latest' }

$receiptPath = '.\artifacts\repair-impact-latest.json'
if (-not (Test-Path -LiteralPath $receiptPath -PathType Leaf)) {
    throw '本次成功候选回执不存在；停止，不猜安装包路径'
}
$candidate = Get-Content -LiteralPath $receiptPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
if ($candidate.status -ne 'PASSED' -or
    $candidate.repair_impact_contract -ne 'repair-impact-v1' -or
    [string]::IsNullOrWhiteSpace([string]$candidate.build_id) -or
    $candidate.build_id -in $oldBuildIds) {
    throw '没有得到本轮新的成功 build；停止，不把旧候选当修正版'
}
$repairTools = @('prepare_repair_impact', 'read_repair_impact_context',
    'submit_repair_impact', 'get_repair_impact', 'prepare_task_risk_fix', 'cancel_task_risk_fix')
$missingRepairTools = @($repairTools | Where-Object { $_ -notin @($candidate.necessary_tools) })
if ($missingRepairTools.Count -gt 0) { throw '新回执缺少必要的六项工具；停止' }
$frozenProbe = Get-Content -LiteralPath $candidate.frozen_probe -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
if ($frozenProbe.status -ne 'PASSED' -or $frozenProbe.schema_contract.status -ne 'PASSED') {
    throw '冻结进程工具或字段契约检查未通过；停止'
}
if ($frozenProbe.runtime_info.features.repair_impact_unknowns -ne 'repair-impact-unknowns-v1') {
    throw '冻结进程未声明本轮未知分级能力；停止，不安装旧候选'
}
$bundle = [string]$candidate.bundle
$exe = [string]$candidate.executable
if (-not (Test-Path -LiteralPath $bundle -PathType Container) -or
    -not (Test-Path -LiteralPath $exe -PathType Leaf)) {
    throw '候选目录或程序不存在；不要改用其他路径猜测安装包'
}
$metadata = Get-Content -LiteralPath (Join-Path $bundle 'version.json') -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
if ($metadata.build_id -ne $candidate.build_id -or $metadata.version -ne '0.3.6') {
    throw '候选目录与回执的构建身份不一致，或不是本次 0.3.6 候选'
}
$metadata | Select-Object version, build_id, source_commit, source_dirty
& $exe install codex --bundle $bundle --json
if ($LASTEXITCODE -ne 0) { throw '安装未完成，保留安装输出并停止后续步骤' }
& $exe prepare-scanners --status --json
if ($LASTEXITCODE -ne 0) { throw '扫描组件状态读取未完成，保留输出，不反复安装' }
```

安装器会校验本地包的清单和摘要。最后一条命令只查看已有扫描组件及数据，不下载；扫描准备尚未完成与程序本地安装是两项状态，不因此反复安装。保留该状态输出，准备完成后再进行需要扫描器的案例。

候选回执保留 `installed=false` 和 `desktop_acceptance=PENDING_USER`，它描述交付时的状态。安装与桌面结果另行登记，不修改构建回执来制造通过记录。GitHub 提交、源码工作树、候选和当前已安装进程分别核对；`source_dirty=true` 时还须保留回执中的变动清单及源码摘要，不能说 GitHub 提交包含整个候选。

## 2. 重开后核对实际连接

安装命令成功后重新打开 Codex，在目标项目的新聊天发送：

> 只核对当前安全检查连接的构建身份和修复影响能力，不扫描项目、不修改文件。对照本功能候选回执核对构建 ID；确认支持修复影响查询及其编辑前流程。

新版通过条件：实际连接的 build_id 等于本轮新版回执，且不是此前 `d6ac9d9e…`、`dd571d41…` 或 `55977e7e…`；能力包含 `repair-impact-v1`、`risk-decisions-v2`、`security-reply-plan-v1`，且 `features.repair_impact_unknowns` 为 `repair-impact-unknowns-v1`。所需工具是子集核对，不要求工具总数固定。开发诊断时应能找到四项影响工具及 `prepare_task_risk_fix`、`cancel_task_risk_fix`，修复准备与确认接口支持 `impact_ref`；未知 schema 应声明 classification、decision_basis 及其约束，`submit_task_security_review` 应明确字符串证据字段及字符串数组，非法格式须有安全字段提示。只有六工具或相同版本号不能证明本轮修正已安装。个人默认连接不应出现已隐藏的功能验证入口。

若连接仍是旧构建，先按该连接提供的同环境重连指导刷新。仅在独立 PowerShell 运行候选的 `runtime-info --json`，不能证明 Codex 当前聊天已经重连。能力检查也不代替下面的交互验收。

本候选由可信产品 MCP 构造器默认接线影响服务及门槛，包括全局工作区子连接；无需也不提供客户端开关。仅直接嵌入 `RemediationService` 而没有配置 `impact_gate` 的旧调用保持兼容，不能把该嵌入路径当作已验证的强制门槛；桌面验收应使用实际产品连接。

## 3. 独立全链样例的建立方式与历史保留

旧 A/B/C 可以继续查看历史：B 的三个原始文件可作为独立对照起点，C 的已保存暂缓可回读。A2、B3、C2 及 B2 的已有记录全部保留，不覆盖目录、清空处置或重建旧任务。**当前 A2 分级续验沿原聊天和原风险进行；B3/C2 已通过分支不重复执行修复或撤销暂缓。** 下列脚本仅保留独立全链对照的创建方法；需要新对照时使用未用过的样例名称和新后缀，不继承旧引用或会话状态，也不把新对照当作恢复原 A2 的手段。

以下命令只从原 B 目录复制 `documents.py`、`permissions.py`、`sharing.py` 三个文件到全新目录。本轮只读核对确认 B 的读取入口仍未修复；命令也核对三个原文件的摘要，后续若被改动就停止，此复制方案不再适用。不会复制 download.py、`.git`、项目配置、状态或任何原任务引用，也不运行样例源码。新目录名使用时间和随机值，已存在的目标直接停止，保留全部旧目录。

```powershell
$repairDesktop = [Environment]::GetFolderPath('Desktop')
$repairSeed = Join-Path $repairDesktop 'repair-impact-B-becca621'
$repairSeedFiles = @('documents.py', 'permissions.py', 'sharing.py')
$repairSeedHashes = @{
    'documents.py' = '1d9f5c950a01f14b0557f1f2660f1813e17d6b98a58f403fbdc82aef43cb28fe'
    'permissions.py' = '0370da1f393eaa480b1cc6b510b31950e742a189d0479c6182195e20dbc59bfe'
    'sharing.py' = 'a01aecfb09ac8976040f66a2477f7fbedc2a2199054e5f6156aaa4fdce8d6f9f'
}
foreach ($repairSeedFile in $repairSeedFiles) {
    $repairSourceFile = Join-Path $repairSeed $repairSeedFile
    if (-not (Test-Path -LiteralPath $repairSourceFile -PathType Leaf)) {
        throw '原 B 的初始文件缺失；停止，不猜其他样例来源'
    }
    $repairSourceHash = (Get-FileHash -LiteralPath $repairSourceFile -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    if ($repairSourceHash -ne $repairSeedHashes[$repairSeedFile]) {
        throw '原 B 文件已变化，不适合作为该验收起点；停止，不覆盖旧文件'
    }
}
$repairTrialSuffix = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0,6)
$repairCases = @{}
foreach ($repairCaseName in @('A2', 'B2', 'C2')) {
    $repairNewTrial = Join-Path $repairDesktop ('repair-impact-' + $repairCaseName + '-' + $repairTrialSuffix)
    New-Item -ItemType Directory -Path $repairNewTrial -ErrorAction Stop | Out-Null
    foreach ($repairSeedFile in $repairSeedFiles) {
        Copy-Item -LiteralPath (Join-Path $repairSeed $repairSeedFile) -Destination (Join-Path $repairNewTrial $repairSeedFile) -ErrorAction Stop
    }
    git init --quiet $repairNewTrial
    if ($LASTEXITCODE -ne 0) { throw '新样例项目创建未完成；停止并保留已有目录' }
    $repairCases[$repairCaseName] = $repairNewTrial
}
$repairCases.GetEnumerator() | Sort-Object Key | Format-Table Key, Value -AutoSize
$trial = $repairCases['A2']
```

在 Codex 分别打开三个输出路径，各开新聊天。每个聊天都先发送下面同一条**样例开发请求**，形成各自真实的编辑前记录和任务原生风险；不能把复制来的三个旧文件当作刚刚由 Agent 编辑的历史：

> 这是本地验收样例。业务规则是：文档所有者和 member_ids 中的共享成员可以读取，其他用户不能读取。请在编辑前按正常开发任务流程记录起点，然后仅新增 download.py：导入 documents.read_document，新增 download_document(user_id, document_id, repository)，将三个参数原样转交并返回结果。保留现有三个文件，不运行样例或构建。完成本次开发任务安全核查，调查下载、文档读取和共享权限之间的关系，登记并报告相关权限风险，先不要修复。

应调查 `download_document → read_document` 的调用，以及 `can_read` 和共享列表的业务条件。风险应指出未授权用户可按文档 ID 读取内容的条件，同时保留“所有者或共享成员可以正常读取”的现有依据。必须有可查询的任务原生风险记录，再进入下一步；只得到口头分析、只有扫描器零告警或来源材料不足时，登记未满足前置条件，不伪造扫描器告警、原任务或修改前版本。

B3 先检查 `submit_task_security_review` 实际提交：证据字段必须是该任务读取返回的 ID 字符串及其数组；若可恢复格式错误，应按 `field_errors` 在原活动任务内纠正，不另起基线。只有正式初始化完成且 read_document 原生风险已落库，才进入下表 B 场景。若再次终止为 `INCOMPLETE`，保留现场并记录初始化失败，不继续假定风险已建立。

该样例主要验收任务原生风险。扫描器分组与确定性票据路径还须使用其已有可复现告警分别执行第 4—6 节，不能用原生风险通过代替扫描器通道通过。

确认各新聊天均已正式登记真实原生风险后，按下表执行一次，不要先执行表格再重复下节的同一请求。A2 的详细核对方法在下节，B 场景本轮使用新 B3，C2 按其对应行执行；原 B2 未满足初始化前置条件，不能直接进入业务场景，也不要把一组的回复或引用搬到另一组：

| 新样例 | 后续第一条 | 后续第二条及回读 |
| --- | --- | --- |
| A2 | “修复刚才这项权限问题会对哪些正常操作产生影响？先只分析，不修改代码。” | “按保留所有者和共享成员访问、拒绝其他用户的方案，修复刚才这项问题。”完成后问“查看刚才保存的影响分析及原问题的安全复查记录，不重新扫描、不修改代码。” |
| B 场景：新 B3 | “如果把刚才的问题改成只有文档所有者能读取，哪些正常操作会受到影响？请结合共享成员和下载入口分析，先不要修改代码。” | “不采用只允许所有者的方案。按保留所有者和共享成员访问、拒绝其他用户的方案修复刚才这项问题。”完成后同样回读影响及原问题复查记录 |
| C2 | “修复刚才这项权限问题会对哪些正常操作产生影响？先只分析，不修改代码。” | “这项问题稍后处理。”随后问“查看刚才保存的影响说明和这项问题当前的处理记录，不重新扫描、不修改代码。” |

A2 与新 B3 的只读轮必须不编辑、不主动索取修复批准；B3 要明确合法共享成员的读取和下载被 owner-only 阻断。明确修复后应沿同一具体授权执行，正式影响已保存且准备通过，原问题的复查记录另行落库。C2 必须直接持久化暂缓、不要求影响先过门槛、不修代码，回读能分别看到影响历史和暂缓处置。任何一步只有口头完成、实际提交被拒绝或来源不清楚，都记录具体失败／阻塞，不算整体通过。下节是 A2 的详细核对方法；B3／C2 使用各自目录和聊天，避免重复发送修复请求。

确定性 Java TLS 路径还须核对 Agent 如何取得规范方案：用户明确批准选定修复后，Agent 先沿原 pending 的 `confirmation_ref/task_ref` 调用 `confirm_remediation(approve=true)`，不传 `impact_ref`；应返回 `IMPACT_REQUIRED.next_action.arguments` 中的 Runtime 规范 source/proposal，且尚未签发 grant 或增加尝试次数。Agent 应原样完成该方案的影响准备、读取和提交，再使用同一确认引用与 `impact_ref` 续办，不要求用户传递内部引用或再次批准。若先前自拟方案返回 `IMPACT_PROPOSAL_MISMATCH`，原 pending 仍有效时可以不传 `impact_ref` 重新取得规范方案，不能循环猜测摘要；过期和范围变化按原确认恢复契约处理。此为待观察的验收流程，未执行时仍登记 `PENDING_USER`。

## 4. A2：只问影响与已授权续办的详细核对

以下是独立全链 A 场景的核对方法，首次创建时在该目录及其聊天执行一遍。**当前已阻塞的 A2 续验应先核对实际连接的新分级能力，再沿原聊天、原风险、原影响和已有授权继续；不要重建 download.py、另起开发基线或重复发送已有修复批准。** B3/C2 已完成分支不因本轮修正重跑。对新的独立样例，先在创建样例时的同一独立 PowerShell 保存源码摘要：

```powershell
$before = @(Get-ChildItem -LiteralPath $trial -File -Filter '*.py' | Get-FileHash -Algorithm SHA256)
```

在刚才的聊天，对准刚才明确的一项风险发送：

> 修复 read_document 这项权限问题会对功能产生什么影响？先只分析，不修改代码。

通过条件：解释方案、已查正常调用、共享成员和其他用户的区别、实际未知；根据关联依据扩读，不为了达到数量读取无关文件。不新建开发基线、不启动新扫描、不确认修复，也不把影响报告当授权。私有评估草稿和证据记账可以保存，源码保持不变。

```powershell
$after = @(Get-ChildItem -LiteralPath $trial -File -Filter '*.py' | Get-FileHash -Algorithm SHA256)
Compare-Object $before $after -Property Path, Hash
```

无输出表示这些源码摘要未改变；同时核对没有新增样例源码。随后只发送一次：

> 修复刚才 read_document 这项权限问题，保留所有者和共享成员的正常读取，只拒绝没有访问权的人。先简述具体影响，然后继续完成修复。

通过条件：在编辑前补足影响材料并沿用该次明确授权，不机械再问“是否确认修复”。优先复用现有共享权限逻辑，不直接限定只有创建者。四个必要文件已读且复用既有 can_read、未见具体合法路径冲突时，不因没有提供整个仓储或外层异常显示而泛化阻塞；这些限制保存在 SCOPE_LIMITATION，不能重复作为 UNDETERMINED。若有真实正常记录缺字段、需改变跨边界身份来源等具体必要事实，则仍阻断并说明事实如何改变当前方案及下一步。改动与既定方案一致；安全复查和已识别的功能影响分别说明，不承诺整个项目功能正常，不主动推荐功能测试。

原生风险的机器回执还须分别核对：

- `submit_repair_impact` 实际接受分析。kind 只接受 `EXPECTED_SECURITY_RESTRICTION`、`NO_ADDITIONAL_CHANGE_IDENTIFIED`、`BUSINESS_BEHAVIOR_CHANGE`、`UNDETERMINED`；coverage 只接受 `REVIEWED` 或 `PARTIAL`。拒绝回执须给可修正字段，不能把 DRAFT、impact_count=0 或“文件已读完”算成通过；原分析、已有授权和原风险保留，不另建普通开发基线绕过。
- 新连接的未知项分级与依据真实保存：SCOPE_LIMITATION 必须 critical=false，BLOCKING_CONTEXT 必须 critical=true 且有本评估实际证据；两者 decision_basis 均非空、不超过 800 字符。记录“已读有限范围但还有非阻断未知”可为 REVIEWED；必读未读、过期、来源变化、真实必要未知及当前方案具体效果不明仍不能变成 READY。READY 也不授予修复权。
- 已明确修复后，先取得或复用原方案 assessment_ref，尽早调用 `prepare_task_risk_fix(task_ref, finding_id, impact_ref, user_requested=true)`，保留原修订及有效 session_ref。入口先核对真实原生风险及归属，再保存修复意图；影响未满足条件时只保存 WAITING、不创建开发基线。随后沿同一评估 read／submit，再重试该准备入口。同 owner 的待准备或在途修复意图会阻止裸 `begin_security_task`；准确签名绑定的任务已为 COMPLETE／NO_CHANGES 时允许后续普通开发，旧准备材料仍只返回原终态任务，不重建基线。普通只读影响草稿不因此阻塞其他开发。
- 只有成功准备且 `ready_for_host_fix=true` 才按原方案编辑。入口直接建立或复用编辑前基线，返回 `repair_task_ref`；不再另调 begin，不把 ts1 传给 scanner `prepare_task_fix`，不伪造 scan_id 或为修引用重扫项目。该约束不等于 Runtime 能原子拦截任意外部文件编辑。
- finish／review 使用返回的修复任务；`risk_resolutions.original_task_ref` 和 finding_id 指向原风险，当前证据覆盖原风险的必要路径及实际改动。随后读原任务风险账本，分别确认影响保存和 `CODE_REVIEWED_RESOLVED / HOST_CODE_REVIEW_NOT_SCANNER_PROOF`；新任务零发现不能关闭原风险。

另建同起点样例，先授权修复，再在处理过程中追问“会影响什么功能”。应先回答，再在原有效范围继续；不把追问当撤销授权，也不重复取得同一批准。

## 5. 业务取舍、暂缓与查询

分别在独立起点执行，避免前一项已经修复后伪造新的待修复问题：

| 用户表达或场景 | 应观察到的结果 |
| --- | --- |
| “如果改成只有创建者可读，哪些正常操作会受影响？只分析” | 明确共享成员会失去读取权限，引用实际权限与调用依据；不给这种方案自动授编辑权 |
| 修复必需的角色、接口或配置规则无法核实 | 先查可得材料；保留具体关键未知，必要时只问决定方案的业务问题，不泛问“有风险是否继续” |
| 已读局部权限和委托链，但没有提供整个外部仓储、身份源或异常显示 | 若当前方案不改变这些边界且没有具体冲突依据，保存 SCOPE_LIMITATION 与有限结论；不自动升级阻断，不宣称全局兼容 |
| 对照源码显示合法共享成员可走缺少权限字段的精简投影，当前分支尚不能核对 | 保存有证据的 BLOCKING_CONTEXT，说明投影选择如何改变方案及必要下一步；UNDETERMINED 仍阻断，不借 A2 正例自动放行 |
| 明确业务取舍后说“按保留共享成员的方案修复” | 绑定对应方案和范围继续，不再增加一次通用批准 |
| 对该明确风险说“稍后处理” | 直接沿原处置保存暂缓，不要求先完成影响评估、不修改源码；保存成功后说明风险保留且本次不再追问 |
| “查看刚才的影响说明及原风险记录，不重新扫描” | 历史读取不创建新取证、不续预算、不恢复授权；原风险、用户决定及影响说明各自保留 |
| 用户决定排除或恢复提醒 | 沿原处置语义执行，影响评估不擅自关闭漏洞、撤销决定或重复旧提示 |
| 已登记修复意图后明确暂停或切换其他开发 | 用 `cancel_task_risk_fix` 报告原 task_ref／finding_id 及 user_requested=true，无须另问批准；只解除该流程阻塞，风险、用户处置、审计和原基线保留，不冒充 DEFER |
| 暂停后尝试恢复原修复 | 沿原基线复核当前风险、最新方案、材料期限和源码；相关依据变化时返回原修复任务待复核、ready=false，不新建基线。DEFER／EXCLUDE 成功自动解除同一修复意图，不要求影响先通过 |

## 6. 来源、版本和范围边界

以下案例需要原始引用和实际工具回执，不能靠自然语言回复判断通过：

- 多项风险中只说“修复”，目标不清楚时仅澄清目标；选择原响应第 1、3 项后，即使摘要重排，也仍处理原两项。
- 扫描器一组含多个成员时，准确记录当前活动集合；只选择组内一个成员不得扩为整组。当前通道无法表达该子集就明确不支持，不假称已有子集参数。
- 同一开发任务进入新的复核修订后再查询旧风险，分别绑定原风险修订和当前源码；无法取回原详情就说明缺口，不用最新风险或最新复核会话冒名替代。
- 另一聊天可按同工作区历史契约读取报告，但不能因此认领、续办或提交原评估。重连恢复保留原合法引用、证据与累计消费，不新建任务清零。
- 相关权限或配置改变后，编辑前发现材料失效并只重评必要范围；注释、行号或无关变化不自动撤销处置和重复授权。
- 需要 Markdown、原扫描清单之外的文件或被遮盖的角色／配置值时，使用实际支持的受限适配器；不支持或脱敏后无法判断就保留未知，不改用原始凭据完成评估。
- 多页和离散窗口依次完成；已识别必读范围超过旧小额度时，仍完整入计划。容量、额度或活动租约不足应保留进度及部分结果，回执不代表评估通过。
- 拒修、建议生成和人工处置不受编辑前门槛阻塞；产生可编辑状态、grant 或票据时仍核对有效影响记录与原授权。快速票据发出后不再插入跨模块调查。

容量、存储错误、伪造引用和并发由内部研发回归提供受控证据。桌面实际遇到时另记结果，不为验收破坏真实状态库，不把领域错误误报为项目未导入或要求重装。

## 7. 记录与通过条件

逐项记录候选 build_id、源码提交与 dirty 状态、源码摘要回执、安装输出、扫描准备状态、宿主版本、样例路径、聊天、准确问题来源、用户原话、实际回复、源码前后摘要、通过／失败及具体原因。不同宿主和不同修复通道分别留证。

构建脚本 `scripts/rebuild_repair_impact.py` 只由开发任务使用当前已有构建环境执行：先运行本功能及相关交互、修复、隐藏入口、归属和证据回归，再构建唯一的新 dist/build 目录，验证完整包、冻结进程身份、契约和所需工具，仅成功后更新 `artifacts/repair-impact-latest.json`。失败保留独立 run 回执，不覆盖上一个成功候选或其他功能的 latest 指针。该内部检查不执行用户项目，不为个人版重新开放功能测试能力。

自动回归、包完整性、冻结包工具及字段契约和真实桌面交互是不同证据。容量与分类消费的受控证据来自实际运行的定向内部回归；新版冻结探针会核对启动、身份、契约、六工具发现和嵌套 schema，不能据此宣称冻结进程已运行 prepare/read/submit 影响分析、消费过源码额度或执行过原生准备／基线守卫。只有用户实际完成对应案例并确认结果后，才将本功能桌面验收登记为通过；未完成案例保留 `PENDING_USER` 或具体缺口，不由 Agent 自报替代。
