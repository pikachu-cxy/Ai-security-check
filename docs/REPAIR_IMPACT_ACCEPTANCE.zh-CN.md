# 修复影响评估真实桌面验收

更新日期：2026-10-18。目标版本：`0.3.6`，目标契约：`repair-impact-v1`。候选构建与内部研发检查由独立回执记录，真实桌面验收保持 `PENDING_USER`。

用户本次已明确授权按当前方案开工、同步 GitHub 并构建可安装候选。这是新的实施授权，不把旧交互候选的待验收状态追记为通过。本页供候选安装与真实聊天验收使用，用户不需要自行构建、安装 Python 或安装开发依赖。验收只覆盖实际记录的候选和宿主。

## 1. 读取本功能候选并安装

使用 **Codex 之外的普通 Windows PowerShell**。先保存工作并完全退出 Codex（包括仍在使用旧 Runtime 的窗口），再执行以下命令。构建回执不存在时，应由开发任务先完成候选，不使用旧的 dependency-fix 回执替代。

```powershell
Set-Location 'C:\Users\Administrator\Desktop\ai-security\Ai-security-check'
$receiptPath = '.\artifacts\repair-impact-latest.json'
if (-not (Test-Path -LiteralPath $receiptPath -PathType Leaf)) {
    throw '本功能候选尚未生成，请保留当前安装并等待候选回执'
}
$candidate = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
if ($candidate.status -ne 'PASSED' -or $candidate.repair_impact_contract -ne 'repair-impact-v1') {
    throw '回执不是已完成内部构建检查的修复影响候选'
}
$bundle = [string]$candidate.bundle
$exe = [string]$candidate.executable
if (-not (Test-Path -LiteralPath $bundle -PathType Container) -or
    -not (Test-Path -LiteralPath $exe -PathType Leaf)) {
    throw '候选目录或程序不存在；不要改用其他路径猜测安装包'
}
$metadata = Get-Content -LiteralPath (Join-Path $bundle 'version.json') -Raw | ConvertFrom-Json
if ($metadata.build_id -ne $candidate.build_id -or $metadata.version -ne '0.3.6') {
    throw '候选目录与回执的构建身份不一致，或不是本次 0.3.6 候选'
}
$metadata | Select-Object version, build_id, source_commit, source_dirty
& $exe install codex --bundle $bundle --json
if ($LASTEXITCODE -ne 0) { throw '安装未完成，保留安装输出并停止后续步骤' }
& $exe prepare-scanners --status --json
```

安装器会校验本地包的清单和摘要。最后一条命令只查看已有扫描组件及数据，不下载；扫描准备尚未完成与程序本地安装是两项状态，不因此反复安装。保留该状态输出，准备完成后再进行需要扫描器的案例。

候选回执保留 `installed=false` 和 `desktop_acceptance=PENDING_USER`，它描述交付时的状态。安装与桌面结果另行登记，不修改构建回执来制造通过记录。GitHub 提交、源码工作树、候选和当前已安装进程分别核对；`source_dirty=true` 时还须保留回执中的变动清单及源码摘要，不能说 GitHub 提交包含整个候选。

## 2. 重开后核对实际连接

重新打开 Codex，在目标项目的新聊天发送：

> 只核对当前安全检查连接的构建身份和修复影响能力，不扫描项目、不修改文件。对照本功能候选回执核对构建 ID；确认支持修复影响查询及其编辑前流程。

通过条件：实际连接的 build_id 等于回执；能力包含 `repair-impact-v1`、`risk-decisions-v2` 和 `security-reply-plan-v1`；所需工具是子集核对，不要求工具总数固定。开发诊断时应能找到 `prepare_repair_impact`、`read_repair_impact_context`、`submit_repair_impact`、`get_repair_impact`，修复准备与确认接口支持 `impact_ref`。个人默认连接不应出现已隐藏的功能验证入口。

若连接仍是旧构建，先按该连接提供的同环境重连指导刷新。仅在独立 PowerShell 运行候选的 `runtime-info --json`，不能证明 Codex 当前聊天已经重连。能力检查也不代替下面的交互验收。

本候选由可信产品 MCP 构造器默认接线影响服务及门槛，包括全局工作区子连接；无需也不提供客户端开关。仅直接嵌入 `RemediationService` 而没有配置 `impact_gate` 的旧调用保持兼容，不能把该嵌入路径当作已验证的强制门槛；桌面验收应使用实际产品连接。

## 3. 建立独立共享成员样例

每组需要不同起始状态的案例另建一个样例目录，保留已验收目录。下面的命令只创建本地说明样例，不启动服务或执行样例源码。

```powershell
$trialName = 'repair-impact-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + ([guid]::NewGuid().ToString('N').Substring(0,6))
$trial = Join-Path ([Environment]::GetFolderPath('Desktop')) $trialName
New-Item -ItemType Directory -Path $trial | Out-Null
git init --quiet $trial
if ($LASTEXITCODE -ne 0) { throw '样例项目创建未完成' }
$permissionSource = @'
def can_read(user_id, document):
    return (
        user_id == document["owner_id"]
        or user_id in document["member_ids"]
    )
'@
$documentSource = @'
def read_document(user_id, document_id, repository):
    document = repository.get(document_id)
    return {"id": document["id"], "body": document["body"]}
'@
$sharingSource = @'
from permissions import can_read


def shared_document_ids(user_id, repository):
    return [
        document["id"]
        for document in repository.list_all()
        if can_read(user_id, document)
    ]
'@
[IO.File]::WriteAllText((Join-Path $trial 'permissions.py'), $permissionSource, [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText((Join-Path $trial 'documents.py'), $documentSource, [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText((Join-Path $trial 'sharing.py'), $sharingSource, [Text.UTF8Encoding]::new($false))
$trial
```

在 Codex 打开输出路径，新聊天发送以下**样例开发请求**，用于形成具有真实编辑前记录的任务原生风险，不能把手动创建的旧文件当作刚刚由 Agent 编辑的历史：

> 这是本地验收样例。请在编辑前按正常开发任务流程记录起点，然后仅新增 download.py：导入 documents.read_document，新增 download_document(user_id, document_id, repository)，把三个参数原样转交并返回结果。样例故意保留 documents.py 的权限缺失，不修改现有三个文件、不运行样例或构建。完成任务安全核查，调查调用与共享成员规则，报告相关权限风险，先不要修复。

应调查 `download_document → read_document` 的调用，以及 `can_read` 和共享列表的业务条件。风险应指出未授权用户可按文档 ID 读取内容的条件，同时保留“所有者或共享成员可以正常读取”的现有依据。必须有可查询的任务原生风险记录，再进入下一步；只得到口头分析、只有扫描器零告警或来源材料不足时，登记未满足前置条件，不伪造扫描器告警、原任务或修改前版本。

该样例主要验收任务原生风险。扫描器分组与确定性票据路径还须使用其已有可复现告警分别执行第 4—6 节，不能用原生风险通过代替扫描器通道通过。

确定性 Java TLS 路径还须核对 Agent 如何取得规范方案：用户明确批准选定修复后，Agent 先沿原 pending 的 `confirmation_ref/task_ref` 调用 `confirm_remediation(approve=true)`，不传 `impact_ref`；应返回 `IMPACT_REQUIRED.next_action.arguments` 中的 Runtime 规范 source/proposal，且尚未签发 grant 或增加尝试次数。Agent 应原样完成该方案的影响准备、读取和提交，再使用同一确认引用与 `impact_ref` 续办，不要求用户传递内部引用或再次批准。若先前自拟方案返回 `IMPACT_PROPOSAL_MISMATCH`，原 pending 仍有效时可以不传 `impact_ref` 重新取得规范方案，不能循环猜测摘要；过期和范围变化按原确认恢复契约处理。此为待观察的验收流程，未执行时仍登记 `PENDING_USER`。

## 4. 只问影响与已授权续办

先在独立 PowerShell 保存当前样例源码摘要：

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

通过条件：在编辑前补足影响材料并沿用该次明确授权，不机械再问“是否确认修复”。优先复用现有共享权限逻辑，不直接限定只有创建者。改动与既定方案一致；安全复查和已识别的功能影响分别说明，不承诺整个项目功能正常，不主动推荐功能测试。

另建同起点样例，先授权修复，再在处理过程中追问“会影响什么功能”。应先回答，再在原有效范围继续；不把追问当撤销授权，也不重复取得同一批准。

## 5. 业务取舍、暂缓与查询

分别在独立起点执行，避免前一项已经修复后伪造新的待修复问题：

| 用户表达或场景 | 应观察到的结果 |
| --- | --- |
| “如果改成只有创建者可读，哪些正常操作会受影响？只分析” | 明确共享成员会失去读取权限，引用实际权限与调用依据；不给这种方案自动授编辑权 |
| 修复必需的角色、接口或配置规则无法核实 | 先查可得材料；保留具体关键未知，必要时只问决定方案的业务问题，不泛问“有风险是否继续” |
| 明确业务取舍后说“按保留共享成员的方案修复” | 绑定对应方案和范围继续，不再增加一次通用批准 |
| 对该明确风险说“稍后处理” | 直接沿原处置保存暂缓，不要求先完成影响评估、不修改源码；保存成功后说明风险保留且本次不再追问 |
| “查看刚才的影响说明及原风险记录，不重新扫描” | 历史读取不创建新取证、不续预算、不恢复授权；原风险、用户决定及影响说明各自保留 |
| 用户决定排除或恢复提醒 | 沿原处置语义执行，影响评估不擅自关闭漏洞、撤销决定或重复旧提示 |

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

自动回归、包完整性、冻结包工具列表和真实桌面交互是不同证据。容量与分类消费的受控证据来自实际运行的定向内部回归；冻结探针只证明其实际检查过的启动、身份、契约和工具发现，不能据此宣称冻结进程已运行 prepare/read/submit 影响分析或消费过源码额度。只有用户实际完成对应案例并确认结果后，才将本功能桌面验收登记为通过；未完成案例保留 `PENDING_USER` 或具体缺口，不由 Agent 自报替代。
