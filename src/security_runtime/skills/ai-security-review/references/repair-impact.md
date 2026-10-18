# 修复影响分析


修复影响分析（repair-impact-v1）：
漏洞后果与拟修复方案对正常业务的影响分别保存并经同一 reply_plan 呈现，不另建提示链。
先生成具体建议再分析；generate_fix 只生成建议，不要求先取得影响 READY，也不授予编辑权限。
用户对选定问题明确回复修复后，保留原响应的任务／风险引用和编号映射，不按新摘要排序换对象。
扫描器分组使用 SCANNER_TASK_GROUP；任务原生风险使用 HOST_TASK_RISK，保留原风险修订和快照，
不伪造 scan_id、不用最新风险或其他会话代替。prepare_task_fix／verify_task_fix 仅用于扫描器任务，
不能传入任务原生风险的 ts1 引用；原生风险使用下述 prepare_task_risk_fix 分支，不因路由错误另扫或换引用。
当前 prepare_task_fix 没有任意组内子集参数；
不能准确表达用户所选子集时说明范围限制，不扩大成全组。暂缓／排除成员不纳入活动修复范围。
在确认批准或进入宿主编辑前，调用 prepare_repair_impact，按工具 schema 提交 source 和 proposal：
security_goal、summary、changes[{file_path,start_line,end_line,reason}]、preserve[]。
source 按实际 schema 使用 kind/task_ref，原生风险另带 finding_id 及可用的 origin_review_revision；
原快照由 Runtime 定位并返回，保留返回的来源身份，不自填或猜测 origin_snapshot_id。
原有建议／无授权准备材料可先取得；影响 prepare 不调用开发任务 prepare／finish 或新扫描。
沿原评估计划通过 read_repair_impact_context 读取必读窗口，复用经校验的同版材料，再提交
submit_repair_impact 所需的实际证据、影响和未知。不能因搜索零命中、import 或已读页无异常宣称全局兼容。
业务取舍要说明具体角色、操作、变化及替代方案；只问会改变方案的事实，不循环询问用户证明漏洞真假。
impacts 使用 kind/summary/evidence_refs，unknowns 使用 summary/critical/evidence_refs。
kind 只接受 EXPECTED_SECURITY_RESTRICTION（预期安全限制）、NO_ADDITIONAL_CHANGE_IDENTIFIED
（已读范围内未发现额外变化）、BUSINESS_BEHAVIOR_CHANGE（正常业务变化）、UNDETERMINED（无法判断）。
coverage 只接受 REVIEWED 或 PARTIAL；不要使用 FULL／COMPLETE、缩写或大小写变体。
每项影响至少引用一个本评估读取回执的 evidence_ref；unknowns.critical 必须是布尔值。
submit 返回未接受、INCONCLUSIVE 或字段错误时，说明本次提交未保存、原有记录保留，并按具体错误和正式方法修正原提交，
不把草稿或“源码已读完”当作 READY，不猜枚举反复试投，不通过新 begin_security_task、换任务或新扫描绕过编辑前条件。
保留用户对同一问题和方案的既有修复授权，技术性提交失败不重复索取同一批准；不能补齐时说明具体阻塞并保持代码不变。
仅当用户明确接受已说明的当前方案业务变化时，提交 business_choice={user_requested:true,
proposal_revision:当前方案摘要,decision:'ACCEPT_PROPOSED_CHANGE'}；原批准已包含同一取舍时复用，不重复问。
一般修复请求或影响查询不能伪造此选择报告，业务选择本身也不补发编辑授权。
有关键未知时停止对应方案；有效评估只表示编辑前条件，不是修复授权或功能验证证明。
扫描器分支满足条件后，confirm_remediation(approve=true) 或 prepare_task_fix 传原 assessment_ref 为 impact_ref，
沿原任务、确认引用和授权继续，不重复确认同一修复。
原生风险明确修复后，先 prepare_repair_impact 取得或复用原方案 assessment_ref，尽早调用 prepare_task_risk_fix，
传原 task_ref、finding_id、该 impact_ref、可用的 origin_review_revision，以及 user_requested=true，登记选定修复意图。
当前影响尚未 READY 时只保存 WAITING 意图、不建基线；沿同一评估 read／submit，提交被接受后重试同一原生准备入口。
只有返回 ready_for_host_fix=true 和 repair_task_ref 才进入编辑；不把登记意图或影响查询当作准备完成。
user_requested 仅报告用户对已选问题的明确修复意图，是 UNTRUSTED_HOST_REPORT；影响查询、模型建议或一般开发请求不能填 true。
准备成功直接建立修复前开发基线并返回 repair_task_ref；保留原 source 和方案，仅用该 repair_task_ref 做 finish／review，
不再裸调用 begin_security_task。准备失败不建立基线、不编辑，不用 scanner 入口、换引用或新开发任务绕过。
修复后对照已接受方案和应保留行为核对实际改动；submit_task_security_review 的 risk_resolutions 仍绑定原 task_ref／finding_id，
再以原任务 get_task_risk_ledger 核对落库状态。新任务零发现不关闭原风险，宿主复核不冒称扫描器复查证明。
risk_resolutions 每项使用 original_task_ref、finding_id、evidence_refs、outcome、rationale、tests；
original_task_ref 是原风险任务，不是 repair_task_ref。outcome 只接受 CODE_REVIEWED_RESOLVED、STILL_PRESENT 或 INCONCLUSIVE。
证据须覆盖原风险全部必需路径的当前版本并含本次实际改动；tests 如实记录实际验证或未执行事项，不编造复查成功。
当前宿主没有原子编辑桥时，这些调用顺序是宿主协议约束，不能宣称 Runtime 能强制拦截任意外部编辑。
真实选定风险已登记修复意图后，准备未完成时同归属普通 begin 会被阻止；先修正原评估或说明阻塞，不另起任务绕过。
只有用户明确暂停该修复或切换到其他开发时，调用 cancel_task_risk_fix，传原 task_ref／finding_id 和
user_requested=true，结束该修复工作流的阻塞意图；这是用户既有暂停／切换请求的报告，不另索取批准。
取消不代表 DEFER／EXCLUDE，不关闭风险、不修改用户处置或撤销已有审计。
DEFER／EXCLUDE 保存选择与解除修复意图分别确认；仅原意图释放返回 APPLIED 才可称工作流已解除。
释放为 PENDING 时说明选择已保存、解除待恢复，沿原引用恢复，不重复索取同一选择、不取消后建意图。
approve=false、DEFER／EXCLUDE／RESTORE 不经过影响门槛；明确稍后处理时直接保存对应处置，不先补影响或创建修复任务。
SessionStart 提供有效 session_ref 时，prepare/read/submit/get 与 confirm_remediation/prepare_task_fix/prepare_task_risk_fix/cancel_task_risk_fix
一致携带该引用；没有时保持当前连接范围，不猜测归属或最近任务。重试不重建基线、不清空累计消费。
用户只问影响且没有既有修复授权时，只准备／读取／分析报告，不调用批准、不编辑；
用户明确限定本轮只看影响或先不要改代码时，即使有既有授权本轮也不编辑；保留授权，恢复原范围时不重问。
get_repair_impact 及历史只读不转移 owner、不重新取证、不恢复授权。只读查询不索取新的修复或业务批准。
已授权修复中追问影响，先回答再按原有效范围继续，明确暂停、新业务取舍或范围变化才停相应编辑。
对已签发 INLINE_PREPARED 票据不得追加搜索；影响分析必须在签发前完成，随后仅按原票据精确编辑与复查。
相关代码、方案或活动成员变化时按原引用重评，不能偷偷换成员、扩大 envelope 或复活过期 grant。
新增影响不覆盖 RiskFact.impact，不重置 authorized／choice_required；沿用 suppressed、handling_available、
current 过滤，已排除／暂缓不重问，处置不可读不回退旧提示。业务方案选择不是第二次 FIX／DEFER。
普通用户只看具体方案、正常行为变化和关键未知，不显示工具、引用、内部 gate 或授权枚举。
个人版不接入或推荐功能测试，也不把功能未测列为安全检查缺口；原问题安全复查与影响分析分别说明。


未知分级判据（repair-impact-unknowns-v1）：
先固定当前选定方案、用户已经说明的业务规则及必须保留的正常操作，再判断缺失事实是否改变本次实施决定。
BLOCKING_CONTEXT（关键阻断未知，critical=true）必须指出：具体角色与正常操作、已读依据、缺失的必要事实、
该事实的不同答案为何会改变当前方案，以及编辑前最小核对步骤。不能以“未提供全项目代码”代替这条决策依赖。
例如：已读仓储明确向合法读取返回不含权限字段的投影，但拟复用的权限函数要求这些字段；补齐方式尚未确定；
或者本方案要改变身份来源，而新来源及其可信绑定尚不能核实。这些直接决定正常访问或安全目标，仍须阻断。
SCOPE_LIMITATION（仅限制结论范围的未知，critical=false）表示已读依据足以决定当前局部改法，缺失材料只限制
结论能否推广到外部调用、仓储实现、部署或界面。decision_basis 要解释为何不改变本次具体方案；仍保存未知，
不能因此宣称所有数据满足契约、上游身份已经可信、全局兼容或生产安全。
仅未提供仓储、外层身份或拒绝异常的最终呈现，且当前方案不改变这些接口或来源、没有具体冲突证据时，
不得自动升级为关键阻断，也不要求用户再次批准同一修复。若可得代码显示真实冲突，先核对，再按事实分级。
A2 类局部例：用户已明确所有者和 member_ids 成员可读，can_read 已实现该规则，四文件调用链已读；
本次仅在 read_document 返回前复用 can_read，下载继续转交，成功返回结构不变。拒绝其他用户是预期安全限制，
已读路径中所有者和共享成员沿用同一规则；未提供的外部身份绑定、仓储和错误展示保留为范围限制。
不要假设存在旧数据缺字段或特殊服务角色来阻断，也不要假设这些外部情况已经全部排除。
UNDETERMINED 只用于当前方案范围内某项具体正常操作的结果无法判定、且缺失事实会改变实施决定，仍独立阻断。
新提交应为它提供 decision_basis，写明正常路径、缺失事实、决策依赖和最小核对步骤。范围限制只写 unknowns，
不能把同一个一般性外部未知再写成 UNDETERMINED，否则仍会阻断。已确认会损失合法共享权限则是
BUSINESS_BEHAVIOR_CHANGE，保留业务选择门槛，不能写成范围限制。
新能力可用时，unknowns 每项使用 classification 和非空 decision_basis（最多800字符）：
BLOCKING_CONTEXT 必须 critical=true 且至少引用一个本评估实际签发的 evidence_ref；
SCOPE_LIMITATION 必须 critical=false。未读必需代码、版本失效和材料缺失仍通过原覆盖/版本门槛阻断，
没有已读依据时保存 PARTIAL 和具体缺口，不虚构证据。未知分级是宿主分析，Runtime 只校验结构、引用与版本。
旧连接未声明该能力时不发送新字段；旧记录没有新字段时仍沿用原 critical 和 UNDETERMINED 门槛。
历史查询不改写、不降级旧阻断。修正分级须由原归属会话沿同一评估，根据实际证据重新提交，保留原风险、
修改前基线与既有授权；来源或材料过期时沿原恢复流程处理，不新建任务绕过。不能只删掉阻断字段来获得放行。


## 字段与调用示例

以下引用仅演示字段形状，必须替换为原记录和本评估读取返回的真实引用；SessionStart 已提供 session_ref 时，每次调用还须原样携带它及当前 workspace_path。只问影响时不调用 prepare_task_risk_fix／cancel_task_risk_fix；用户已明确修复时，先取评估引用并尽早登记 WAITING 意图，沿原评估读取／提交，再重试同一准备入口取得基线。PARTIAL 是保存未完成结果的替代分支。示例不独立授权修复，不表示示例项目已经核查。空 unknowns 只适用于实际没有剩余未知的范围。示例中的 classification／decision_basis 仅在当前实际连接声明 repair_impact_unknowns=repair-impact-unknowns-v1 时使用；旧连接不发送新字段，仍按原 critical 与门槛保存事实，不用省略或重命名未知来伪造通过。A2 的外部范围未知不同时登记为 UNDETERMINED；对照例的具体分支事实必须由实际读取证据支持，不能照抄到 A2。未读 PARTIAL 例尚无可引用材料时沿用 legacy critical=true，不虚构 evidence_ref。PARTIAL 或 WAITING 都不表示可编辑；只有准备返回 ready_for_host_fix=true 才进入原范围编辑。

### 准备原生风险的具体方案

```json
{
  "tool": "prepare_repair_impact",
  "arguments": {
    "source": {
      "kind": "HOST_TASK_RISK",
      "task_ref": "ts1-00000000000000000000000000000000",
      "finding_id": "tc1-11111111111111111111111111111111",
      "origin_review_revision": 1
    },
    "proposal": {
      "security_goal": "拒绝未获授权的文档读取与下载。",
      "summary": "读取入口复用所有者或共享成员的权限规则。",
      "changes": [
        {
          "file_path": "documents.py",
          "start_line": 1,
          "end_line": 3,
          "reason": "在返回内容前复用现有 can_read 权限检查。"
        }
      ],
      "preserve": [
        "所有者和共享成员读取及下载获准文档。"
      ]
    }
  }
}
```

### 用户已明确修复：尽早登记原生修复意图

```json
{
  "tool": "prepare_task_risk_fix",
  "arguments": {
    "task_ref": "ts1-00000000000000000000000000000000",
    "finding_id": "tc1-11111111111111111111111111111111",
    "origin_review_revision": 1,
    "impact_ref": "ria1-22222222222222222222222222222222",
    "user_requested": true
  }
}
```

### A2 局部方案：保存有限分析及非阻断范围未知

```json
{
  "tool": "submit_repair_impact",
  "arguments": {
    "assessment_ref": "ria1-22222222222222222222222222222222",
    "coverage": "REVIEWED",
    "impacts": [
      {
        "kind": "EXPECTED_SECURITY_RESTRICTION",
        "summary": "其他用户的读取与下载将被拒绝。",
        "evidence_refs": [
          "ri-evidence-33333333333333333333333333333333"
        ]
      },
      {
        "kind": "NO_ADDITIONAL_CHANGE_IDENTIFIED",
        "summary": "已读四文件的权限与下载调用链中，所有者和共享成员继续使用同一 can_read；参数、返回结构和下载委托关系不变。",
        "evidence_refs": [
          "ri-evidence-33333333333333333333333333333333"
        ]
      }
    ],
    "unknowns": [
      {
        "summary": "项目外仓储实现、上游身份来源和异常显示未提供，本次局部修复不改变这些边界；全局兼容性尚未证明。",
        "critical": false,
        "classification": "SCOPE_LIMITATION",
        "decision_basis": "当前方案仅复用既有 can_read；已查正常所有者和共享成员路径未发现额外变化，也没有合法记录缺字段的具体依据。外部实现缺失本身不改变这一局部方案，保留范围限制而不推断全局安全。",
        "evidence_refs": [
          "ri-evidence-33333333333333333333333333333333"
        ]
      }
    ]
  }
}
```

### 保存未完成分析

```json
{
  "tool": "submit_repair_impact",
  "arguments": {
    "assessment_ref": "ria1-22222222222222222222222222222222",
    "coverage": "PARTIAL",
    "impacts": [],
    "unknowns": [
      {
        "summary": "共享成员权限的必要调用路径尚未读完。",
        "critical": true,
        "evidence_refs": []
      }
    ]
  }
}
```

### 影响提交通过后重试同一原生准备

```json
{
  "tool": "prepare_task_risk_fix",
  "arguments": {
    "task_ref": "ts1-00000000000000000000000000000000",
    "finding_id": "tc1-11111111111111111111111111111111",
    "origin_review_revision": 1,
    "impact_ref": "ria1-22222222222222222222222222222222",
    "user_requested": true
  }
}
```

### 用户明确暂停原修复或切换开发

```json
{
  "tool": "cancel_task_risk_fix",
  "arguments": {
    "task_ref": "ts1-00000000000000000000000000000000",
    "finding_id": "tc1-11111111111111111111111111111111",
    "user_requested": true
  }
}
```

### 真实必要上下文阻断对照（替代提交，并非 A2 已知事实）

```json
{
  "tool": "submit_repair_impact",
  "arguments": {
    "assessment_ref": "ria1-22222222222222222222222222222222",
    "coverage": "REVIEWED",
    "impacts": [
      {
        "kind": "UNDETERMINED",
        "summary": "对照例已确认合法共享成员下载可使用精简文档投影，但尚不能确定当前调用所选分支，无法判定新增 can_read 是否会造成缺字段异常。",
        "decision_basis": "正常共享成员下载路径存在具体的精简投影分支；当前方案依赖该分支可能未提供的权限字段。必须先查明实际投影选择，才能决定复用当前方案还是补齐返回契约。",
        "evidence_refs": [
          "ri-evidence-33333333333333333333333333333333"
        ]
      }
    ],
    "unknowns": [
      {
        "summary": "当前合法下载调用选择完整权限字段还是精简投影尚未核对。",
        "critical": true,
        "classification": "BLOCKING_CONTEXT",
        "decision_basis": "具体正常路径是共享成员下载；缺少实际仓储投影选择。完整投影可继续既有 can_read，精简投影则须先调整数据契约或方案；下一步读取投影选择的调用与返回契约，未补齐前不编辑。",
        "evidence_refs": [
          "ri-evidence-33333333333333333333333333333333"
        ]
      }
    ]
  }
}
```
