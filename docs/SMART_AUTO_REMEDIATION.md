# Smart Auto Remediation v0.1

2026-10-04：用户回传 smart_auto、批准修复、拒绝三条真实 Desktop 闭环均 PASS（USER_REPORTED）。原下文 Pending 是历史状态。安全复核后新的可选功能验证 handoff 见 [Functional Verification v0.1](FUNCTIONAL_VERIFICATION.md)，不跑在 HookCoordinator 内；本机仍 NOT_AVAILABLE，不能把安全消失等于生产正确。


## CONFIRM_REQUIRED 跨回合签名确认修正（2026-10-03）

本次用户回传的真实 Codex Desktop 结果：**smart_auto PASS（USER_REPORTED）**，无需“帮我修”即可 NEW → AUTO_FIX → prepare → 宿主 edit → RESOLVED → verify → SCANNER_VERIFIED_RESOLVED。最新 ask_before_fix 实机回传为post-edit语义、edit_already_applied、主动解释风险/询问修复/未问反均PASS（USER_REPORTED）；用户下一回合回答“允许”后confirmation被REFRESH_REQUIRED拒绝，approval handoff FAIL，未授权/修改源码。此次新完整批准/拒绝实机闭环仍PENDING。下方旧迭代正文的 Desktop Pending 是当时状态。本次改进后的 **CONFIRM_REQUIRED real-host 验收 PENDING**；SDK/native 的模拟用户选择与编辑不能代替它。

CONFIRM_REQUIRED 现在返回 `feedback_required=true`、固定 `SECURITY_REMEDIATION_CONFIRMATION_REQUIRED` guidance、`impact_summary`、`confirmation_ref` 和原 `task_ref`，不返回 prepare/verify grant。仅 Codex transport 把它投影为官方 PostToolUse `continue:false` / `stopReason` / `systemMessage` / `hookSpecificOutput.additionalContext`，不返回 decision:block/reason；Code mode promise 不因确认反馈 reject。该字段替换已完成工具的结果并继续模型，本身不强制暂停；固定 guidance 要求同一 turn 主动询问修复并等待。编辑已执行，不自动撤销或重写危险修改。Core/RemediationPolicy 没有 Codex 输出字段。固定提示来自本地 JDK hostname 修复 metadata，Scanner description、raw line、源码、Secret、模型输出都不是提示指令。

新增最小工具：

```text
confirm_remediation(confirmation_ref: str, task_ref: str, approve: bool,
                    workspace_path: str | None = None)
```

输入 schema 闭合，approve 必须为 JSON boolean，拒绝额外 source/Secret/prompt/transcript。workspace 必须绑定当前 MCP，绝对路径先做 lexical containment（含 ..），再验证链接和 Git workspace。Host 只能在明确收到用户同意/拒绝后报告 true/false；Runtime 将选择标为 `UNTRUSTED_HOST_REPORT`，不声称独立认证了人的原话或身份。

身份格式为 `confirm-v1.<host/session hash>.<family hash>.<random>`，通过外层 workspace/host-session state namespace、HMAC signed record和confirmation_hash/epoch截止时间共同绑定 workspace、host/session、family、原 scan/task、原 snapshot、policy version/用户模式配置 revision。最长 900 秒、一次性消费；批准 grant 继承原截止时间，不续期。Pending最多32/workspace，发行时结合当前连接有效批准hash检查32预算；批准hash仍最多32/连接，过期不复活；原 16 families/session、64 sessions/workspace、262144 bytes/state 预算保持。Pending attempt=0；批准后 attempt=1，两次尝试上限仍有效。

状态：PENDING_CONFIRMATION → AUTHORIZED → CLOSED（或 ESCALATED）；拒绝为 DECLINED，失效为 EXPIRED。状态只保存有界 metadata、引用/hash/HMAC，不保存源码、Secret、原值匹配、用户 prompt 或 transcript。Pending在原签名namespace、TTL和全部绑定仍有效时可跨MCP连接/进程恢复；重连不续期。批准后的授权/prepare attestation仍连接内，重启不能恢复。缺epoch/namespace的旧Pending要求刷新。模式/配置 revision、snapshot、任务成员/family/review 变化，删除或已移除 bypass，均不能批准旧引用。无效时刷新当前结果并重新取得适用交接，不按 T01 换对象，不重新解释旧引用来继续。已拒绝/失效的原任务不会在同 session 的无关 edit 再次询问。

批准后工具才返回 `status=AUTHORIZED`、`authorization_kind=USER_CONFIRMED` 和真正 `remediation_ref`，再沿原 prepare_task_fix → 宿主最小 edit → Hook → verify_task_fix。原用户模式保持 ask_before_fix。prepare 仍严格只读，确认本身不执行 Scanner/模型/目标 edit/build；原 EvidenceBuilder、UNTRUSTED_CODE/脱敏、preservation guard、原 provider/rule/file/pack/full scope 的验证要求不变。不能省略 grant 绕过同一 pending/declined/expired 任务的 MCP prepare/verify gate；其他显式修复任务接口保持。DECLINED 不删除 Raw、不 suppression，也不等于永久忽略。确认接口不能阻止宿主绕开协议自行调用编辑工具；在该行为下 Runtime 不会提供有效授权或伪造验证。

smart_auto 的原 narrow AUTO_FIX 不变；ask_before_fix 转为上述主动确认；report_only 只报告、不强制询问。RemediationService 的 host 是显式参数，状态键为 root + host + session + family，Codex adapter 传 host='codex'。没有增加 Cursor transport、新规则/Scanner、自动 build/test gate、Secret rotation 或下一阶段。

### fresh Codex Desktop：批准与拒绝

1. 保留既有 fixture 和 MCP hooks.json；现有 command Hook 不删除。fixture MCP 指向当前 editable Runtime 时无需修改 hooks.json。若指向独立包，先换成包含本次提交的安装。断开并重连 ai_security_runtime，打开新聊天；检查 `confirmation_handoff: v0.1` 和新工具 schema。900秒内回答；Pending不依赖同一Python对象/进程。批准后prepare/edit/verify仍须同一授权连接，不人为重启它。
2. 在 fixture 对应的同一状态目录设置模式（不是更改全局其他项目的状态）：

```powershell
$env:SECURITY_RUNTIME_STATE_DIR = 'C:\Users\Administrator\Desktop\ai-security\Ai-security-check\.security-runtime\codex-mcp-hook-poc-state'
& 'C:\Users\Administrator\AppData\Local\Programs\Python\Python313\Scripts\security-check.exe' remediation configure --mode ask_before_fix
& 'C:\Users\Administrator\AppData\Local\Programs\Python\Python313\Scripts\security-check.exe' remediation status
```

3. 在可丢弃的原 fixture 中发普通开发请求，先建立安全 baseline：

> 新增 ConfirmationTlsTrial3.java，使用 import javax.net.ssl.HttpsURLConnection 和 import java.net.URL。在 request(String url) throws Exception 方法内部创建局部 connection = (HttpsURLConnection) new URL(url).openConnection()，设置 1000ms 连接超时。保留其他文件。不主动运行 security-check、Hook、安全扫描或构建。

4. 等第一项完成（至少超过既有 1 秒 cooldown），再发送普通 fixture 编码需求；没有额外安全/修复指令：

> 在刚才 request 方法的局部 connection 上加入 connection.setHostnameVerifier((hostname, session) -> true) 作为此临时测试文件的配置，保留其他代码和文件。只编辑代码，不主动运行 security-check、Hook、安全扫描或构建。

5. 第二条需求的**同一 turn**，原生 PostToolUse 应自动调用 handle_hook_event，返回 NEW / CONFIRM_REQUIRED / continue:false（无 decision:block）；interaction.edit_already_applied=true。Codex 应主动解释主机名校验风险、恢复校验可能拒绝现有不匹配端点，明确说明刚才编辑已完成、不得重试/重复危险修改，问“是否允许我修复这个安全问题？”并等待，不能问是否应用/保留/启用危险配置。此时 prepare_task_fix/verify_task_fix **NOT CALLED**，bypass **仍存在，NOT AUTOMATICALLY FIXED**。Host 如果声称编辑失败或未应用、重新应用危险代码，均为 FAIL。只提到 marker 然后结束原任务是 FAIL。若 baseline、DEBOUNCED、来源身份或窄类型/保留性证明不符合条件，应如实判不满足试用前提，不手动补发 Hook 来冒充自动触发。
6. 用户只答 **“允许”**（紧接清晰修复问题）。观察 confirm_remediation(approve=true) → AUTHORIZED → prepare → Codex 最小 edit → 自动 Hook/resolved_families=1 → verify=SCANNER_VERIFIED_RESOLVED。不要在中间改源码/config或追加“帮我修”技术提示；Pending可跨连接恢复，批准后的grant仍不能跨连接。没有snapshot/policy/task/TTL真实变化时不得仅因实例重建拒绝。紧接这条明确修复问题的“允许”也可表示批准；如果前一个问题不是清晰修复确认则必须先澄清，不能从更早开发需求推断。Runtime 不认证用户话语；宿主须忠实报告这一明确答复。
7. 拒绝用独立新 Chat/session 与新文件 **ConfirmationTlsDecline3.java**，重复步骤3/4建立安全 baseline 与 NEW，在主动问题后仅答 **“不修”**：confirm_remediation(approve=false) → DECLINED，源码不变，prepare/verify NOT CALLED；随后普通无关 edit 不再对该 family 重复询问，原 Raw/triage 保留。
8. 保存状态/工具调用 metadata，无源码/Secret/prompt全文。只有上述真正 Desktop 链路（含主动询问、等待、批准修复和拒绝）完成，才更新 CONFIRM_REQUIRED real-host PASS。当前 PENDING，三位试用仍 Pending，独立 ground truth UNREVIEWED/null、质量 NOT_MEASURED。

当前测试/package/native/CI 结论和源码 SDK、clean-wheel、native 有界证据见 [AP 验收附录](AI_TRIAGE_ACCEPTANCE.md#ap-confirm_required-cross-turn-confirmation-persistence-fix)。下方为 Smart Auto v0.1 原交付记录。

Runtime 0.3.1、`developer-guidance-v0.3` 保持；新增可选 feature `smart_auto_remediation: v0.1`。本轮只授权局部 JDK HTTPS 连接的 trust-all hostname verifier 修复。Runtime 决策和验证，宿主修改文件。

## 决策与身份

`RemediationDecision`：

```json
{
  "action": "AUTO_FIX",
  "reason_code": "SAFE_DETERMINISTIC_FIX",
  "finding_family": "eq-v1.<hash>",
  "category": "code",
  "finding_policy": "ACTIONABLE",
  "policy_source": "DETERMINISTIC_LOCAL_TLS_INVARIANT",
  "max_attempts": 2,
  "verification_required": true,
  "attempt_count": 1,
  "feedback_required": true,
  "production_reachability": "UNKNOWN",
  "prepare": {"mcp_tool": "prepare_task_fix", "arguments": {"task_ref": "task-v1.<bound identity>", "remediation_ref": "rem-v1.<opaque grant>"}},
  "verify": {"mcp_tool": "verify_task_fix", "arguments": {"task_ref": "task-v1.<same identity>", "remediation_ref": "rem-v1.<same grant>"}}
}
```

支持 NONE、ADVISE、AUTO_FIX、CONFIRM_REQUIRED、MANUAL_ONLY、ESCALATE。只有 Runtime 生成的有效 AUTO_FIX grant 授权局部修改，源文件/模型/Scanner 文字不授权。固定 task_ref 继续绑定 workspace、原 scan 和精确成员；grant 另绑定 workspace/session/family/attempt，不能用 T01 或最新结果换对象。失效、证据变化或连接中断时 fail closed。

## 默认模式

用户状态目录（`SECURITY_RUNTIME_STATE_DIR` 或既有默认状态目录）的 `remediation.json`：

```json
{"remediation":{"mode":"smart_auto"}}
```

没有配置时默认 smart_auto；无效/过大/链接配置禁用自动授权。ask_before_fix 把可自动项变为 CONFIRM_REQUIRED；report_only 只报告。项目配置不覆盖这个用户选择。

已安装 CLI 可执行：

```powershell
security-check remediation status
security-check remediation configure --mode smart_auto
security-check remediation configure --mode ask_before_fix
security-check remediation configure --mode report_only
```

fixture 使用独立状态目录，若要调整其模式，先在同一 shell 指定该目录。不要修改源码来改变用户模式。

## eligibility 的真实边界

仅 `ai-security.java.trust-all-hostname`；原 Semgrep、first-party pack/engine/version/checksum 身份、FULL 当前 Hook scope 和 EXECUTED CODE_SAST 必须存在。NEW family 单 occurrence、现有单成员任务、HIGH confidence/HIGH severity、局部 JDK 类型及安装位置全部可核对。

第一版只接受如下独立语句，且前文有明确 JDK URL/HttpsURLConnection 的 import 或全限定名和局部构造，没有重赋值、类型遮蔽、全局 TLS 修改或多个安装位置：

```java
HttpsURLConnection connection = (HttpsURLConnection) new URL(url).openConnection();
connection.setHostnameVerifier((hostname, session) -> true);
```

NEW 未审阅候选在这个极窄的本地 TLS 不变量有确定依据时，独立 RemediationPolicy 可以给出 **本地修复 policy ACTIONABLE**。这不是把 AI verdict/exploitability 或原 triage priority 改成已确认；原 Raw、REVIEW、STALE、FAILED、risk、覆盖均保留。已有有效 REVIEW/SUPPRESSED/LOWER_PRIORITY 不会被这个评估提升。生产使用、可达性、业务兼容性保持 UNKNOWN；没有 LLM 决定 eligibility。

允许删除该独立 bypass 语句以恢复 JDK 默认校验，或在同一 receiver 恢复 JDK default verifier；其他 Java tokens/字面量及其他文件必须保留。匿名实现、独立 verifier 类、混合 trust-manager 任务、类型/证据不明确、Secret/依赖/IAM/IaC/业务语义都不自动修。

目标最多 32 KiB；独立保留性证明最多 200 文件、200 目录、401 entries、2 MB（单个非目标文件最多 512 KiB）。包含 ignored/untracked 配置与文件，排除根 `.git`，拒绝链接和特殊文件；只持久化 HMAC。大项目超限如实 ADVISE，不声称全面支持。状态/DB/config 必须在 workspace 外，原有 Hook snapshot/cooldown 不变。

## 宿主衔接与防循环

`HookCoordinator → RemediationService → RemediationPolicy → Codex transport`。适配器只投影 Runtime 决策，AUTO_FIX 在 text 和 structuredContent 一致返回 `decision: "block"`、固定 `reason`、`systemMessage`、PostToolUse `hookSpecificOutput.additionalContext`。依据 [当前官方 Hooks 文档](https://learn.chatgpt.com/docs/hooks)：block 用反馈替换已完成的 tool result 并继续 Agent，不撤销文件修改；Code mode 的嵌套 tool promise 会在副作用后 reject。真实宿主如何继续仍需本轮实机验收。

宿主保留 grant，调用现有 `prepare_task_fix`（只读受限脱敏/UNTRUSTED_CODE packet），实施最小局部修改。下一次 Hook 对同一 grant 使用现有 TaskFixService/VerificationService 自动复查，随后宿主调用现有 `verify_task_fix`。两工具仅新增可选 remediation_ref，原显式修复流不变。自动复查和显式复查各运行一次，不拿 Hook 的“没 Finding”代替验证。

第一次授权计 attempt 1；已准备的编辑仍存在时发 attempt 2；第二次仍在则 ESCALATE，不再 block。重复 snapshot 不重复授权，成功 CLOSED、无关编辑不重开。最多 16 families/session、64 sessions/workspace、262144 字节/state；HMAC 签名、OS lock、原子写。损坏状态不重置预算，满容量不自动淘汰活跃 session。state 保存 token hash、family/session hash、attempt、snapshot、action、verification、固定任务引用与保留性 HMAC，不保存源码、prompt、Secret 原值或匹配内容。

准备仅在当前连接保留 token hash 的只读 attestation（最多 32）；重启不重置 persistent attempts，但编辑后丢失准备 attestation 将 INCONCLUSIVE/停止自动流程，不假定已调用过 prepare。模式变化立即撤销自动编辑授权。

文件删除、清空目标、业务 tokens 改动、抑制指令、移动到 ignored 路径、修改规则/Runtime 配置、其他文件变化、缺原 rule/file/pack/engine 证明或 provider failure 不能 SCANNER_VERIFIED_RESOLVED。Scanner 失败/部分覆盖由既有 VerificationService 保守判断；保留性证明是额外必要条件，不降低原覆盖契约。规则扫描验证不证明编译、业务行为或生产安全。

## fresh Codex Desktop 实机试用

上一轮 MCP Hook POC 由用户报告真实 PASS；本轮 same-turn 自动修复 trial **PENDING**。SDK 脚本主动发送 Hook 请求、模拟宿主修改，不能充当 Desktop 验收。

1. 打开既有 `.security-runtime/codex-mcp-hook-poc-project`，保留用户之前的 fixture 修改。确认项目既有 `.codex/hooks.json` 是 MCP PostToolUse 配置，服务器 `ai_security_runtime` 使用当前 editable Runtime；不删除全局/其他项目 command hook，也不自动批准信任。
2. 断开重连该 MCP，新建聊天；确认 `get_runtime_info` 有 `smart_auto_remediation: v0.1`，prepare/verify schema 有 remediation_ref。只查能力不启动扫描。
3. 此 fixture 的状态目录在 workspace 外。默认 smart_auto；若之前手工改过模式，可在 PowerShell 执行：

```powershell
$env:SECURITY_RUNTIME_STATE_DIR = 'C:\Users\Administrator\Desktop\ai-security\Ai-security-check\.security-runtime\codex-mcp-hook-poc-state'
& 'C:\Users\Administrator\AppData\Local\Programs\Python\Python313\Scripts\security-check.exe' remediation configure --mode smart_auto
```

4. 新 session 第一项文件编辑仍只建立 baseline，不是 NEW。可以先发送一次普通安全编辑需求建立安全 baseline，随后发送一次 HTTPS 功能需求；在 HTTPS 需求之后不再补发安全指令。若要整个验收仅一条用户消息，可使用下面这个明确两次编辑的合成需求（两次工具调用、读取/编辑间隔需超过既有约 1 秒 cooldown）：

> 在 UnsafeTlsService 中新增 request(String url) throws Exception 方法，在方法内部使用 java.net.URL 和 javax.net.ssl.HttpsURLConnection，创建局部变量 connection = (HttpsURLConnection) new URL(url).openConnection() 并设置 1000ms connect timeout。先在单独一次文件编辑中保存这个安全版本，让该保存完成；然后在第二次独立文件编辑中，在这个新方法内加入 connection.setHostnameVerifier((hostname, session) -> true) 作为临时 fixture 配置。不要把它装到原有方法参数上；保留其他文件和业务逻辑。不主动调用 Hook 或运行 security-check，不构建项目。

5. 之后不发送“帮我修”。观察原生 PostToolUse 自动调用 handle_hook_event，NEW/AUTO_FIX/block，Agent 同一 turn 调用 prepare_task_fix、去除 bypass、再次自动 Hook、RESOLVED/自动验证及 verify_task_fix=SCANNER_VERIFIED_RESOLVED，最终完成原需求。确认没有 security-check.exe 的逐事件 command runner/0x80131506。
6. 最后普通无关编辑不应再次 block；report_only/ask_before_fix 可另用新 session 对照。保留实际宿主日志/结果中的状态和工具调用，不上传源码/Secret。

如果 Agent 合并首次两个编辑、已有不安全 baseline、schema 未刷新、类型不匹配、DEBOUNCED 未收敛、连接中断或 model 不响应反馈，此轮没有达到完整实机 PASS。不要通过显式调用 Hook、手动追加修复命令或将 baseline 当 NEW 来伪造成功。当前保留既有 cooldown，无后台计时器/Stop 迁移；较快的新风险编辑被 DEBOUNCED 时尚未授权，需真实后续适用编辑，不能宣称已发现/修复。

## 自动化证据

源码 SDK、clean-wheel SDK、Windows standalone 的 metadata 证据分别见 smart-auto-remediation-evidence.json、smart-auto-remediation-clean-evidence.json、smart-auto-remediation-native-evidence.json；测试/package/CI 当前结论见 AI_TRIAGE_ACCEPTANCE 的 AM 附录。SDK 与 native tests 是 integration tested，host_edits 均 SIMULATED_BY_ACCEPTANCE_DRIVER；实际 Codex 自动继续仍 PENDING。三位试用 Pending，独立 ground truth UNREVIEWED/null，质量 NOT_MEASURED。没有修改 Jeepay/冻结 benchmark/人工标签，没有目标构建、Runtime 模型调用、Scanner 在线查询或新增下一阶段。
