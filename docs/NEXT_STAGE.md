# Next Stage — AI Triage Quality Validation & Developer Guidance

## Functional Verification v0.1（2026-10-04）

当前从干净 `feature/runtime-mvp` / `ca4a773def7e3c3deb019c0c309994ebd06a6971` 继续。本轮用户明确回传真实 Desktop 的 **smart_auto、CONFIRM_REQUIRED 批准→修复→verify、拒绝→DECLINED 三条完整链路均 PASS（USER_REPORTED）**。下方 AP/AO/AN 的失败和 Pending 是历史时点；不重新开发已通过能力。新功能验证的 fresh Desktop handoff 仍 PENDING。

独立 FunctionalVerificationService/四个 verifier/连接内 deterministic plan/两个可选 MCP 工具已实现，原 HookCoordinator 不跑长测试。仅 Runtime 已授权修复且原 HMAC record 的 CLOSED/SCANNER_VERIFIED_RESOLVED、原 task/member、grant/TTL/policy/source guard/snapshot 全部成立后可运行。安全状态与功能状态、生产正确性分开；失败 REVIEW_REQUIRED，不恢复危险代码、不自动修失败测试、不重试循环，不改变 smart_auto eligibility 或原 coverage contract。

**当前验收仍不完整：** Windows/macOS 缺强制隔离 backend 返回 NOT_AVAILABLE；Linux bubblewrap+cgroup backend 已实现但真实执行验收 PENDING。本机无 Maven/Gradle/bubblewrap/Docker，WSL 只返回安装帮助，未发现可用 Linux 入口；未安装或下载补齐。真实 SDK/clean/native 可证明安全修复与功能门禁/NOT_AVAILABLE 契约，不证明 Maven 编译测试 PASS。模拟 executor 的成功/失败不替代真实 Maven A/B。实现/测试/交付最新结果见 [AQ](AI_TRIAGE_ACCEPTANCE.md#aq-functional-verification-v01)，边界与可执行试用命令见 [Functional Verification](FUNCTIONAL_VERIFICATION.md)。

本地 targeted241 + 最终修正focused67通过；最终full **791 passed /6 skipped /6 subtests passed，581.35s**。wheel/sdist/六模块字节校验/package/compliance/严格离线clean/Windows native均PASS（native/SDK只证明安全与门禁，功能execution仍NOT_AVAILABLE）。真实Maven A/B及Desktop/host功能验收 **PENDING_ENVIRONMENT_PREREQUISITES**，按用户明确要求不搭建或下载环境。新CI推送后核实，未预写通过。

本轮 implementation `c9e99d7eb3f5a98248cedb68126e557397aed694` 已推送。实际 Runtime/Package/Compliance/Standalone 新CI全部账户付款/支出条件阻止启动，9 jobs 无Runner/steps，**PENDING_RERUN_AFTER_ACCOUNT_RECOVERY**；新run见AQ.5，四平台未执行，不能写PASS。final docs HEAD按本文件git log核对，docs-only新CI在最终回复单列。

### 本轮 Agent Handoff

先读 AQ 和 FUNCTIONAL_VERIFICATION，核对 Git/证据，保留原三条 Desktop USER_REPORTED PASS。不要把新功能未实测写成 PASSED，不直接运行项目命令绕过隔离或仅凭 offline flags 声称禁网。缓存绑定所有文件 keyed snapshot、配置/scripts/manager/固定 argv/executable hash/provider/version、原 grant 和隔离 version；相同计划复用，变化刷新。baseline UNKNOWN，不接受 Host baseline 断言。Raw/coverage/风险策略、UNTRUSTED_CODE、脱敏、command/MCP Hook 及授权修复仍保持。

Enterprise Enforcement/CI Gate、其它 Host、新 AUTO_FIX 类型、自动失败测试修复、Joern/DAST/Deep Audit/watcher/依赖安装/Secret rotation 等继续 Planned。三位真实试用 Pending；独立 Ground Truth UNREVIEWED/null，质量 NOT_MEASURED。仅操作可丢弃 fixture，未改 Jeepay、用户实际 Desktop fixture、冻结 benchmark 或人工标签。本阶段完成已授权交付后停止，Pending 如实保留。

以下章节是各阶段历史记录，最新状态以上文及 AQ 为准。


## CONFIRM_REQUIRED Cross-Turn Confirmation Persistence Fix（2026-10-03）

本轮实现 `a88c84071d823cd784ca39569bacadef03c067dd` 已推送；targeted172、补充focused6及final full **724 passed /6 skipped /6 subtests passed，615.42s**，wheel/sdist/逐字节校验/package/compliance/strict clean/实际SDK和Windows native均PASS，后两者包含真实MCP进程A→B→C重启验收。本轮四类CI全部GitHub failure但9个jobs未启动，账户付款/限额原因，**PENDING_RERUN_AFTER_ACCOUNT_RECOVERY**。具体新run见AP.5；实际Desktop新批准/拒绝PENDING，旧提问语义USER_REPORTED PASS独立保留。

起点为干净 `feature/runtime-mvp` / `1a92dff6d86dc688f5b0a4fbecb56da109a8c4f7`。最新用户真实Desktop回传：post-edit语义、edit_already_applied、主动解释风险、主动询问修复、未问成应用危险代码均 **PASS（USER_REPORTED）**；随后明确回答“允许”，confirmation返回REFRESH_REQUIRED、未授权/未修复，**approval handoff FAIL**。原smart_auto真实PASS保留。下方AO/AN的旧Pending与失败是历史时点，不能覆盖本次反馈。本次修复后的新完整Desktop批准与拒绝均 **PENDING**。

代码确定存在的缺陷是已签名落盘的Pending仍依赖发行实例的self.confirmations与monotonic deadline；新服务实例丢失字典即可否定有效Pending。真实Host的旧通用错误未提供底层诊断，不能推测Codex对象/进程生命周期或断言每次REJECT都是内存缺失。此次只移除这项错误的Runtime契约，并增加安全枚举诊断；没有cold-start修复或Host生命周期假设。

Pending权威改为现有HMAC state：只持久化confirmation_hash、issued/expires epoch、workspace_id、host/session hash与namespace、family_key、固定task_ref/origin_scan、snapshot、policy/mode/config revision binding、source/preservation HMAC等有界metadata。高熵opaque确认token本身不落盘，无源码、Secret、prompt/transcript或Scanner原始文字。引用携带原namespace，工作区限定在当前MCP绑定；这是原host/session-bound bearer capability，不独立认证当前调用者或人类答复，approval_trust仍UNTRUSTED_HOST_REPORT。

固定deadline由Runtime time.time()发行，expires-issued=900秒并纳入HMAC。now必须在[issued,expires)且有效期<=900；非有限/错误类型/缺字段/时钟回退到issued之前拒绝。调用confirm、重连或重复Hook不续期。墙钟依赖本机OS时间，不能声称独立可信时钟或检测发行后所有小幅回拨；批准grant另保留原monotonic剩余期限和epoch检查，仍connection-local，不因重启恢复授权。旧格式缺持久化TTL/namespace的Pending要求刷新，不自动迁移或重发。

确认在原workspace OS锁内重读并验证HMAC/ref hash、phase、namespace、TTL、当前snapshot、policy/config revision、原scan/task/member/rule/family、source与preservation proof；读取成员后再复核这些条件。批准只消费一次成为AUTHORIZED，拒绝DECLINED；重启后重放仍ALREADY_CONSUMED。失效EXPIRED，需刷新。Signed Pending允许A发行→A退出→同state的B确认；已批准grant及prepare attestation仍限当前连接，B退出后C不能prepare。Pending最多32/workspace；发行时结合本连接有效授权hash检查32预算，授权hash仍最多32/连接，16families/session、64sessions/workspace、262144bytes/state与原Raw/coverage/风险策略保持。

新增安全diagnostic_reason枚举区分STATE_NOT_FOUND、REFERENCE_INVALID/MISMATCH、NAMESPACE_MISMATCH、EXPIRED、SNAPSHOT_CHANGED、POLICY_CHANGED、TASK_CHANGED、SOURCE_GUARD_CHANGED、STATE_INVALID。用户仍收到通用refresh reason，不回显path/token/source/Secret/exception字符串。AUTO_FIX与Codex输出未改；CONFIRM_REQUIRED仍continue:false及固定post-edit修复问题，command Hook保留。

实际门禁/测试/包/native与本轮新CI见 [AP验收](AI_TRIAGE_ACCEPTANCE.md#ap-confirm_required-cross-turn-confirmation-persistence-fix)。实现HEAD按 `git log -1 --format=%H -- src/security_runtime/remediation.py` 核对，最终docs HEAD按PROJECT_STATE的git log核对。fresh Chat采用ConfirmationTlsTrial3.java，主动询问后用户只“允许”；独立拒绝Chat采用ConfirmationTlsDecline3.java，只“不修”。必须真实跨用户回合授权→修复→验证才可把批准闭环改为PASS，SDK/native不能替代。

没有新Scanner/规则/政策、Functional Verification、Cursor、Hook v0.2、自动build、依赖升级、Secret rotation、Deep Audit/Joern/watcher。Runtime不模型、不编辑/构建目标；新Scanner验收强制离线，公共包/GitHub授权交付可联网，无源码/Secret上传Scanner/模型。用户fixture/Jeepay/冻结benchmark/人工标签未修改；三位试用Pending，Ground Truth UNREVIEWED/null，质量NOT_MEASURED。完成本轮交付后停止，后续范围Planned。

### 本轮 Agent Handoff

从AP的实际测试/CI恢复；Pending可跨进程不代表任意workspace/替换task或猜测用户同意。旧连接内confirmed grant不能恢复。保留上述最新USER_REPORTED语义PASS/旧approval FAIL，与本次新闭环PENDING分开；不要再次退回block确认输出，不推进下一阶段。


## CONFIRM_REQUIRED PostToolUse Host Semantics Fix（2026-10-03）

本轮实现 `158a85db8aeb553f58926188aad112fe332cd45c` 已推送；final full offline **692 passed /6 skipped /6 subtests passed，490.59s**，targeted 210 passed；wheel/sdist、逐字节包校验、compliance、strict clean wheel、实际SDK和本地Windows native均PASS。本轮四类新CI全部GitHub failure但9个jobs未启动，实际注解为付款失败或支出限额，**CI BLOCKED / PENDING_RERUN_AFTER_ACCOUNT_RECOVERY**；四平台Standalone未在本轮CI执行，不写PASS。实际新run及jobs见AO.4，账号设置/验收门槛未修改。final docs HEAD按git log核对，docs-only新CI在最终回复按实际状态单列。

本轮从干净 `feature/runtime-mvp` / `9d2dbd539ce2ed3753bfd0420b9507aa20ae2ade` 继续，仅修复确认的 post-edit 语义。用户真实 Desktop 回传：CONFIRM_REQUIRED policy、identity/TTL **PASS（USER_REPORTED）**；主动交互 **PARTIAL**；问题语义 **FAIL**（问成批准应用危险配置）；approve→repair 与 decline **NOT VALIDATED**。smart_auto 的完整 Desktop 链路 **PASS（USER_REPORTED）** 保留。修正后新的确认 Desktop 批准/拒绝均 **PENDING**，不能由 SDK/native 的模拟选择与编辑替代。

已重新搜索并实际读取 [当前官方 Hooks contract](https://learn.chatgpt.com/docs/hooks)：PostToolUse 副作用已完成，block 在 Code mode 会 reject 工具 promise；continue:false 用反馈替换结果并继续模型，但不 reject promise。因此仅 CONFIRM_REQUIRED transport 改为 `continue:false` + 固定 `stopReason`/`systemMessage`/`additionalContext`，不返回 decision:block/reason。它不是强制停止模型；主动提问并等待仍依赖宿主遵循固定 guidance，必须真实验收。AUTO_FIX 的原 block/reason 不改，也不删除 command Hook。

Core 只增加 host-neutral `interaction` metadata：POST_EDIT_REMEDIATION_CONFIRMATION、edit_already_applied=true、requested_user_decision=REMEDIATE_SECURITY_FINDING、must_not_retry_previous_edit=true。固定 guidance 明示“编辑 ALREADY executed；不得 retry/re-apply/repeat，不自动 revert；只问是否修复风险，不问应用/保留/启用危险配置”，解释 hostname 风险、恢复 JDK 默认校验的请求行为变化及 ask_before_fix 的批准原因。主动问“是否允许我修复这个安全问题？”，然后等待；批准前无 grant、无 prepare/verify/目标修改。仅在紧接清晰修复问题时，单独“允许”才能算批准，否则先澄清。

沿现有 confirm_remediation：明确批准 → AUTHORIZED/remediation_ref → prepare → 宿主最小 edit → 自动 Hook/RESOLVED → verify=SCANNER_VERIFIED_RESOLVED，不再要求第二条“帮我修”。拒绝 → DECLINED，不 prepare/verify/edit/suppression/删除 Raw，同 session 无关 edit 不再询问。opaque identity、900秒 TTL、一次性 grant、workspace/scan/task/member/session/snapshot/policy revision、预算、保留性证明和原覆盖/风险/脱敏/UNTRUSTED_CODE 契约不改；Core 无 Codex 输出字段，Runtime 不解析/保存用户原话。

本轮实际测试、打包、clean install、Windows native 与新 CI 结论见 [AO 验收](AI_TRIAGE_ACCEPTANCE.md#ao-confirm_required-posttooluse-host-semantics-fix)。最新实现 HEAD 按 `git log -1 --format=%H -- src/security_runtime/codex_mcp_hook.py` 核对，最终 docs HEAD 按 `git log -1 --format=%H -- docs/PROJECT_STATE.md` 核对。下方 AN/旧阶段为各自时点历史，不代表本轮通过。fresh Desktop 用 ConfirmationTlsTrial2.java 与 ConfirmationTlsDecline2.java，见 [试用步骤](SMART_AUTO_REMEDIATION.md#fresh-codex-desktop批准与拒绝)。

三位试用 Pending；独立 Ground Truth UNREVIEWED/null、质量 NOT_MEASURED。无新 Scanner/规则/政策、Functional Verification、Cursor、Hook v0.2、cold-start repair、自动 build、自动依赖升级、Secret rotation、Deep Audit/Joern/watchers；这些继续 Planned。本轮 Scanner 强制离线；Runtime 不调用模型、不修改目标源码或构建，SDK/native 驱动的编辑是可丢弃合成项目，不改 Jeepay/用户 fixture/冻结 benchmark/人工标签。公共包获取和授权 GitHub 推送/CI 可联网，不上传项目源码或 Secret 给 Scanner/模型。完成交付后停止。

### 本轮 Agent Handoff

保留当前分支及工作区，从 AO 的实际门禁和提交恢复；不要把 continue:false 等同硬性暂停模型，也不要把模拟宿主编辑写成真实 Desktop。新的批准和拒绝实机链路都通过才可更新 CONFIRM_REQUIRED 整体 PASS。AUTO_FIX 实机 PASS 独立记账，后续阶段不得自动推进。


最终文档提交 eaafecc9c595b924940d272249a7ac7a08b26909 的Runtime/Package/Compliance实际failure，GitHub检查注解明确为付款失败或支出限额，未分配Runner、未执行步骤；文档CI验收 PENDING_RERUN_AFTER_ACCOUNT_RECOVERY。修正implementation 73c0945 的四类/四平台实际success不变，不把文档CI外部阻塞写为PASS。账号付款/支出设置未修改；恢复后重跑，无源码/coverage降级或workflow绕过。

本轮 implementation HEAD `73c0945c934fe82fef7323db9e10bfe938e3fc74` 已推送 origin/feature/runtime-mvp，Runtime tests（Linux/Windows）、Package integrity（Linux/Windows）、Compliance、Standalone artifacts（Windows/Linux/macOS arm64/x64）全部实际 success；具体新 run 见 AN.2。最终 docs HEAD 用 git log -1 --format=%H -- docs/PROJECT_STATE.md 获取。

初次实现 `c21ccd80c405f34aa84e63e54645d8c2df7c9abd` 已推送，其Runtime/Package/Compliance通过；首轮Standalone的两个macOS任务实际失败（Windows/Linux通过）。已定位并修正无confirmation目录时的legacy gate链接边界，真实symlink回归通过；新的修正提交/四类CI最终结论在AN.2记录，不能把首轮Standalone写成通过。

## CONFIRM_REQUIRED Host Interaction v0.1 — 当前交接（2026-10-03）

从干净 `feature/runtime-mvp` / `5965497e3a687dbe67fb3e86d367dfdc0059052a` 继续，仅修复已暴露的确认反馈/授权链路。用户已报告真实 **smart_auto Desktop PASS（USER_REPORTED）**；原 **ask_before_fix Policy decision PASS / Host confirmation UX FAIL**。本次新的 **CONFIRM_REQUIRED real-host PENDING**，不得把 SDK/native 的模拟用户选择与宿主编辑写成 Desktop PASS。下方旧迭代 Pending 保留其当时语义，由本节记录新的真实回传。

CONFIRM_REQUIRED 产生 feedback_required=true 和独立固定 guidance，Codex 薄 transport 按今日重新核对的 [官方 Hooks contract](https://learn.chatgpt.com/docs/hooks) 返回 PostToolUse block/reason/additionalContext：在当前 turn 解释风险与可能行为变化、主动询问并等待，不撤销已完成 edit。只用 Runtime 固定结构化 metadata，不将 Scanner prose/源码/Secret 当指令。批准前无 remediation_ref；同一 pending 任务的 MCP prepare/verify 也不能省略 grant 绕过。

新增闭合 `confirm_remediation(confirmation_ref, task_ref, approve: bool, workspace_path=None)`；宿主只报告明确用户答复，标记 UNTRUSTED_HOST_REPORT，Runtime 不冒充独立认证人类同意。一次性 opaque 引用绑定 workspace/host/session/family/固定 task/原 scan/snapshot/policy revision，900 秒内有效；批准 grant 继承截止时间。连接重启、snapshot/成员/family/review/mode/config revision 变化失效，不按 T01 换对象。PENDING_CONFIRMATION → AUTHORIZED → CLOSED/ESCALATED；拒绝 DECLINED，失效 EXPIRED。拒绝保留 Raw/triage，不 suppression，同 session 无关 edit 不重复询问。metadata/HMAC 预算保持，待确认+批准 hash 最多32/连接，无源代码、Secret、prompt/transcript持久化。

沿原 TaskFixService/EvidenceBuilder/VerificationService prepare → 宿主最小 edit → Hook → verify；narrow TLS allowlist、Raw/risk/coverage、脱敏/UNTRUSTED_CODE、preservation proof、两次尝试、snapshot/cooldown/single-flight/family multiset 不变。Core host 参数显式化，Codex adapter 传 host='codex'；没有 Cursor 接入、command Hook 删除、新 Scanner/规则、自动 build/test gate 或下一阶段。

已交付 baseline **651 passed /6 skipped /6 subtests**；新增37项；原针对性 **137 passed**、CI修正后确认测试 **37 passed**；本轮 final full offline **688 passed /6 skipped /6 subtests passed，355.00秒**。六项真实多引擎 PATH e2e skipped 单列，未算通过。wheel/sdist/module bytes/package integrity/licenses/notices、严格 clean venv（无 editable/system site）、实际本地 SDK/Windows native 的批准/拒绝/report_only/原 AUTO 链路通过。Scanner 真实离线执行，用户选择/宿主 edit 是 SIMULATED_BY_ACCEPTANCE_DRIVER；新 Desktop 门禁仍 PENDING。本轮四类实际新CI全部success，见AN.2；Standalone四平台均运行本次确认/拒绝/原AUTO/report_only离线MCP验收，不代表Desktop实机UX。

包0.3.1、developer-guidance-v0.3 保持，新增 optional confirmation_handoff v0.1；实际 schema/模式与 fresh Desktop 步骤见 [Smart Auto 文档](SMART_AUTO_REMEDIATION.md#fresh-codex-desktop批准与拒绝)，当前验收与有界证据见 [AN 附录](AI_TRIAGE_ACCEPTANCE.md#an-confirm_required-host-interaction-v01) 和 [acceptance metadata](confirmation-acceptance.json)。不修改 Jeepay、原 fixture 用户编辑、冻结 benchmark、人工标签。本轮确认/修复流程的Scanner网络、Runtime模型、目标build及Secret rotation未执行；公共包及授权GitHub分发/CI可联网，既有Standalone门禁可获取公开引擎/漏洞库用于合成fixture，不上传项目源码/Secret给Scanner/模型。三位试用Pending，独立 Ground Truth UNREVIEWED/null，质量NOT_MEASURED；后续 Deep Audit/Joern/watcher/MCP-Skill Security/自动依赖升级继续 Planned。提交推送、核实本轮实际 CI 后停止。

### 本轮停止条件

仅完成 CONFIRM_REQUIRED Host Interaction v0.1 的源码/测试/分发/实际CI；新的同-turn询问/批准/拒绝 Desktop 门禁保持 PENDING，不能因宿主 Pending 启动新阶段。三位真实试用无法安排的状态保留；独立人工质量门禁不由自动化替代。Deep Audit/Joern/watcher/Functional Build-Test Gate/Cursor 接入及其他新阶段未开始，继续 Planned。


## Smart Auto Remediation v0.1 — 当前交接（2026-10-03）

本轮 implementation HEAD `462633e8b5d4dcc730dba868bd9ac66e8bc40b37` 已推送，Runtime tests、Package integrity、Compliance、Standalone artifacts 四类实际新CI全 success；后者四平台均执行新增离线自动修复 MCP 验收（宿主编辑仍模拟，Desktop trial Pending），具体链接见 AM.1。最终 docs HEAD 用 git log -1 --format=%H -- docs/PROJECT_STATE.md 核对。

本轮从 `feature/runtime-mvp` / `3d6611d7e94d80e9804ee526c6d35b809ca69c20`、干净工作区继续；现有 Hook/command/MCP 实现保留。上一轮 Codex Desktop MCP Hook POC 的自动触发、baseline/NEW/PERSISTING/multiset/RESOLVED 由用户在本轮明确报告真实 PASS，来源 **USER_REPORTED**；下方历史 POC Pending 是当时状态，不覆盖这项新反馈。本轮 **same-turn Smart Auto Remediation Desktop trial 仍 PENDING**，不得把 SDK 模拟宿主编辑当成新宿主 PASS。

独立 RemediationPolicy/Service 仅 allowlist `ai-security.java.trust-all-hostname` 的明确局部 JDK HTTPS inline installation。Runtime 发 AUTO_FIX grant，宿主沿现有 prepare_task_fix → edit → 自动 Hook/VerificationService → verify_task_fix；Runtime 不编辑源码、不调用宿主模型。用户级 smart_auto 默认，ask_before_fix/report_only 可选；两次尝试上限、HMAC/OS lock/有界 metadata、原 task_ref 和额外 grant 绑定、保留性证明防删除/抑制/移动/配置规避。已有 REVIEW/STALE/FAILED 与 Raw/risk/coverage 不提升或改写，本地 TLS 不变量的独立 ACTIONABLE repair policy 不证明生产可达性。

最终源码离线回归 **651 passed / 6 skipped / 6 subtests passed，260.36 秒**（新测试50项）；旧阶段已交付 baseline 601/6/6。六项 skipped 单列为 tests/test_e2e_real.py 的三引擎 PATH 前提，未计为通过。实际 SDK、严格 clean-wheel venv、Windows native MCP/离线 Semgrep/Gitleaks 修复验证通过；模拟宿主编辑、原引擎子进程实际执行。wheel/sdist/package integrity/licenses/notices 通过。本轮四类新 CI 需以 AM 的具体 run/结论为准，不能引用历史 CI 为当前通过。

包版本0.3.1、developer-guidance-v0.3 保持，新增 optional smart_auto_remediation v0.1。说明、真实 schema、模式命令、预算/连接中断/cooldown 限制、实机步骤见 [Smart Auto 文档](SMART_AUTO_REMEDIATION.md) 和 [AM 验收](AI_TRIAGE_ACCEPTANCE.md#am-smart-auto-remediation-v01)。现有 fixture 用户改动未覆盖；command hook 保留，不迁移 SessionStart/Stop 或其他 Host。

后续 Deep Audit、watcher/daemon、MCP/Skill Security、Joern、自动构建、自动依赖升级、Secret rotation、业务/IAM/IaC 自动修改未开始，继续 Planned。三位试用 Pending；独立 ground truth UNREVIEWED/null，质量 NOT_MEASURED；Jeepay、冻结 benchmark、人工标签原状。完成本轮提交/推送/验收记录后停止，不开始下一阶段。

### 本轮停止条件与仍待验收

Smart Auto v0.1 单场景 Runtime 实现/自动化交付，**产品同 turn 宿主体验 Pending**。只提交推送当前范围并记录真实 CI；不以宿主 Pending 启动下一阶段。后续阶段保持 Planned；三位开发者无法安排的真实状态保留。当前授权局部 AUTO_FIX 是本轮新指令；下方旧阶段“自动修复未授权/未开始”属于历史交接。


## 当前transport POC边界（2026-10-03）

Codex MCP Tool Hook POC仅实现PostToolUse/FILE_CHANGED薄适配与独立配置生成，复用原HookCoordinator；原command hook保持。真实SDK stdio/Scanner验收通过，fresh Codex Desktop自动触发及advisory消费Pending，见[AL](AI_TRIAGE_ACCEPTANCE.md#al-codex-mcp-tool-hook-poc)。完成本轮测试、文档和commit后停止；不因POC自动开始SessionStart/Stop迁移、自动修复/构建、Deep Audit、Joern、watcher、新scanner/policy或Host重构。

用户仍无法安排三位独立试用者，保留Pending；独立ground truth UNREVIEWED/null，质量NOT_MEASURED。以下既有规划状态不由transport协议测试改变。

## Host-agnostic Hook Integration v0.1 — 当前交接（2026-10-03）

本轮从干净且 ff-only 同步的 `feature/runtime-mvp` / `8a36b3884a7d25cfb7f75c3405df727909ed1c90` 开始，用户明确授权 Hook 实现；前置 Fix & Verify / eq-v1 已交付。HookCoordinator、本地快照/锁/冷却、多重集变化、中立 CLI、Codex 和 Cursor 适配已实现。本轮新的完整自动化、包和原生/CI 门禁以 AK 附录为准，后文“Hook 未开始”是旧阶段历史状态，不能作为当前结论。初次实现 `40d9905b1ddb8fbac93fd2a31ba2f3075f3cb6bd` 与跨平台验收修正后的实现 `c1d42552d63596790bfba6eaadf206bffae754f2` 已推送；最终576项离线回归、wheel/sdist、完全隔离clean venv、合规、本地Windows native和本轮四类新CI全部通过，详见AK.1/AK.2。文档最终HEAD用 `git log -1 --format=%H -- docs/PROJECT_STATE.md` 获取。

Hook 仅触发现有本地 quick SAST/Secret 检查，ADVISORY；MCP 继续负责核查/修复交接，Git pre-commit 保留 quick --staged 的原边界。没有 Runtime 调用模型、网络依赖解析、自动补丁、目标构建、后台 watcher/daemon、新 scanner/规则、Joern 或 Deep Audit。三位试用 Pending，独立人工 ground truth UNREVIEWED/null、质量 NOT_MEASURED；Jeepay 源码、冻结 benchmark、人工标签保持原状。

Codex/Cursor 的官方 schema 已核实，项目配置/适配与实际生成命令测试通过；**fresh Codex/Cursor host trial 仍 PENDING**，不得把 CLI/合成 fixture 当成宿主真实自动触发。WorkBuddy（桌面）/Kiro/Qoder 为 MANUAL_CONFIGURATION_REQUIRED，提供中立命令，不从 CodeBuddy CLI 或其他产品推测其 schema。详见 [AK 验收与试用步骤](AI_TRIAGE_ACCEPTANCE.md#ak-host-agnostic-hook-integration-v01)。

## 历史交接：Developer Fix & Verify v0.1（2026-10-02）

起始干净、ff-only 同步 HEAD `0f33d2624204794c84da6fa10cf43b8178cd5a56`，分支 feature/runtime-mvp。本轮明确授权 A→B，先完成 A 回归再实施 B。Stable Finding Equivalence 与任务修复/验证 v0.1 已实现；整体宿主产品 UX 尚待真实验收。Hook Integration 未开始，完成本轮推送后停止。

保留旧 occurrence ID/fingerprint 与历史 Raw/triage/task_ref；eq-v1 无行号，区分原 rule/provider/file，Dependency 复用稳定包/advisory身份，Secret 不含原值/匹配行/凭据摘要。旧 verify 只有完整原规则/文件复查证明缺席时才 RESOLVED + SCANNER_VERIFIED_RESOLVED，行号移动仍 STILL_PRESENT，缺文件/规则/引擎或 scope 无证明为 INCONCLUSIVE。

MCP 当前13工具，新增 prepare_task_fix（严格只读约束/受限证据交接）、verify_task_fix（本地 scanner/cache/temp 副作用，非 destructive）；能力契约 developer-guidance-v0.3，required subset。固定 task_ref 绑定 workspace/scan/精确成员，变化刷新，新 scan 不换对象。宿主响应明确“修复它/修第一项”后编辑选定本地代码并调用复查；Agent fixes. Runtime verifies。组内全部修复/全部仍在/混合为 SCANNER_VERIFIED_RESOLVED/STILL_PRESENT/PARTIALLY_RESOLVED，任一未知整体 INCONCLUSIVE，完全未复查 NOT_VERIFIED。

复查最多100成员/20原受影响文件/2MB，同 provider/file 复用，默认离线不下载或自动fallback，不构建/编辑目标、不调用模型。prepare 沿用 EvidenceBuilder 的20项/32KiB/120行/5相关文件预算，原 triage session/hash/evidence_refs 防护不变。宿主 patch/build/tests 声明为 UNTRUSTED_HOST_REPORT，不能改变 Runtime 观察或结论。Gitleaks/IaC 未提供原 detector/check 执行清单时缺席保守 INCONCLUSIVE；POM PARTIAL 不能证明完整图修复。

完整离线508 passed / 6 skipped / 6 subtests passed（120.12秒）。真实 Semgrep 1.178.0 合成100→110行仍存在、安全替换、分组只修一项及实际子进程失败均符合预期；包/合规/wheel/sdist 与本地全新 Runtime venv 安装通过（复用本地 SDK 依赖，无公网）。Windows native/实际 SDK及四平台新 CI 门禁均通过（实现 HEAD `1e10b53`），见 [AJ 验收](AI_TRIAGE_ACCEPTANCE.md) 和 [合成证据](fix-verify-synthetic-evidence.json)；结构/边界详见 [当前架构](ARCHITECTURE.md)。

没有修改 Jeepay、旧 scan/benchmark、ground truth、risk/coverage/policy；没有 scanner 公网查询、外部模型、目标构建或生产变更。三位真实开发者试用、真实宿主普通意图连续 UX 仍 Pending，独立人工 ground truth UNREVIEWED/null、质量指标 NOT_MEASURED。Hook 当前 Planned / NOT_STARTED，旧 PREREQUISITE_MISSING 留作历史门禁记录。


更新：2026-10-02。路线规划基线 `7e19744`；本轮继续核查起始 `feature/runtime-mvp` / `50a01e6870d78e6fd8a96a8b8fbe236521c5306f`；既有 Triage 实现 `5570520`、验收快照 `3d773aa`。**入口、继续核查及第三轮 Developer Fix & Verify v0.1 已获授权实现；本轮不实施 Hook、独立人工质量工作、模型实验或 Joern。**

下一阶段为 **AI Triage Quality Validation & Developer Guidance**。三次产品迭代的 Runtime接口与宿主指导已实现、自动化/分发及新 CI 通过；真实宿主连续 UX 与三位开发者试用 Pending，整体质量 milestone 未完成。继续核查已实现、源码/wheel/SDK 验收通过；修复与验证 v0.1 已实现，实际宿主 UX Pending；独立人工 Ground Truth 仍是质量工作的核心。

先读 [PROJECT_STATE](PROJECT_STATE.md)、[ARCHITECTURE](ARCHITECTURE.md)、[DECISIONS](DECISIONS.md) 和 [AI_TRIAGE_ACCEPTANCE](AI_TRIAGE_ACCEPTANCE.md)。

## 为什么同时验证质量与使用效果

已提交的 Jeepay 历史回放有 115 Raw、26 triaged，2 ACTIONABLE / 23 REVIEW / 1 LOWER_PRIORITY / 0 SUPPRESSED / 89 UNTRIAGED。独立人工标签文件仍全部 UNREVIEWED/null。现有 `scripts/jeepay_triage_benchmark.py` 通过 `host_analysis` 回放 Coding Agent 审阅 artifact，验证实际 MCP handoff、policy、cache 与 Raw 保留；不是实时调用不同模型的评测器，也不是独立人工 ground truth。

当前 BYOK 只有 mock/loopback 协议验收；invalid output rate=0 和 382 passed 不能转成“准确率”。先明确人工真值、模型误判与错误压制风险，才能判断深度数据流工具究竟解决哪些证据缺口。**Joern 继续后置。**

用户随后提供了固定 scan `99ca7566-4a6f-4818-b447-38646072457b` 的实际宿主 MCP 验收报告：115 Raw、26 VALID、0 ACTIONABLE / 26 REVIEW / 0 LOWER_PRIORITY / 0 SUPPRESSED、0 FAILED / 0 STALE、89 UNTRIAGED，整体及 Dependency 仍 PARTIAL。该结果与历史脚本回放是不同运行，不能为了匹配回放调整 verdict/priority。报告尚未固化为仓库内机器可核验的验收 artifact，第一轮未直接重跑该 MCP；第二轮仅对其已保存有效审阅做实际 SDK 复用验收，见 AH；它是产品问题的输入，不是新的独立 ground truth。

用户需要连续转发多轮提示词，才从验收表走到 TLS 的业务影响与修复方案。后续调用链来自宿主 Agent 额外只读源码核查，并未提交为 Runtime Triage；不能把它记成 Runtime 自动调用链分析或扫描覆盖提升。此前 `human.render_triage` 将有效分析记录称为“已验证”，容易与人工验证混淆；本轮已修正为“已完成 AI 审阅”，质量验证仍独立 Planned。易读性和判断正确性分别验收。

## 当前已实现与本阶段 Planned

| 已实现的 v0.1 基础 | 质量阶段尚未实现 |
| --- | --- |
| Raw / TriageRecord 分离、五类 verdict 与独立 exploitability | 版本化真实项目 ground truth schema 与独立人工 adjudication |
| EvidenceBuilder、脱敏、预算、HMAC revision、引用/hash 校验 | 完整 benchmark 源码/证据身份冻结与标注审计 |
| Agent-native MCP prepare/submit/get、session/replay 防护 | 真实多模型、重复运行及 provenance 比较 |
| 显式授权 BYOK、结构化输出、依赖 batch/cache | suppression risk、precision/agreement 的有效统计 |
| 独立 scan/triage coverage、Raw 分组和保守 policy | prompt/model regression 与人工确认的质量门槛 |
| 合成 fixtures 和真实 26 项审阅回放 | Joern Java PoC、compiler-grade dataflow |
| 十一个 MCP 工具；summary 只读任务投影、task_ref 继续核查、版本/能力与宿主连接指导 | 实际宿主自然语言试用及三位未参与开发者的真实易用性反馈（Pending） |
| 宿主可在其授权范围内继续读源码 | 通用宿主补充报告导入与超出受限证据的分析（未实现） |
| generate_fix/verify 兼容；task_fix 结构化交接及原规则等价复查 v0.1 | 真实宿主 UX / 生产与业务验证 |

产品迭代与质量工作流均保留 Raw、现有 TriagePolicy、RiskEngine、覆盖契约、Secret 保护与 External AI 授权边界。不增加 scanner、不自动构建目标项目、不做全仓主动 AI 审计、不增加 FALSE_POSITIVE 反证类型。质量实验若暴露实现缺陷，应记录独立问题、按新的修复任务处理，再复验；不能把评测脚本的结果悄悄改成 Runtime 产品行为。

## 用户已确认的产品迭代顺序

| 顺序 | 交付范围 | 用户可获得的结果 |
| --- | --- | --- |
| 1：开发者任务入口 v0.1 — Implemented / 自动化与分发 CI 验收通过 / 人工试用 Pending | 定位当前 workspace 的扫描；只读汇总；保守合并；普通/详细视图；建议下一步 | 任务单及完整逐项入口，不自动执行动作 |
| 2：继续核查 v0.1 — Implemented / 自动化/原生/四组 CI 通过 / 旧聊天试用未通过，刷新后复验 Pending | 精确任务引用、pending-only/cache 推进、受限 MCP handoff；先查已有证据，再询问必要业务候选问题 | 用户说继续某项，无需 Finding UUID；Runtime 不调用宿主模型 |
| 3：Developer Fix & Verify v0.1 — Implemented / 宿主 UX Pending | 结构化约束、宿主获授权编辑、原规则 bounded 复查与分组结论 | 不改生产、不自动构建；用户不搬 prompt/UUID |

独立人工质量工作仍 Planned；不把报告易读性当风险判断质量。第二轮曾调整受限缓存/批次推进；本轮实现第三轮 Runtime 修复交接/验证，不调用真实模型或由 Runtime 应用补丁。

2026-10-02 真实用户在原 Jeepay 聊天用两句普通意图试用，回复虽可读，调用记录却仅有 get_triage，继续轮没有工具调用；未取得新 summary/task_ref 或执行任务级 handoff，不能计验收通过。旧聊天此前缺少新入口，同配置程序的全新 SDK 连接已确认能力存在，疑似旧连接/工具列表未刷新，具体原因未证明。先刷新宿主连接与工具列表，再在新聊天取得新 summary 后复验；不让用户搬运技术提示词或盲目重装 editable。见 [试用记录](jeepay-host-task-trial.json) 与 AH。三位独立开发者和人工质量状态不变；当时第三轮 Planned，本轮已实现 Runtime 交接与验证，真实宿主 UX 仍 Pending。

### 首轮：开发者任务入口 v0.1

已新增 `get_security_summary(workspace_path=None, scan_id=None, details=False)`，当前共十一个 MCP 工具；CLI 为 `security-check summary [--path <project>] [--scan ID] [--details] [--json]`。共用 security_summary.py 投影和 ReadOnlySQLiteStore；纯汇总连接延后初始化可写 Runtime，不创建 DB/schema/key 或 telemetry。没有 GUI、云服务、新推理路径或持久化任务表。

TLS 合并限定为两个明确 first-party trust-all 规则、同文件、行起点相距不超过 40 行；同规则、远距离或不同文件不合并。阈值用于展示共同校验核查目标，不证明对象共享调用链。依赖按既有四元组分组，身份字段缺失则保守逐条展示。普通最多三项推荐，详细列出全部任务/成员/状态/来源与 Raw 入口。原 policy、覆盖和 release 状态不改；任务编号是当次展示投影。

1. **Workspace 定位。** 有明确 scan ID 时校验其归属；未提供时，只能在已绑定/明确选择的 workspace 内定位最近扫描，不取全局最近记录。未绑定或目标有歧义时要求明确 workspace；无记录时返回“需要首次检查”和可选下一步，不自行扫描。旧工具不默认获得 `scan_id="latest"` 别名。
2. **纯只读汇总。** 输出基于现有 scan、Raw 与 Triage 记录，不调用 scanner/模型、不收集目标项目环境变量或凭证值、不改源码或 DB。旧 `TriageService.view` 默认写入 STALE 的行为保留；新入口使用只读存储和 `persist_stale=False` 的 freshness/投影路径。证据不可核对时保留过期/不可核对状态，不能把历史 VALID 当成当前确认。
3. **保守任务合并。** 有明确共同位置/规则语义/修复目标的 TLS 发现可合并；依赖沿用 ecosystem/package/version/manifest 分组，每条 advisory 保留独立 identity 和分析状态。不能仅凭相同 severity、文件或模型叙述合并不相关风险。任务是展示投影，首轮不另建持久化任务数据库，不覆盖原 Finding/TriageRecord。
4. **普通与详细视图。** 默认一页、最多三个推荐跟进任务，提供完整任务列表/Raw 入口。任务包含可能影响、已有依据、未知条件、建议下一步及关联 Finding。UUID、CVE 明细、confidence、evidence_refs、policy_notes 留在详细视图。所有 REVIEW 时仍可建议“核查影响”，但不得重映射为 ACTIONABLE，不自动隐藏其余候选。
5. **状态表达。** “已验证”改成“已完成 AI 审阅”，明确 VALID 是记录通过 Runtime 校验，非人工验证、复现或线上可利用证明。扫描覆盖与审阅覆盖分别展示；FAILED、STALE、UNTRIAGED、IaC 不 eligible 分开解释。0 ACTIONABLE 不生成“安全”结论。
6. **来源与权限。** 区分扫描器候选、Runtime 已接受的 AI 审阅和宿主补充核查。模型 reason/合法引用不是确定性事实证明；未被 Runtime 接受的额外调用链不得伪装为其已验证证据。当前没有通用宿主补充报告的导入接口，首轮不伪造已持久化记录。下一步先展示建议动作，不自动执行编辑、构建、联网或模型上传；既有授权在其范围内有效，不重复询问已授权的只读工作。

Jeepay TLS 是贯穿用户任务的样例：两条校验绕过候选可组织为“核查云闪付 HTTPS 连接”；明确区分不安全实现、静态业务调用与未知生产条件。此前宿主追踪到下单、关单、退款及补单查询，这属于用户提供的补充核查报告，尚无本轮独立复验或已接受的新 Triage 记录。Secret 先核对用途与部署覆盖，用户只提供状态而非原值；依赖缺少 affected range/fixed version 时先补信息，不编造升级版本。

### 首轮验收标准（自动化/分发/CI 通过；人工易用性 Pending）

- 无需手工寻找 UUID 就能取得当前 workspace 的结果；多 workspace、显式不匹配 scan、未绑定/有歧义、无扫描记录均有确定行为，不串项目。
- 默认报告让用户能回答“先做什么、为什么、下一步如何推进”；技术详情和完整列表仍可获得，不以省略信息制造低风险印象。
- 两条相关 TLS Finding 能形成一个任务，并能逐条回溯；依赖 grouping 不吞 advisory，不混淆未审阅/失败/过期状态。
- 26 REVIEW / 0 ACTIONABLE、部分扫描、75 eligible 未审阅与 14 不 eligible 的 IaC 等状态都能准确表达；历史回放另测，不能要求同一 priority 分布。
- 汇总读取不改变 scans/findings/triage_records；来源、Secret 脱敏、workspace 边界与现有授权约束完整。新增工具数与所有展示在交付时据真实代码更新。
- 找三位未参与开发的开发者，不给工程验收长提示词，观察其是否能取得结果、理解首个任务并选择下一步。记录困惑、错误理解和所需额外解释；此项检验易用性，不当作安全准确率。

用户明确回复“目前无法安排，保留待验收”。本轮不以 Agent 模拟用户或自动化测试替代三位真实试用者，不声称首轮全部验收/整体质量 milestone 已完成；实际自动化及分发结果见 AI_TRIAGE_ACCEPTANCE 的本轮附录。

### 第二轮：继续核查 v0.1（已实现，源码/wheel/SDK 通过；实际宿主试用 Pending）

继续核查已处理“排序后先取 limit、再查 cache”的推进问题：缓存不占新分析名额，任务模式保留 VALID、优先 UNTRIAGED、其次 STALE、FAILED 显式 retry_failed。每次最多检查1000候选，packet/证据错误最多20；hash/session/引用/原策略保留。额外源码核查须标明范围和来源；词法结果不宣称 compiler-grade 调用链，不把宿主任意读取结果塞进不允许的 evidence_refs。

修复迭代复用现有修复任务和扫描复查基础，但不能把 `generate_fix` 宣称为现有自动补丁能力，或把 `verify` 无匹配当业务修复证明。准备补丁、应用补丁、构建/测试、扫描复查与生产发布分别报告执行状态；沿用用户已给出的授权，超出范围的实际执行再取得相应授权。目标 Maven/Gradle/npm/pip 构建仍不默认执行。修复与验证 v0.1 的设计与实现见本文当前状态，真实宿主 UX 尚未通过。

## Host-agnostic Hook Integration v0.1 — Planned / NOT_STARTED（下述为历史门禁）

用户已提出新的 Hook 任务，并明确以前置 Developer Fix & Verify v0.1 和稳定 Finding equivalence 为门禁。2026-10-02 干净工作区 ff-only 同步后仍为 `787aace`：该历史时点修复与验证尚为 Planned，旧位置敏感指纹/旧 verify 在同规则同文件仅移动行号时仍错误返回 RESOLVED。完整离线 baseline 461 passed / 6 skipped / 6 subtests passed（108.77秒）；基线通过不证明前置能力存在。

按用户要求停止 Hook delta 正式实现，未实现或安装 Codex/其它 Host Hook，不另建第二套 Finding Identity，也不在本任务自动补做 Fix & Verify。恢复条件是先交付/同步前置阶段并验收行号移动仍 PERSISTING/STILL_PRESENT，再复用其身份开展本轮范围。实际 fresh Codex Hook、性能、package/standalone 与新 Hook CI 全部 NOT_RUN；旧 MCP/CI 不能计本轮验收。现有 pre-commit、独立人工 ground truth 和其它 Planned 状态保持。检查依据见 AI_TRIAGE_ACCEPTANCE 的 AI 附录。

## 固定 Benchmark 与评测边界

已保存输入为 [jeepay-osv-online-evidence.json](jeepay-osv-online-evidence.json)，scan ID `f5224162-0624-416f-8472-0f0474e7fd58`，文件 SHA-256：

`52af4bb37bdb411babd388e50e9d6e4ec2fb9ef6e8d88975d8dcb4f34b88bd5d`

现有 capture 仅记录 Jeepay branch=master，**没有对应源码 commit SHA**。规划第一步必须核实原扫描/packet 对应的源码版本。不能把任意新的 Jeepay master 当作旧样本；无法还原时标 SOURCE_REVISION_UNKNOWN，保留旧验收，同时另建有明确 revision 的质量样本版本，不能覆盖历史记录。论文式/发布式可复现质量结论需通过这一身份门槛。

样本分层：

- 全部 115 Raw 保留为 universe，4 code、9 Secret、88 dependency、14 IaC，不把 triaged 子集当完整仓库风险全集。
- 首批 26 项固定为 v0.1 对照 cohort；其余 75 dependency 另列后续分层标注 cohort，不能只挑高置信成功项。
- IaC 14 项不属于 v0.1 AI eligible，人工可验证其分类/候选意义，但不塞进 AI verdict precision 分母。
- Dependency 28 个包/版本/生态/manifest 组内 advisory 相关，逐 Finding 与逐组统计分别呈现，不能把同组重复证据当独立 88 次成功。
- 合成 fixture 用于边界与回归，独立列出；不混入真实 Jeepay 人工质量分母。尤其真实 cohort 目前无 FALSE_POSITIVE/SUPPRESSED，不能由此估计这一分支的可靠性。

模型比较使用同一冻结的受限脱敏 packet、相同选择列表、预算和 prompt 意图。人工可在授权本地范围核对更完整上下文，但须记录依据是 BOUNDED_PACKET、LOCAL_SOURCE 还是 EXTERNAL_RUNTIME_FACT；分别评价“给定证据能合理判断什么”和“实际风险已被人工证实什么”，避免惩罚模型无法获得的运行信息。

## 质量工作流：八个规划阶段

阶段 1 先冻结样本并做独立试标；阶段 2/3 形成 schema 和标准，再回到阶段 1 完成正式标注。模型比较、指标与回归使用冻结后的 adjudicated 版本，不在模型输出之后随意改标签。以下路径都是**未来可能涉及的文件**，本轮不创建或修改它们。

### 1. 人工标注固定 Jeepay benchmark

输入：保存的 native scan、现有 26 项审阅、源码版本线索及 [人工标注入口](jeepay-human-ground-truth.json)。

规划：先核实 source revision、Raw SHA、scan identity、provider/coverage 与样本选择；建立只读评测输入清单。至少两名独立人工审阅者盲审，初次不展示既有 Agent verdict/priority，记录引用、理由、未知前提与证据范围；分歧交由第三方裁定或显式保留 unresolved。涉及 Secret 仅查看安全结构/用途，不在标签中保存明文，不测试线上凭证有效性。

未来文件：既有 ground truth 的版本化继承、`tests/triage/fixtures/jeepay` 的独立质量 fixture，以及待定义的 benchmark manifest；原验收/原 Raw 不覆盖。

验收：26 项都有人工状态或明确不可判定原因；身份无法还原的样本不能宣称可复现。扩展 eligible cohort 时报告选择规则和各分层未标注数；没有真正人工审阅者就继续 UNREVIEWED，不由 Agent 自填。

### 2. 建立 Ground Truth Schema

输入：阶段 1 的试标及身份 manifest。当前文件只有三种 allowed_labels 和 reviewer/status 槽位，尚不够表达完整五类判定、分歧与真实运行依据。

规划 schema_version、benchmark_version、source revision/status、raw scan/hash、case identity、scope、审阅者匿名稳定 ID、时间、证据引用、reason、verdict、confidence、exploitability、已满足/未知前提、可判定性、review/adjudication 状态和变更理由。将 `bounded_evidence_verdict` 与 `independently_established_risk` 分开；后者允许 UNKNOWN，不能由模型 verdict 推导。旧三标签保留其原义及 provenance，不能自动映射成 CONFIRMED/FALSE_POSITIVE。

模型/provider/prompt/run 记录独立于 human records；必要的标签变更保留版本/原因。事实 schema 与 TriageRecord API 不混同，不为了 benchmark 扩字段就假称已改产品模型。

未来文件：待定义的 schema、ground truth versioned artifact、质量数据校验脚本；必要时扩展现有 fixture metadata，但不改 v0.1 Runtime contract。

验收：UNREVIEWED/UNRESOLVED/证据不足不能拥有“已裁定真值”；非法枚举、缺 identity、越界引用和 Secret 内容均拒绝；schema 校验用实际人工记录和负例验证，不能仅测试生成器自身。

### 3. 五类 Verdict 一致性标准与人工校准

输入：schema、盲审试标。先校准规则再完成正式标注，不用既有模型输出定义答案。

| Verdict | 给定证据的共同标准 | 不可据此推导 |
| --- | --- | --- |
| CONFIRMED | 当前证据支持候选所声称的不安全行为/版本事实，引用和适用范围明确 | 自动证明公网可利用、生产可达或所有前提满足 |
| LIKELY | 多项具体证据支持风险，但存在明确未知；列出未知及置信依据 | 仅凭 severity、rule ID 或模型自信判定 |
| NEEDS_REVIEW | 证据不足、互相冲突或依赖运行/协议事实 | 自动判安全、误报或统计成正确阴性 |
| UNLIKELY | 有具体减弱风险的证据但没有充分排除候选 | FALSE_POSITIVE 或隐藏 Raw |
| FALSE_POSITIVE | 明确反证推翻该候选，HIGH confidence、引用有效且无相关未知前提 | 仅 doc/test/example/default 位置、公开仓库、有限搜索无结果 |

人工另标 exploitability，依赖版本匹配与可达性分离。TLS bypass 的实际安装支持局部确认，生产调用/攻击位置可能未知；MD5 支付签名要核对协议/威胁条件；Secret 使用目的与真实有效性分离；Dependency graph/affected API/runtime 前提缺失则保留未知。

未来文件：标签指南、校准样例和 adjudication 记录，可与正式 quality acceptance 合并，避免为每个小主题单独新增顶层 docs。

验收：审阅者能按同一标准解释分歧；报告人工 agreement 与 unresolved 数，不强迫所有案例进入确定二值真值；确定性 policy 与人工更广的反证不混同，人工认为误报不表示当前 Runtime 必须 SUPPRESSED。

### 4. 比较 Agent-native / BYOK 不同模型结果

输入：冻结且已标注的 cohort、packet、schema 和判定指南。先做 pilot，再按固定预算运行多个实际模型/版本和重复运行；相同模型若两条路径都可用，可单独测路径差异，否则明确模型与路径变量混杂。

每 run 记录：Runtime commit、benchmark/packet digest、provider_type/name、实际 model identifier/版本可观测性、prompt_version、budget、batch/group shape、时间、错误/拒绝/结构不合格、cache hit、耗时/可观测用量，以及 policy 版本依据。宿主的 host-managed 通用标签不足以证明具体模型；拿不到真实 model/version 时标 UNKNOWN，不伪造固定版本或严格同模型对照。

独立新推理与 cache replay 分开；cache 命中不能当新模型样本。未来 harness 必须明确实现固定 packet 与实验 state/cache 隔离方式，不能假设当前 CLI 已有 no-cache、精确模型追踪或全量自动遍历选项。对 default limit/cache 优先选择问题显式选择 case IDs，确保实际待评项进入运行。

未来文件：新质量评测 harness 与 run manifest、现有 MCP/BYOK 测试的协议复用；现有 host_analysis 脚本继续作为回放验收，不包装成真实多模型评分器。

验收：每结果可追溯到真实 case/model/prompt；统计完整选定 cohort，不丢弃失败、不只留成功答案。External BYOK 实验须另获目标 endpoint、脱敏内容和费用范围的明确授权；历史 OSV 元数据授权不代替模型上传授权。没有授权或模型可用性时记录 NOT_RUN，继续人工工作。

### 5. 测量 False-negative Suppression Risk

输入：独立人工结论、模型提议及 Runtime policy 后结果。分别观察模型提出 FALSE_POSITIVE 和 policy 最终 SUPPRESSED，不能用只检查 schema 的测试替代风险测量。

重点统计：

- 在人工已确立风险的候选中，被最终 SUPPRESSED 的数量/比例；这是 **conditional false suppression rate**，分母为已独立确立风险且纳入本轮的候选。
- 在已有可判定真值的 SUPPRESSED 中，实际有风险的数量/比例；分母为这些可判定的压制项。
- 人工确立风险却被 UNLIKELY/LOWER_PRIORITY、FAILED/STALE 或尚未处理的项，单列潜在遗漏/降优先级风险，不与压制混在一起。
- 原 115 项是否始终可见于 Raw，以及 ERROR/STALE 是否仍可复核。

真实样本不足的 FALSE_POSITIVE/注入/placeholder 边界用明确合成或独立构造 counterfactual case 补充压力测试，结果单列，不冒充真实风险基率。已知 Secret、注入指令、伪造引用、unknown precondition、dependency “没找到 API”应重点复核。发现任何已确立真实风险被压制，先阻断扩大 suppression 的发布结论、人工裁定并追根；修复独立授权处理。

未来文件：质量报告中的风险矩阵/案例引用，必要的独立 regression cases；本阶段不自动放宽或重写 TriagePolicy。

验收：无真值、无 SUPPRESSED 分母时写 NOT_MEASURED/N/A；当前真实 0 SUPPRESSED 只能说未观察到压制，不能声称 0% 风险或零 false negatives。本阶段评估的是扫描候选集合内的分流风险，不能测得 scanner 未检出的仓库漏洞 recall。

### 6. 测量 Triage Precision / Agreement

输入：人工裁定版本与阶段 4/5 的完整 run。按 category、severity、provider/model、verdict 和依赖组分层报告 numerator / denominator / unknown / failed / stale / untriaged。

指标定义在运行前固定：

| 指标 | 计算与解释 |
| --- | --- |
| Positive triage precision | 已 adjudicated 且实际风险可判定的 CONFIRMED/LIKELY 输出中，人工独立支持风险者 / 该可判定输出总数；同时报告被排除的 UNKNOWN |
| ACTIONABLE precision | 可判定 ACTIONABLE 中人工支持该风险者 / 可判定 ACTIONABLE；与原 verdict precision 分列 |
| Five-label agreement | 模型给定证据 verdict 与人工 bounded_evidence_verdict 的一致项 / 已裁定可比较项；附完整 5×5 confusion matrix |
| Human agreement | 独立审阅者原始一致率、分歧与 adjudication；必要时报告 kappa 及类别基率限制 |
| Repeatability / model agreement | 固定 packet 下跨模型/重复运行的 verdict 与 priority 一致性；一致不是正确性 |
| Evidence fidelity | 独立核验 claim 获得引用支持的比例；不能把行范围合法率叫事实正确率 |
| Operational coverage | 输出 VALID、结构失败、provider 错误、STALE、cache/new inference、UNTRIAGED 的各分母与比例 |

人工真实风险 UNKNOWN 时不当作 FP/TN；NEEDS_REVIEW 不是负例。需要更广业务事实的结论与 packet 合理性分开评价。按 case 和 dependency cluster 报告，置信区间须考虑组内相关和样本量；26 项不足以作普遍“准确率”承诺。缺分母就 N/A；尚未运行就 NOT_MEASURED；不填写“99% accuracy”。

未来文件：质量指标脚本、完整分母/分层报告与 schema 校验。算法/矩阵须用人工可核算的小表验证，并复核实际 cohort ID，避免自生成标签、自打分。

验收：指标可以从冻结输入和记录重算，所有排除项有理由，三类数据（真实人工、合成、历史回放）不混算。当前 documentation 仍记录 NOT_MEASURED，不能把规划示例写成已测结果。

### 7. Prompt / Model Regression

输入：已有质量基线、suppression 风险分析与冻结 holdout。用于迭代的 development cohort 与最终 holdout 分开，不能在看过 holdout 输出后改“标准答案”。

每次 prompt/model/Runtime policy/evidence 边界变化，固定数据复跑并对比模型提议、accepted verdict、priority、引用支持、unknown preservation、误压制、provider/schema failure 与成本/耗时。Prompt/version 变化影响 cache；单独验证 raw scan/coverage 不受评测污染。

安全 regression 包括 Secret 四出口、恶意回显、注入、伪造 session/replay、越界引用、过时 hash、依赖 reachability 过度断言，以及未授权 external call=0。可复用既有单测；真实人工效果门槛不能由单测替代。质量实验只持久化必要脱敏结构/metadata，不默认存完整 prompt/源码/raw response。

未来文件：版本化 baseline/run manifest、质量 regression runner 与精简 acceptance；模型 endpoint/key 由隔离配置提供，付费/外部实验不默认在 CI 发起。

验收：人工/维护者在看 holdout 前确立 numerical thresholds、最小样本和回退规则，并留决策版本；不存在有证据真实风险被压制的未解决 case，无 Raw 丢失/Secret 出口/授权绕过。结果不达阈值须标 failed，不因为多数 agreement 高而忽略严重案例。本轮不捏造已经同意的 precision 阈值或预算。

### 8. v0.1 质量稳定后，才进入 Joern Java PoC

依赖：前七阶段完成；独立人工身份/标签足够、质量分母可解释、误压制调查无未解决重大问题、prompt/model 回归稳定，且 case 分析显示 bounded evidence 的具体 Java 缺口值得深度工具验证。没有这些证据就保持 Deferred。

未来仅规划独立 bounded PoC：固定工具版本与许可、指定少量 Java source-to-sink/调用案例、预定义安全负例、记录 unsupported code、资源/时限/输出 cap 和工具失败。证明“选定案例的路径是否可提取”，不承诺完整仓库或依赖可达性；没有路径不等于不可达。若需要构建/依赖解析，应另定义安全及用户授权范围，不默认执行 Maven/Gradle。

未来可能文件：隔离 PoC fixtures/评测脚本/报告；产品 adapter 与 release policy 变更留待独立设计决策，不列为本阶段直接实现。

验收：先写具体问题、预期证据增益和比较基线，再决定是否实施；PoC 结果不污染 Raw、scan coverage 或已冻结 ground truth。Joern / compiler-grade dataflow 在当前代码中仍 **NOT_IMPLEMENTED**。

## 阶段完成标准与交接

质量工作流完成必须同时具备：可复现 benchmark 身份；独立人工标签与分歧记录；五类 verdict/实际风险/利用条件的区别；可追溯多模型 run（或明确未运行限制）；分母完整的 precision/agreement/suppression-risk；安全边界回归；预先确立并满足的质量门槛。没有足够人工真值或真实模型结果只能交付部分测量，不宣布完成整体质量 milestone。

**开发者任务入口 v0.1 已实现，三位真实开发者试用仍 Pending**；实际自动化结果独立记录。继续核查已实现，修复与验证 v0.1 已实现，实际宿主 UX Pending。独立质量任务仍未开展：冻结 Jeepay 身份、人工盲审及 ground truth schema/指南；原 UNREVIEWED/null 不由 Agent 填写。

整体 milestone 需分别交付获授权的产品迭代并达到质量工作流门槛。产品迭代需同时满足其使用验收和既有边界回归；独立质量工作流按前述身份、标签、指标与风险门槛单独验收。任务入口完成不代表八项质量工作或整个新 milestone 完成。先使用既有目录与证据，新增报告尽量合并为一个 acceptance，不再为每次运行增加顶层总结文档。旧验收按原时点保留，原 ground truth 的 null 不在本轮填写。

新聊天从 PROJECT_STATE 的 Agent Handoff 开始，区分已实现入口/继续核查/修复验证 v0.1 与真实宿主 UX Pending。后续源码开发须另有明确任务；不能默认公网模型请求、人工标签代填、训练/调参或 Joern。


第二轮接口：`prepare_task_triage(task_ref, workspace_path=None, limit=20, retry_failed=False)`，当前13个 MCP 工具。宿主从实际展示项的 continuation 参数发起，然后分析本次受限 packet 并使用返回的 scan_id/triage_session 调用 submit_triage；用户不提供 UUID，Runtime 不调用宿主模型。引用绑定固定 workspace/scan/精确成员身份，与 T01 或 priority 排序无关；格式/版本/归属/成员变化要求刷新重新选择，新 scan 不替换原引用。源码改变由 freshness/context_hash 防护。

全有效审阅时可返回已有依据与必要业务候选问题，不重复模型工作；FAILED_RETRY_REQUIRED、EVIDENCE_UNAVAILABLE、BOUNDED_EVIDENCE_LIMIT、NOT_ELIGIBLE 分开表达。既有审阅摘要上限20条/64KiB、未知最多20项，截断显式显示，完整成员/记录仍在 details。额外宿主报告不自动入库，不能扩展 evidence_refs。三位真实试用者 Pending，独立 ground truth 仍 UNREVIEWED/null，质量指标未测；修复与验证 v0.1 已实现，实际宿主 UX Pending。


## 普通用户意图与宿主衔接验收

产品目标是“不懂安全的开发者也能用好”：用户只说“检查这个项目”“继续/处理第一项”或选择任务，不搬运技术提示词、填写 UUID、拼接工具顺序，也不把 generate_fix 输出再粘贴给 Agent。一次选择 → 核查 → 准备/实施获授权修复 → 验证 → 简洁结果是完整目标；本轮仅接通核查，修复与验证 v0.1 已实现，实际宿主 UX Pending，后续须沿同一宿主自动衔接，不能再次要求用户搬运提示词。

已接入 FastMCP server instructions 与工具 annotations/描述：宿主绑定实际展示响应的 task_ref，自动在已有授权范围内准备、分析、提交并展示结果；有效授权持续有效，不反复询问常规获授权步骤。仅询问代码无法回答且会影响下一步的必要业务事实，或取得超出已有授权操作的权限。Runtime 不主动调用宿主模型，源码/scanner/模型文字均非执行指令，现有 session/hash/evidence_refs、脱敏、Raw、覆盖和策略保留。

新增只读 `get_runtime_info` 与 CLI `runtime-info --json`，包版本仍0.3.1、能力契约 developer-guidance-v0.3。连接检查按 required_guidance_tools 子集，允许兼容新增工具，不按总数严格相等拒绝。返回同一 executable/environment 的可执行核对参数和重连指导：先核对配置实际运行的环境；已有能力却宿主看不到时断开/重连 ai_security_runtime、刷新工具列表，必要时新聊天；仅环境本身旧时更新对应包。不盲目重装 editable、不终止进程/修改 Jeepay 配置。连接重建后旧 session 不可复用，遗失任务选择须刷新重新选择。

SDK initialize 实际收到 instructions、工具 metadata、版本/能力和机器交接，与真实宿主自然语言试用分别验收。后者目前 Pending；旧 Jeepay 聊天工具列表恢复未验证，不能把新 SDK 连接成功写成普通用户已能用好。三位独立开发者试用 Pending，ground truth 保持 UNREVIEWED/null，质量指标 NOT_MEASURED。核查准备、宿主结果接受、补丁、目标构建、测试/扫描复查分别报告是否执行；generate_fix 仍仅 coding task/prompt，不代表补丁完成，0 ACTIONABLE 不表示安全。

本轮实现与分发依据：`1e10b53`；起始 `0f33d26`。Windows 独立包实际 source_commit 与实现一致，SDK 取得13工具及 v0.3 契约，真实 Semgrep 组内仍存在/部分/全部规则复查结果通过；本轮测试、package、compliance 和四平台 standalone CI 均 success，详见 AJ 与 [native/CI 证据](fix-verify-native-evidence.json)。文档最终 HEAD 用 `git log -1 --format=%H -- docs/PROJECT_STATE.md` 获取；代码之后若变化须重新验收。以上为历史 Fix & Verify 交付；当前 Hook 已完成实现与分发验收，真实 UX、三位试用与独立人工质量状态不变。

## 本轮结束后的范围（2026-10-03）

Hook 核心、Codex/Cursor适配和 CLI/合成 quick链路已实现；当前验收/分发事实以 AK为准。完成最终门禁、提交推送 feature/runtime-mvp 后停止。fresh Codex Host trial 需宿主重新加载并信任项目hooks，当前聊天不能替代这个新会话；Cursor实际事件及界面反馈同样未验收。三位真实开发者用户当前无法安排，保持 Pending；独立人工 ground truth UNREVIEWED/null。没有授权后续自动修复、构建、watcher、模型/在线查询、Joern 或新 scanner/rules。

WorkBuddy桌面、Kiro、Qoder schema 未证明时保留 MANUAL_CONFIGURATION_REQUIRED；CodeBuddy CLI 的设置不能直接当 WorkBuddy桌面契约。未来只有独立新任务和对应官方 schema/真实环境证据，才扩展适配。MCP 的核查/修复工具流和 Git commit边界仍各司其职；本轮不是质量/人工真值阶段完成。


本轮 Hook implementation/分发交付已完成，停止开发。fresh Codex/Cursor host trial、旧Jeepay宿主连接刷新后UX、三位真实开发者试用仍Pending；Kiro/WorkBuddy/Qoder官方schema与自动adapter待人工资料确认。Deep Audit、watcher daemon、MCP/Skill Security、新阶段、独立Ground Truth/模型质量评测、Joern均未开始，继续Planned。不得自动推进。
