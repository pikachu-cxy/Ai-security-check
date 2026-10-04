# AI Security Runtime — Architecture Decisions

## AUTO_FIX PostToolUse Code Mode Contract Fix v0.1（2026-10-04）

干净起点 `feature/runtime-mvp` / `50f002deff33d0946ee99c338d700b08a739e394`。最新用户真实 Desktop：缺失首安全 Hook 后危险首有效 Hook 为 SETUP_SEED / baseline_available=true / SCANNED / NEW1 / AUTO_FIX，First-run Baseline Seed、归因、AUTO检测策略 **USER_REPORTED PASS**。之后 Script failed、未prepare/未secure edit、resolved0；Host重试危险编辑导致SESSION/NEW0/ESCALATE。**PostToolUse continuation USER_REPORTED FAIL（Code Mode decision:block contract）**；Stop未进入，Desktop **NOT TESTED**，不能写Stop FAIL。readiness/lifecycle已有真实PASS，不再调查。新transport的fresh Desktop自然继续/Stop闭环 **PENDING_ACTUAL_DESKTOP**。

[当前官方 Hooks 文档](https://learn.chatgpt.com/docs/hooks#tool-calls-from-code-mode)核对于2026-10-04：PostToolUse decision:block 在已执行工具后拒绝nested Code Mode promise；continue:false把反馈作为model-visible result而不拒绝promise。只改codex_mcp_hook.py的AUTO_FIX反馈为continue:false/stopReason，systemMessage原样；固定提示前一编辑已执行、不要retry/repeat、授权的是remediation、立即prepare_task_fix，然后附原bounded guidance。无新字段、无原AUTO decision/reason。CONFIRM_REQUIRED原continue:false/stopReason主动询问并WAIT；NONE无停止；Stop仍decision:block/reason生成continuation prompt，不能机械替换。

实现 `1033abfd5c467661a2a7110442bcc410851e9bb1` 已提交推送。focused **156 passed in 383.80s (0:06:23)**；targeted **534 passed in 1007.83s (0:16:47)**；final full offline **987 passed, 6 skipped, 6 subtests passed in 1142.05s (0:19:02)**。六项skipped单列于AV，不计PASS。wheel/sdist/package/compliance、101打包文件bytes integrity、其余全部Runtime源码不变、严格离线clean安装、actual source SDK、独立新目录Windows native均PASS。新四类CI **PENDING_RERUN_AFTER_ACCOUNT_RECOVERY**，实际jobs/annotations见AV；未运行的平台不写PASS。最终docs HEAD按本文件git log核对，其docs-only CI在最终交付回复单列。

AUTO_FIX action/interaction、原task_ref/remediation_ref/grant_id与prepare/verify handoff、policy/guards/verification/state machine保持。HookCoordinator/baseline/snapshot/cooldown/single-flight/family multiset/coverage gating、Raw/脱敏/UNTRUSTED_CODE/session/hash/evidence_refs/预算保持；command hook保留。SessionStart/PostToolUse/Stop的matcher/tool/input/timeout/statusMessage exact Hook定义与起点一致；canonical SHA256 cb407a5d3e175add5d51d90c86e5fd43cb74708b770dc585eab9eca92e82eb8b仅Runtime测试摘要，不猜Host私有hash、不写信任数据库。

SDK/clean/native真实Runtime/Scanner均SETUP_SEED/NEW1/AUTO_FIX，新feedback→driver消费原Stop handoff→prepare→模拟secure edit→resolved1/SCANNER_VERIFIED_RESOLVED/CLOSED，匹配receipt无需重复explicit verify；functional prepare NOT_AVAILABLE、无run。**SYNTHETIC_SDK_NOT_DESKTOP**，不证明自然模型继续。新原生包dist/standalone-code-mode由已提交实现HEAD构建；保留旧活动包/进程。fresh步骤见[Codex使用说明](CODEX_INTEGRATION.md)：全新disposable Git fixture→setup/Local Baseline READY→正常Review & Allow→退出/重开/新Chat→safe edit→danger edit→路径A自然PostToolUse或路径B原Stop兜底→同grant prepare/secure edit/resolved1，不得Script failed或重复危险编辑；不用旧ESCALATED baseline-seed-desktop-trial。

真实Maven A/B/Linux hardened execution PENDING_ENVIRONMENT_PREREQUISITES；不安装/下载/搭环境。三位试用PENDING，独立Ground Truth UNREVIEWED/null、质量NOT_MEASURED。未改Jeepay/用户实际fixture/冻结benchmark/人工标签；Runtime无模型/目标编辑/build/Secret rotation、Scanner离线，仅官方文档与授权GitHub交付联网。Capability/Entitlement、Plus/Pro、Enterprise Gate、Deep Audit、Skill/MCP Scan、Cursor、Installer、新Scanner/rule、baseline/Stop redesign及state relaxation/duplicate retry tolerance/AUTOrenewal均不进入。完成交付后停止。

完整门禁/CI/边界见[AV](AI_TRIAGE_ACCEPTANCE.md#av-auto_fix-posttooluse-code-mode-contract-fix-v01)和[结构化记录](code-mode-acceptance.json)。以下各旧节保留历史事实，当前状态以本节与AV为准。

### 本轮决策

1. 按官方event-specific契约修transport，不把工具已执行与Code Mode拒绝混为一谈。
2. 明确禁止重复原危险编辑，原授权只用于修复。
3. 保留Stop block及CONFIRM等待人，不改变原状态机/签名/guard。
4. 旧ESCALATED session不放宽、不续期；用全新fixture验收。
5. specification oracle只模拟文档规定的输出效果，不声称实现或验证Codex内部executor。

## First-run Baseline Seed + Trust UX v0.1（2026-10-04）

干净起点 feature/runtime-mvp / `50ecaf2f4451e4cc6854651c9987ae7167a8b11c`。本轮只修 setup→首有效 Hook 的归因缺口，暂停继续扩展 Stop Guard。最新用户 disposable Desktop 真实反馈：第一条安全编辑无 Hook 记录；第二条危险 TLS 编辑首次有效 Hook 返回 BASELINE_ESTABLISHED、baseline_available=false、scanner_run=true、FULL、NEW0/NONE。这是 **USER_REPORTED FIRST_RUN_TRUST_GAP**，本次没有 AUTO_FIX，不是 Stop Guard 失败。缺失首 Hook 的 Host 底层原因未证明，不能推断用户拒绝信任。旧 readiness/lifecycle PASS 保留历史。

Free v1稳定Host Hook ABI：SessionStart→handle_readiness_event、PostToolUse→handle_hook_event、Stop→handle_stop_event的exact definitions与起点一致，matcher/input/tool/timeout/structure及当前版本样式statusMessage都冻结，不随内部升级改文案。canonical配置SHA256 `cb407a5d3e175add5d51d90c86e5fd43cb74708b770dc585eab9eca92e82eb8b` 仅Runtime测试摘要，不猜Codex私有hash。官方[Hooks](https://learn.chatgpt.com/docs/hooks)要求精确定义审批；没有找到可用受支持trust查询API，不读/写私有信任数据库或绕过审批。SessionStart仍轻量readiness；Stop Guard/command adapter/风险政策/Raw/UNTRUSTED_CODE/脱敏/修复验证/Functional contracts保持。

真实Maven A/B/Linux hardened execution PENDING_ENVIRONMENT_PREREQUISITES；不安装/下载/搭环境。三位试用PENDING，独立Ground Truth UNREVIEWED/null，质量NOT_MEASURED。未改Jeepay/用户实际fixture/冻结benchmark/人工标签；Runtime无模型、目标编辑/build/Secret rotation，Scanner离线，仅官方文档与授权GitHub交付联网。Capability/Entitlement、Plus/Pro、Enterprise Gate、Deep Audit、Skill/MCP Scan、Cursor、其它Host、新AUTO_FIX rule、Functional sandbox扩展等继续Planned。完成本轮交付后停止。

当前架构/决策见ARCHITECTURE与DECISIONS首节；完整门禁/CI/实机边界见[AU](AI_TRIAGE_ACCEPTANCE.md#au-first-run-baseline-seed--trust-ux-v01)，[结构化记录](baseline-seed-acceptance.json)与[试用步骤](CODEX_INTEGRATION.md)。

### 本轮决策

1. setup是Host审批前的比较点；不把完整scan移进SessionStart，不绕过Host信任。
2. seed的兼容性绑定与源码变化区分，后者不能触发刷新或吸收新风险。
3. FULL/SCOPED覆盖证明按原quick contract，partial seed不用来伪造归因；默认baseline不保存Finding DB片段。
4. repair/重建明确重新定义比较点，不表示项目safe；有效setup/repair幂等。没有新增显式refresh命令，刷新条件限missing/stale/incompatible/re-setup。
5. 冻结现有含旧版本字样的Hook文案，避免无谓重新review；内部逻辑/schema版本与Host ABI分开。
6. 首次无法归因风险只diagnose不AUTO_FIX；保持原修复政策。

以下章节为历史记录，最新状态以本节与AU为准。

## Auto Remediation Continuation Guard v0.1（2026-10-04）

Implementation `17a638f492d277d6bc9a104b019a5bbf081cb2ee` 已推送 origin/feature/runtime-mvp。新 Runtime/Package/Compliance/Standalone 四类 CI 实际 GitHub failure，9 jobs 未分配 Runner、steps为空，检查注解明确为账户付款失败/支出限额，**PENDING_RERUN_AFTER_ACCOUNT_RECOVERY**，四平台未运行；不是代码 PASS，不放松契约或更改账户/workflow。新 runs 见 AT.5。Windows native 从该已提交 HEAD 在独立目录重建并实际验收 PASS，71.33s，source_commit/hash可核对。旧活动目录第一次重建 DLL锁定失败；恢复74个缺失且未变资源，旧exe未改、未终止MCP。最终docs HEAD用本文件git log核对，其新CI在最终回复独立核实。

本轮最终 focused 116 passed in 177.41s (0:02:57)；targeted 497 passed in 555.13s (0:09:15)，最后retrygrant清理另3项PASS并由最终full覆盖；final full offline 951 passed, 6 skipped, 6 subtests passed in 666.89s (0:11:06)。wheel/sdist/package/compliance、八模块bytes integrity/十二核心不变、严格离线clean安装PASS。Windows native PASS（71.33s，独立目录，已提交source_commit）；CI PENDING_RERUN_AFTER_ACCOUNT_RECOVERY，Desktop Stop trial Pending。

干净起点 `feature/runtime-mvp` / `04c145e8bd5dbe5d266290a1db109e5d220d6368`。最新真实用户回传：无 get_runtime_info warm-up、无 reconnect/warm-up、首普通编辑 PostToolUse、MCP connection、AUTO_FIX policy、`integration status` 的 READINESS_OBSERVED / overall READY、setup 幂等/healthy repair/remove/re-setup 均 **USER_REPORTED PASS**。最新 fresh trial 中 Host 未调用 prepare_task_fix、未修复、resolved=0、无 security receipt/functional entry，**Host continuation UNSTABLE / FAIL（USER_REPORTED）**。AS 的旧 Cold-start/lifecycle Pending 已由本次真实反馈覆盖，早期 AUTO Host PASS 保留历史。本轮不调查或改 cold-start/readiness 设计；新的 Stop Desktop 自动继续仍 **PENDING_ACTUAL_DESKTOP**。

仅增加官方 Stop MCP fallback：handle_stop_event 的四项 closed/strict bounded host claims → HostContinuationGuard → 现有 RemediationService signed state/原 authority 与 guards。主 PostToolUse AUTO systemMessage/interaction/decision:block 和原强 guidance 保留。Stop 只补 PREPARE_REQUIRED，successful prepare 后旧条件静默，不覆盖 edit/recheck/functional。Stop 不扫描、不 prepare、不模型、不编辑、不 build、不联网、不创建/刷新 grant。用户未提供的 prompt/transcript/source/command/ref 不进入输入；无 Secret/source/model prompt 持久化。

原 AUTO POLICY_AUTO/OFFERED grant 的 exact workspace/host/session namespace、family/task/original scan、signature、mode/policy/config revision、snapshot、source/preservation proof 和未消费 prepare 必须同时成立。原高熵 token 仅当前连接内保留（最多32），不从 hash 恢复；重连 fail closed。900秒仅限 Stop 兜底窗口，不续期修复权限。独立签名 continuation counter 绑定 grant/snapshot/policy/PREPARE_REQUIRED，最多2，与 repair attempt_count 分开；耗尽记录 HOST_CONTINUATION_EXHAUSTED，允许结束，不反复写入。stop_hook_active=true 且此前未由本 guard 继续时不加入其他 Hook 循环。CONFIRM_REQUIRED/PENDING_CONFIRMATION、USER_CONFIRMED、DECLINED/EXPIRED/CLOSED/ESCALATED、report_only/NONE/ADVISE/MANUAL_ONLY 均不 block。无未消费 handoff 时 `{}` 文本输出，无 warning/state creation。

Codex setup 自有 SessionStart/PostToolUse/Stop 三事件，均 mcp_tool；required=true 与 readiness telemetry 原样保留。沿 HMAC fingerprints、old/new journal、merge/CAS/atomic/readback/ownership/repair/remove；旧已签名两事件可升级，foreign Stop 保留，malformed fail closed；能力 subset 新增 handle_stop_event，无 exact tool count。status 增加 Stop Guard，只有 READINESS_NOT_OBSERVED 的有效配置不再建议 repair。

HookCoordinator、snapshot/cooldown/single-flight/family multiset/equivalence、Scanner/rules/policy、TaskFix/Verification/Functional 三模块、command fallback 与原风险/Raw/coverage/脱敏/UNTRUSTED_CODE 均保持。新增模块与八模块包字节检查、十二核心不变的真实证据见 AT。Runtime 0.3.1 / developer-guidance-v0.3 保持；optional feature auto_remediation_continuation_guard=v0.1，不进入 entitlement/licensing。

真实验收与门禁记录见 [AT](AI_TRIAGE_ACCEPTANCE.md#at-auto-remediation-continuation-guard-v01)、[结构化记录](continuation-acceptance.json)、[Codex 配置与 fresh 步骤](CODEX_INTEGRATION.md)。本地自动化的 Host edit/forced fallback 是 driver 模拟，不能冒充 Desktop 模型继续。本轮实现/push/CI/native真实结果见本节首段与AT.5，最终docs HEAD按git log核对。

真实 Maven A/B/Linux hardened execution **PENDING_ENVIRONMENT_PREREQUISITES**，不搭建/安装/下载环境或构建依赖；三位试用 PENDING、独立 Ground Truth UNREVIEWED/null、质量 NOT_MEASURED。未改 Jeepay/用户实际 Desktop fixture/冻结 benchmark/人工标签。无 Scanner 网络、Runtime 模型、目标构建或 Secret rotation；仅官方文档/GitHub授权交付联网。Enterprise Gate/Capability-Entitlement/Plus-Pro/PreToolUse enforcement、其它 Host/新 rule/Windows backend、Deep Audit/Joern/DAST/watcher 均继续 Planned，完成本轮后停止。

### 本轮决策

1. Stop 为可靠性兜底，保留原 PostToolUse 主流程与 command transport。
2. Runtime state 是事实来源，Host action/文字不能授权；仅 POLICY_AUTO 的原 handoff，排除整条 confirmation 授权路线。
3. 原 token 不持久化，不重新签发、不续期；连接丢失宁可允许 Stop，不恢复 authority。
4. 独立 continuation 上限2；官方 stop_hook_active 不是安全身份，不可用 false 重置预算。prepare 成功即结束本阶段。
5. 不把 local SDK/clean/native forced fallback 当作模型行为证明；新的 Desktop trial Pending。

以下章节为历史记录，最新状态以本节和 AT 为准。

## Codex Integration Productization v0.2 / Cold-start Readiness v0.3（2026-10-04）

Implementation e68cff74c97a0a7a45df2381015b5906b072a82f 已推送；本轮四类新 CI **PENDING_RERUN_AFTER_ACCOUNT_RECOVERY**，9 jobs 无 Runner/steps，实际 annotations 均为账户付款/支出限额阻止启动，不是代码 PASS 或已运行的代码失败。未改账户、workflow门槛或安全契约，四平台未执行。新 runs 见 AS.5。Windows native 已从该已提交 implementation HEAD 重建并完成实际本地 MCP/lifecycle验收，68.66s，version.json source_commit与实现HEAD一致。最终docs HEAD按PROJECT_STATE的git log核对，docs-only新CI在最终交付消息独立核实。

干净起点 feature/runtime-mvp / 022f402a7ade0ed0cf6bbfce50dccd04ed5920a1。最新用户真实 Desktop 回传：MCP Hook/equivalence、CONFIRM 主动询问/批准/拒绝、AUTO 无错误许可问题→prepare→宿主最小修复→Hook resolved1→Runtime 内部 TaskFixService.verify SCANNER_VERIFIED_RESOLVED→functional prepare 无 verifier NOT_AVAILABLE/SECURITY_VERIFIED_FUNCTION_UNKNOWN，均 **USER_REPORTED PASS**。未报告显式 verify_task_fix 或 functional run，不补写已执行。AR 的旧失败/Pending 保留历史语义，由本节最新回传覆盖当前判断。

本轮只交付 Codex 自有项目 setup/status/repair/remove、readiness/诊断及既有复核协议去重。Runtime 0.3.1 / developer-guidance-v0.3 保持，features 新增 codex_integration v0.2 / cold_start_readiness v0.3。新 **fresh Desktop cold-start PENDING_ACTUAL_DESKTOP**；未在当前聊天伪造真实启动派发。source SDK/clean/native 模拟宿主编辑不代替 Desktop。

新增 focused **59 passed**；定向 **438 passed /420.09s**，最后三项 readiness 状态/恢复由 focused 与 final full 覆盖。最终完整离线 **894 passed, 6 skipped, 6 subtests passed in 514.48s (0:08:34)**，六项 skipped 单列。wheel/sdist/七模块逐字节完整性/package/compliance/严格离线 clean（无 editable/system site，117 cached wheels）/Windows native **PASS**。实际本地 MCP + Semgrep/Gitleaks 合成冷启动不调用 get_runtime_info、不重复显式 verify，无 verifier 时不调用 functional run。门禁见 [AS 验收](AI_TRIAGE_ACCEPTANCE.md#as-codex-integration-productization-v02--cold-start-readiness-v03)、[证据](codex-product-acceptance.json)、[用户命令与 fresh trial](CODEX_INTEGRATION.md)。新 CI 推送后按实际 jobs/steps/annotations 核对，未预写通过。

### 本轮决策

1. Core唯一实现保留，只增加可替换Host lifecycle adapter，不扩Cursor或enforcement。
2. 官方required=true用于自动初始化前提，SessionStart MCP只作观察，不是启动器或派发顺序保证。无command fallback热身，无最终用户安全prompt前置条件；真实Desktop Pending独立。
3. 不采用PATH-old Runtime、不猜schema，不用exact tool count。新配置signedfingerprints ownership才可修改/删除；用户同名/manual POC无法证明时failclosed。
4. 旧command只有旧生成器完整三events精确匹配与Git本地exclude provenance一起成立才迁移；command子串/statusMessage单独不是ownership。保留疑似用户Hook并报POTENTIAL_DUPLICATE_HOOK；command实现与测试保留。
5. 幂等不重写正确配置；repair deterministic merge，不删光重装；remove不删DB/源码/其他Hook-server。保留用户mode，不为setup写remediationconfig。
6. Matched CLOSED/scanner-resolution receipt可跳过重复explicitverify；不是新授权能力。functionalprepare仍验证原signedgrant/source/snapshot/policy。No findings、delta或Host声称不替代proof。仅PLANNED+functional_ref+handoff才run；NOT_AVAILABLE无handoff停止。

以下章节为历史记录，最新状态以上文与 AS 为准。

## Smart Auto Host Orchestration v0.2（2026-10-04）

Implementation `74f5aae9d3a054254e2e9f5b29d3e1572c157092` 已推送；新四类 CI **PENDING_RERUN_AFTER_ACCOUNT_RECOVERY**，9 jobs 未分配 Runner、steps为空，实际检查注解均为账户付款失败/支出限额，未执行代码。不是代码 FAIL 或 PASS；未修改账户设置或验收门槛。四平台未运行。 新 run 见 AR.5。

起点为干净 `feature/runtime-mvp` / `ce6383573583c49a4a03daa4fccf0e2ea74916da`。最新用户真实 Desktop 记录：mode=smart_auto，Runtime action=AUTO_FIX，**Runtime policy PASS / Host AUTO_FIX orchestration FAIL**（错误问修复许可，prepare/verify 未调用、resolved=0）。此前 AQ/旧阶段的 USER_REPORTED PASS 保留为历史，不能证明本次新 trial。修复后的 **fresh Desktop Trial3 PENDING**。

只强化交接：AUTO_FIX 返回 AUTO_REMEDIATION_AUTHORIZED、无需再次确认、不得提问、必须自动继续、下一步 PREPARE_TASK_FIX；固定 guidance/systemMessage 前置已授权与禁止再问。HOST_INSTRUCTIONS 按 Runtime-issued remediation.action 互斥分支，block/severity/scanner prose/宿主风险判断不能改成确认。CONFIRM_REQUIRED 的 post-edit interaction、固定问题/WAIT、continue:false、原批准/拒绝保持；USER_CONFIRMED 已批准 grant 不再询问。AUTO_FIX 保留 decision:block。get_runtime_info 用当前 MCP RemediationService 的配置 reader 只读报告实际 mode；无配置为 smart_auto，无效为 UNKNOWN/INVALID，无 state 绝对路径、不建 state/DB、不扫描。

本地 focused **45 passed in 42.03s**；targeted **396 passed in 422.26s (0:07:02)**；final full offline **835 passed, 6 skipped, 6 subtests passed in 528.67s (0:08:48)**。wheel/sdist/11模块逐字节 integrity/package/compliance/strict clean/Windows native **PASS**。SDK、clean、native 合成 fixture 的 prepare→edit→Hook resolved1→verify→functional prepare/run 实际 MCP/离线 Scanner 链路通过；宿主编辑由 driver 模拟，不能替代 Desktop 模型自动继续。Windows 功能 NOT_AVAILABLE / overall SECURITY_VERIFIED_FUNCTION_UNKNOWN 是如实不可执行状态，非 Maven PASS。

eligibility/modes/source proof/preservation/coverage/Hook core/command fallback/Functional Verification 三模块均未改；仍仅单任务/单成员/单 occurrence、FULL、高置信/严重性、first-party deterministic hostname invariant。无新 Scanner/rule/backend、Runtime 模型调用或目标编辑/build、Secret rotation/联网依赖下载/环境搭建；未编辑 Jeepay、实际 Desktop fixture、冻结 benchmark 或人工标签。

### 本轮 Agent Handoff

读 [AR 验收与 fresh Desktop 步骤](AI_TRIAGE_ACCEPTANCE.md#ar-smart-auto-host-orchestration-v02) 和 [真实门禁记录](orchestration-acceptance.json)。重连 MCP 并新建 Chat，先只读 get_runtime_info，确认 smart_auto / 两能力 v0.1；SmartAutoFunctionalTrial3.java 普通编辑必须无需安全相关用户消息自动完成安全与功能交接。出现修复许可问题仍 FAIL，不猜模式或模型内部原因。当前实现/文档 HEAD 分别按 remediation.py、PROJECT_STATE.md 的 git log 核对；新 CI 在推送后按实际 run 验证，禁止预写 PASS。

真实 Maven A/B/Linux hardened execution **PENDING_ENVIRONMENT_PREREQUISITES**；fresh Desktop 自动继续 **PENDING**；三位试用 PENDING、Ground Truth UNREVIEWED/null、质量 NOT_MEASURED。Enterprise Enforcement、其它 Host/漏洞类型/Scanner/policy、自动失败测试修复、Joern/Deep Audit/watcher 等保持 Planned，完成本轮交付后停止。

以下章节为历史记录，最新状态以上文及 AR 为准。

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

### ADR-021：确认反馈与短期授权

用户的普通开发请求不能隐式批准 ask_before_fix。使用官方 PostToolUse feedback 让宿主主动询问；显式 boolean host report 不是独立人类认证。一次性 pending identity 与 approved grant 分离，模式不改成 smart_auto；状态/配置 revision 或连接变化撤销。拒绝不 suppression、不反复询问；失效要求刷新，不复活旧 grant。当前仍只实现 narrow local JDK hostname repair，不增加新 intrinsic confirmation 分类。


## Smart Auto Remediation v0.1 — 当前交接（2026-10-03）

本轮 implementation HEAD `462633e8b5d4dcc730dba868bd9ac66e8bc40b37` 已推送，Runtime tests、Package integrity、Compliance、Standalone artifacts 四类实际新CI全 success；后者四平台均执行新增离线自动修复 MCP 验收（宿主编辑仍模拟，Desktop trial Pending），具体链接见 AM.1。最终 docs HEAD 用 git log -1 --format=%H -- docs/PROJECT_STATE.md 核对。

本轮从 `feature/runtime-mvp` / `3d6611d7e94d80e9804ee526c6d35b809ca69c20`、干净工作区继续；现有 Hook/command/MCP 实现保留。上一轮 Codex Desktop MCP Hook POC 的自动触发、baseline/NEW/PERSISTING/multiset/RESOLVED 由用户在本轮明确报告真实 PASS，来源 **USER_REPORTED**；下方历史 POC Pending 是当时状态，不覆盖这项新反馈。本轮 **same-turn Smart Auto Remediation Desktop trial 仍 PENDING**，不得把 SDK 模拟宿主编辑当成新宿主 PASS。

独立 RemediationPolicy/Service 仅 allowlist `ai-security.java.trust-all-hostname` 的明确局部 JDK HTTPS inline installation。Runtime 发 AUTO_FIX grant，宿主沿现有 prepare_task_fix → edit → 自动 Hook/VerificationService → verify_task_fix；Runtime 不编辑源码、不调用宿主模型。用户级 smart_auto 默认，ask_before_fix/report_only 可选；两次尝试上限、HMAC/OS lock/有界 metadata、原 task_ref 和额外 grant 绑定、保留性证明防删除/抑制/移动/配置规避。已有 REVIEW/STALE/FAILED 与 Raw/risk/coverage 不提升或改写，本地 TLS 不变量的独立 ACTIONABLE repair policy 不证明生产可达性。

最终源码离线回归 **651 passed / 6 skipped / 6 subtests passed，260.36 秒**（新测试50项）；旧阶段已交付 baseline 601/6/6。六项 skipped 单列为 tests/test_e2e_real.py 的三引擎 PATH 前提，未计为通过。实际 SDK、严格 clean-wheel venv、Windows native MCP/离线 Semgrep/Gitleaks 修复验证通过；模拟宿主编辑、原引擎子进程实际执行。wheel/sdist/package integrity/licenses/notices 通过。本轮四类新 CI 需以 AM 的具体 run/结论为准，不能引用历史 CI 为当前通过。

包版本0.3.1、developer-guidance-v0.3 保持，新增 optional smart_auto_remediation v0.1。说明、真实 schema、模式命令、预算/连接中断/cooldown 限制、实机步骤见 [Smart Auto 文档](SMART_AUTO_REMEDIATION.md) 和 [AM 验收](AI_TRIAGE_ACCEPTANCE.md#am-smart-auto-remediation-v01)。现有 fixture 用户改动未覆盖；command hook 保留，不迁移 SessionStart/Stop 或其他 Host。

后续 Deep Audit、watcher/daemon、MCP/Skill Security、Joern、自动构建、自动依赖升级、Secret rotation、业务/IAM/IaC 自动修改未开始，继续 Planned。三位试用 Pending；独立 ground truth UNREVIEWED/null，质量 NOT_MEASURED；Jeepay、冻结 benchmark、人工标签原状。完成本轮提交/推送/验收记录后停止，不开始下一阶段。

### Smart Auto v0.1 决策

- 一个确定 JDK hostname bypass 的显式修复 allowlist，不扩展 scanner/policy DSL/Host 通用框架。
- 未审阅 NEW 在本地类型/安装位置/保留性均可核对时由独立 remediation policy 标 ACTIONABLE（source 明示），绝不伪造 AI review 或生产 exploitability；已有 REVIEW 优先，STALE/FAILED 不自动提升。
- AUTO_FIX 通过官方 PostToolUse decision:block 返回反馈，不撤销编辑；Code mode promise rejection 与宿主自动继续是独立实机门槛。NONE/BEST_PRACTICE 静默，失败或上限 ESCALATE 不再次 block。
- 两次 Runtime 授权计数；原 coverage contract 加保留性证明，两者缺一即 INCONCLUSIVE。连接重启牺牲自动推进，保留只读准备与安全预算。
- 保留 default cooldown；first-edit baseline 不当 NEW，DEBOUNCED 不声称已执行。没有后台补扫定时器/Stop 全量迁移。
- capability contract 不强行 bump；新增 feature metadata，Desktop 自动修复 gate Pending，Runtime 自动 patch 仍 NOT_IMPLEMENTED。


## ADR-019 — Codex MCP transport POC（Accepted / Host trial Pending）

2026-10-03按用户授权，只增加PostToolUse的MCP transport，复用唯一HookCoordinator和原Codex事件翻译/输出，不移除command hook。原因是用户报告Windows command Host runner错误0x80131506；协议替代验证与真实Host修复是不同结论。

采用[官方Hooks schema](https://learn.chatgpt.com/docs/hooks)的mcp_tool/server/tool/input/timeout/statusMessage及${hook_event_name}/${cwd}/${session_id}/${tool_name}。turn_id虽在官方PostToolUse输入中存在，现有核心不需要它，本轮不接收；不转发源码/工具输出/模型/transcript。MCP声明不可信，服务端workspace绑定必需，missing/invalid/foreign claims不能扫描或换workspace。JSON生成是可回滚、显式启用的POC，不自动安装或批准trust。

返回受限metadata/count与官方advisory输出；不阻断、不提高优先级、不定义新的risk/coverage。SDK错误拒绝未知字段并隐藏输入值；原预算、脱敏、快照、多重集及离线边界不变。注册工具数可增加，连接兼容性继续按required subset，不能硬编码13。fresh Desktop自动调用及systemMessage消费必须独立实测；当前只证明SDK stdio与本地Scanner，不把它写成Host通过。

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


更新：2026-10-02。既有验收快照 `3d773aa`；本轮继续核查起始 `feature/runtime-mvp` / `50a01e6870d78e6fd8a96a8b8fbe236521c5306f`。用户已分别授权入口与继续核查 v0.1。Accepted 表示决策已确立，各项仍区分 Implemented / Planned，修复与验证 v0.1 已实现，独立质量工作未实施。

恢复入口：[PROJECT_STATE](PROJECT_STATE.md)；实现事实：[ARCHITECTURE](ARCHITECTURE.md)；后续规划：[NEXT_STAGE](NEXT_STAGE.md)。

## ADR-001 — Capability > Scanner

**Status：Accepted / Implemented。**

用户需要知道代码、Secret、依赖和 IaC 哪项检查完成，而不是某个引擎是否 exit 0。Scanner 是可替换 provider，Capability 是产品契约。`ScannerPlanner` 按能力与 scope 选择 adapter；ScannerRun 保留 provider 身份、角色、执行与覆盖数据，最终 capability 独立聚合。

Trivy 分成 vuln 与 misconfig 两项，Gitleaks 独立提供 Secret，OSV 只在允许的依赖失败后回退。SUCCESS/PARTIAL 不能提升依赖为 EXECUTED；SUCCESS/FULL 可以满足契约，同时保留 primary 的失败历史。理由是避免一个 provider 的失败污染无关能力，以及把“进程成功”误当“完整检查”。

依据：[capabilities.py](../src/security_runtime/capabilities.py)、[planner.py](../src/security_runtime/planner.py)、[dependency_fallback.py](../src/security_runtime/dependency_fallback.py)、[OSV 验收](OSV_DEPENDENCY_FALLBACK.md)。

## ADR-002 — Raw Finding 与 TriageRecord 分离

**Status：Accepted / Implemented；数据库级不可变审计未实现。**

Raw Finding 保存归一化后的 scanner 候选及原 severity/confidence/source；TriageRecord 保存独立审阅结论、证据引用、未知前提、provider/prompt/context 与 Runtime priority。scan、triage、fix、verify 各自有不同证据含义。

SQLite 通过加法新增 triage_records/cache index 兼容旧数据库，不搬移已有 state，不由模型覆盖扫描记录。保留原 scan JSON 使人工能回看分析基础。现有 scans/findings 仍用 INSERT OR REPLACE；“Triage 不改 Raw”是当前路径的行为，不等于整个数据库已经 immutable 或完整保留每次 finding lookup 的 occurrence。

依据：[models.py](../src/security_runtime/models.py)、[triage_models.py](../src/security_runtime/triage_models.py)、[storage.py](../src/security_runtime/storage.py)、[AI_TRIAGE_ACCEPTANCE](AI_TRIAGE_ACCEPTANCE.md)。

## ADR-003 — AI 不删除 Raw Finding

**Status：Accepted / Implemented。**

模型可能证据不足或受注入影响，输出不能成为销毁候选的权限。`SUPPRESSED` 仅表示独立 Triage 显示优先级；get_findings 仍返回每个原候选的 agent projection，CLI `triage --raw` 可以查看 Raw。模型不决定 hide/block，也不能降低原 scan release_status。

保留未验证、失败与过期项；没有 triage 不意味着没有风险。Jeepay 115 Raw 全保留，26 triaged、89 UNTRIAGED、0 SUPPRESSED。

依据：[triage.py](../src/security_runtime/triage.py)、[mcp_server.py](../src/security_runtime/mcp_server.py)、[cli.py](../src/security_runtime/cli.py)。

## ADR-004 — FALSE_POSITIVE 必须有高证据门槛

**Status：Accepted / Implemented；更多自动反证类型未实现。**

错误确认的候选还能进入人工复核，错误压制可能使真实风险被忽视，因此 FALSE_POSITIVE 比 CONFIRMED/LIKELY 使用更严格标准。有效引用、HIGH confidence、明确可核验反证及无未知前提缺一不可；模型理由、doc/test/example 位置或“没搜到 API”不能证明误报。

v0.1 的确定性反证只有严格完整赋值中的固定 placeholder 字面量；引用必须覆盖该反证。门槛不满足时 Runtime 降为 NEEDS_REVIEW。UNLIKELY 仅 LOWER_PRIORITY，不等价 FALSE_POSITIVE。真实 Jeepay 没有足够的误报反证，0 SUPPRESSED 也不能被解释为已测得零误压制率。

依据：[EvidenceBuilder](../src/security_runtime/triage_evidence.py)、[TriagePolicy](../src/security_runtime/triage.py)、[Triage tests](../tests/triage/test_triage.py)。

## ADR-005 — Finding Secret 不发送给模型

**Status：Accepted / Implemented 的出口保护；不宣称任意未知 Secret 的完整保证。**

Triage 验证 Secret 的位置、用途和结构，不使用明文值猜测有效性，不主动探测线上凭证。Gitleaks 原层脱敏，EvidenceBuilder 对已识别 Secret 匹配行整行遮盖，并保守清理相邻字面量/长 token；返回文本保存前再脱敏，错误不保存 body/request。API key 值只从指定环境读取，用于用户配置 endpoint 的 Authorization，不写入 packet、record 或日志。

脱敏后的内容仍需反映原值变化以使 cache 失效，因此使用本地随机 HMAC key 的 opaque revision，而不发送可猜测 Secret 的普通明文 hash。权限保护受操作系统约束；同用户账户已被控制及任意未识别敏感数据仍是限制。

依据：[triage_evidence.py](../src/security_runtime/triage_evidence.py)、[triage_providers.py](../src/security_runtime/triage_providers.py)、[storage.py](../src/security_runtime/storage.py)。

## ADR-006 — External AI 必须显式授权

**Status：Accepted / Implemented；细粒度持久授权票据未实现。**

普通 scan 不调用模型；配置 provider 不意味着同意外传代码。BYOK 每次显式调用须带 `--allow-external-code-context`，CI/非交互相同。URL 限制、HTTPS、禁止 redirect、预算和 offline 拒绝外部模型共同控制上传。

Agent-native 将脱敏 packet 交给宿主，但 Runtime 不调用其模型。`is_external=False` 只描述 Runtime 的网络调用角色，不证明宿主模型在本地；宿主应依自己的授权和数据策略处理。公开仓库、曾授权依赖元数据查询或历史模型运行，都不能自动扩展成任意源码上传授权。

依据：[triage_providers.py](../src/security_runtime/triage_providers.py)、[cli.py](../src/security_runtime/cli.py)、[native BYOK evidence](triage-native-byok-evidence.json)。

## ADR-007 — Scan Coverage != Triage Coverage

**Status：Accepted / Implemented。**

Scan coverage 回答本次计划中的规则、文件、能力/库存检查执行程度。Triage coverage 回答候选中多少已有有效独立审阅，以及 actionable/review/lower/suppressed/failed/stale/untriaged 数量。前者不证明没有漏洞；后者不补齐未执行规则或未解析依赖。

两套字段分别返回。只 triage 26 项不能把 115 Raw 算作全验证，也不能把 Jeepay Dependency PARTIAL 改成 FULL。当前 IaC 不 eligible，仍计入总 Raw 与未审阅项；FAILED/STALE 与单纯 UNTRIAGED 分开报告。

依据：[rule_coverage.py](../src/security_runtime/rule_coverage.py)、[runtime.py](../src/security_runtime/runtime.py)、[triage.py](../src/security_runtime/triage.py)。

## ADR-008 — Dependency bounded evidence 不证明 reachability

**Status：Accepted / Implemented。**

Package/version/advisory 命中只建立 scanner 候选。有限 manifest、词法引用或“未找到受影响 API”不能证明实际调用、动态加载、运行条件或不存在攻击路径。POM 仅精确直接声明匹配可标 DIRECT，其它 UNKNOWN；旧 capture 缺失的 ranges/fixed version 不编造补齐。

v0.1 把依赖 CONFIRMED/LIKELY exploitability 限为 CONDITIONAL，并保留未知前提；同 package/version/ecosystem/manifest 分组减少重复上下文，原 advisory 全部可展开。OSV SUCCESS 与完整 Maven parent/property/传递/test 依赖图仍是两回事。

依据：[osv.py](../src/security_runtime/osv.py)、[triage_evidence.py](../src/security_runtime/triage_evidence.py)、[triage.py](../src/security_runtime/triage.py)。

## ADR-009 — Runtime policy 决定优先级，LLM 不决定 hide/block

**Status：Accepted / Implemented。**

模型提交受 schema 限制的 verdict/confidence/exploitability/引用/理由/前提，Runtime 检查 identity、hash、引用范围，再由 TriagePolicy 产生 ACTIONABLE / REVIEW / LOWER_PRIORITY / SUPPRESSED。Raw release policy 继续由 RiskEngine 决定；Triage 不自动解禁 BLOCKED。

代码、注释、README、config、Skill、scanner 内容均为 UNTRUSTED_CODE；模型无 Runtime 授予的任意 shell/network/environment/tool execution。Structured output 与合法引用只能证明格式和出处满足约束，不能代替结论的人工语义核验。

依据：[triage_models.py](../src/security_runtime/triage_models.py)、[triage.py](../src/security_runtime/triage.py)、[risk.py](../src/security_runtime/risk.py)。

## ADR-010 — 不自动执行目标项目构建 / 安装

**Status：Accepted / Implemented。**

默认扫描/triage 不执行被扫项目 Maven、Gradle、npm、pip、go 构建或应用代码，不自动修改 mirror/settings。目标源码、配置、manifest 和构建脚本是输入，不是执行指令。采用验证后的 scope、快照、参数数组和限长进程控制；明确接受由此产生的图/上下文不完整。

Runtime 自身安装 scanner engine/规则与目标项目构建不同。当前进程管理不是 OS sandbox，插件是受信任 Python 代码；不能因此承诺任意恶意 scanner/plugin 均被隔离。

依据：[scanners.py](../src/security_runtime/scanners.py)、[osv.py](../src/security_runtime/osv.py)、[processes.py](../src/security_runtime/processes.py)、[toolchain.py](../src/security_runtime/toolchain.py)。

## ADR-011 — Joern / compiler-grade dataflow 尚未实现

**Status：Accepted 的延后决策；实现为 Planned / Deferred。**

现有 Java 是规则 search/taint + bounded evidence；没有 Joern CPG、完整跨文件 source-to-sink 或依赖 reachability。不能把词法引用升级成编译器级结论。

下一阶段为 AI Triage Quality Validation & Developer Guidance；独立 Ground Truth 仍是质量工作核心，产品先迭代开发者任务入口。26 条 Coding Agent 审阅及脚本回放不是独立人工真值；应先识别当前误判、模型差异与 suppression risk。只有质量基线和回归门槛建立后，才为确有证据缺口的 Java 场景规划独立、受限、可测的 Joern PoC；不默认执行目标构建，也不对无路径结果宣布不可达。

依据：[JAVA_RULES_ACCEPTANCE](JAVA_RULES_ACCEPTANCE.md)、[AI_TRIAGE_ACCEPTANCE](AI_TRIAGE_ACCEPTANCE.md)、[NEXT_STAGE](NEXT_STAGE.md)。

## ADR-012 — 质量结论必须有独立来源与明确分母

**Status：Accepted 的下一阶段原则；验证流程尚未实施。**

编码 Agent 的审阅、mock/loopback、合成参考样本与独立人工 adjudicated ground truth 有不同用途。当前真实 Jeepay human_label/reviewer 均未填写；invalid output=0、26 cache hits、382 tests passed 证明协议/实现验收，不证明 triage precision、模型 agreement 或漏报率。

后续报告应记录样本冻结身份、人工盲审/分歧、provider/model/prompt/policy/run provenance、未判定/失败/过期项及各指标分母。没有人工真值或有效分母时报告 UNKNOWN / NOT_MEASURED / N/A，不能填 0 或“99%”。模型不得给自己的输出盖人工确认章。

依据：[jeepay-human-ground-truth.json](jeepay-human-ground-truth.json)、[benchmark replay](../scripts/jeepay_triage_benchmark.py)、[NEXT_STAGE](NEXT_STAGE.md)。

## ADR-013 — 任务引导与风险判定分开

**Status：Accepted / 开发者任务入口 Implemented；三位真实开发者易用性验收 Pending；继续核查 Implemented；Fix & Verify v0.1 Implemented / 宿主 UX Pending。**

面向普通开发者的默认结果应回答“先做什么、为什么、下一步如何推进”。相关候选可投影成一个任务，保留原 Finding/Advisory、证据和状态的完整访问；普通/详细视图共享同一结果，不靠隐藏未完成检查制造安全印象。首轮最多展示三个推荐跟进任务，并提供完整列表入口。

建议跟进动作与 Runtime priority 是不同字段：所有结果为 REVIEW 时，可以推荐先“核查 TLS 影响”，但不能改成 ACTIONABLE、删除 Raw 或降低 release_status。VALID 应表达为“已完成 AI 审阅”，而非人工验证、复现或确定线上可利用。优先级策略如需变化，另以人工基准和独立回归证据决策；不会为匹配历史分布调整结论。

已实现 summary/get_security_summary：只在明确/绑定 workspace 内定位最近或指定扫描，不取全局最近记录；SQLite mode=ro 与不持久化 freshness 投影，不创建/迁移 DB、生成 key 或记录 telemetry。MCP 延后初始化可写 Runtime，纯汇总连接无写入。无扫描给出建议，不执行。TLS 仅明确互补规则、同文件相距最多 40 行成对；该展示规则不证明共享调用链。依赖组保留全部 advisory/state，缺身份字段不合并。继续核查沿用原授权原则已实现；修复与验证 v0.1 已实现，实际宿主 UX Pending；三位试用者目前无法安排，Pending 如实保留。

理由：当前工程验收输出要求用户理解内部枚举并编写多轮提示词，增加决策负担。可执行任务应减少用户负担，同时保持证据、未知条件和风险政策的真实含义。易用性试用与安全质量分别验收。

依据：[当前展示](../src/security_runtime/human.py)、[当前 MCP](../src/security_runtime/mcp_server.py)、[PROJECT_STATE](PROJECT_STATE.md) 的用户报告与 [NEXT_STAGE](NEXT_STAGE.md) 的已批准范围。

## ADR-014 — 证据来源与核查范围显式区分

**Status：Accepted；引用/hash 校验与任务来源分层 Implemented；宿主补充报告导入契约 Planned。**

扫描器候选、Runtime 接受的 AI 审阅、宿主额外源码核查和独立人工判断具有不同证据含义。结构/引用合法不证明语义正确；静态业务调用不证明生产启用；有限依赖与词法证据不证明完整图或 reachability。展示时保留来源和未知条件，不把一种分析升级为另一种确认。

用户提供的 Jeepay 实际宿主 MCP 运行与已提交脚本回放使用不同 scan identity，分别记录，不覆盖原验收或要求匹配 verdict/priority。宿主后来读取完整调用链的报告没有作为新的 Triage packet/hash/refs 提交，不能伪装成 Runtime 已接受结论，也不能补齐 scan coverage。当前没有通用宿主补充报告导入接口，未固化 revision/artifact 的聊天报告仅作为带来源的产品输入。

理由：跨设备和跨聊天需要知道事实来自哪次运行、哪些核查尚未实施。模型审阅、宿主分析和人工真值混在一起会掩盖证据缺口，并污染质量指标。

依据：[EvidenceBuilder](../src/security_runtime/triage_evidence.py)、[TriageService](../src/security_runtime/triage.py)、[PROJECT_STATE](PROJECT_STATE.md)、[NEXT_STAGE](NEXT_STAGE.md)。

## Approved / Planned 与其它尚未实现事项

开发者任务入口与继续核查已获明确授权并实现；全部独立质量工作（版本化 ground truth、人工盲审、多模型、指标、prompt/model regression 和后置 Joern）继续在 NEXT_STAGE Planned。本轮不因展示易读而宣布人工易用性或风险质量已验证。

数据库 retention/完整审计、更多自动反证、IaC AI validation、云端多租户及主动审计也没有实现；它们不属于本轮已批准产品迭代的默认开发任务。

变更这些决策时，应新增或明确 supersede ADR，写出原因、证据和行为变化；历史验收按原时点保留，不用聊天记录取代持久化决策。


## ADR-015 — 精确任务引用与受限继续核查

**Status：Accepted / Implemented；不替代原风险策略。**

T01 为响应内的展示序号，不能作为跨请求 identity。summary 的 task_ref 绑定 workspace/固定 scan/topic/精确成员与规范化身份，状态排序或审阅推进不换对象；成员或任务身份改变、scan 移除、格式/版本无效要求刷新重新选择，不回退当前第一项或最新 scan。引用非权限凭据，仍需绑定/明确 workspace、提交时的 task identity/session/hash/ref 校验；源码 freshness 由 HMAC packet hash 独立判断。

任务入口复用 prepare_triage 的 EvidenceBuilder/schema/instructions/缓存，再沿原 submit_triage 接受宿主分析；Runtime 不主动调用宿主模型。VALID 保留，UNTRIAGED 优先，STALE 重建，FAILED 默认单列显式重试；缓存不占新分析名额，工作/输出预算单独有界。已有证据不重复劳动，业务问题仅是与已记录未知相关的候选，宿主先核对受限证据再询问。范围外条件保留未知，不升 priority、不补完整图或任意 host evidence。

理由：用户说“继续第一项”时不应寻找 Finding UUID，也不应因排序/缓存命中继续了别的任务或反复同一批。既有审阅和 Raw 保留，修复与验证仍是下一轮独立任务。

依据：[task_triage.py](../src/security_runtime/task_triage.py)、[security_summary.py](../src/security_runtime/security_summary.py)、[triage.py](../src/security_runtime/triage.py)、[NEXT_STAGE](NEXT_STAGE.md) 与本轮验收附录。


## ADR-016 — Hook Delta 必须复用 Fix & Verify 稳定身份

**Status：Accepted；以下 PREREQUISITE_MISSING 为2026-10-02历史记录，前置已交付，本轮Hook依据ADR-018实现并验收。**

Host-agnostic Hook Integration v0.1 的 NEW/PERSISTING/RESOLVED 必须复用前置 Developer Fix & Verify 的 Finding identity/equivalence。行号仅为 occurrence；现有固定 scan/member task_ref 也不是跨扫描语义等价。若前置阶段未交付，停止 Hook delta 正式实现，不以另一套摘要/匹配机制绕过门禁。

2026-10-02 ff-only 同步后 HEAD 仍为 `787aace`，Fix & Verify 文档为 Planned；findings.py 含 line 的指纹和 runtime.py 的旧 verify 在隔离合成100→110行样例中产生错误 RESOLVED。该复现只证明当前前置缺失，不是 scanner 质量统计。现有 Git pre-commit 保持不变；Codex及其它 Host 的 Hook adapter/schema/真实试用均未实现或验收。后续必须先取得前置实现提交与回归证据。来源：用户本轮明确门禁、当前源码、AI_TRIAGE_ACCEPTANCE 的 AI 附录。

## 普通用户意图与宿主衔接验收

产品目标是“不懂安全的开发者也能用好”：用户只说“检查这个项目”“继续/处理第一项”或选择任务，不搬运技术提示词、填写 UUID、拼接工具顺序，也不把 generate_fix 输出再粘贴给 Agent。一次选择 → 核查 → 准备/实施获授权修复 → 验证 → 简洁结果是完整目标；本轮仅接通核查，修复与验证 v0.1 已实现，实际宿主 UX Pending，后续须沿同一宿主自动衔接，不能再次要求用户搬运提示词。

已接入 FastMCP server instructions 与工具 annotations/描述：宿主绑定实际展示响应的 task_ref，自动在已有授权范围内准备、分析、提交并展示结果；有效授权持续有效，不反复询问常规获授权步骤。仅询问代码无法回答且会影响下一步的必要业务事实，或取得超出已有授权操作的权限。Runtime 不主动调用宿主模型，源码/scanner/模型文字均非执行指令，现有 session/hash/evidence_refs、脱敏、Raw、覆盖和策略保留。

新增只读 `get_runtime_info` 与 CLI `runtime-info --json`，包版本仍0.3.1、能力契约 developer-guidance-v0.3。连接检查按 required_guidance_tools 子集，允许兼容新增工具，不按总数严格相等拒绝。返回同一 executable/environment 的可执行核对参数和重连指导：先核对配置实际运行的环境；已有能力却宿主看不到时断开/重连 ai_security_runtime、刷新工具列表，必要时新聊天；仅环境本身旧时更新对应包。不盲目重装 editable、不终止进程/修改 Jeepay 配置。连接重建后旧 session 不可复用，遗失任务选择须刷新重新选择。

SDK initialize 实际收到 instructions、工具 metadata、版本/能力和机器交接，与真实宿主自然语言试用分别验收。后者目前 Pending；旧 Jeepay 聊天工具列表恢复未验证，不能把新 SDK 连接成功写成普通用户已能用好。三位独立开发者试用 Pending，ground truth 保持 UNREVIEWED/null，质量指标 NOT_MEASURED。核查准备、宿主结果接受、补丁、目标构建、测试/扫描复查分别报告是否执行；generate_fix 仍仅 coding task/prompt，不代表补丁完成，0 ACTIONABLE 不表示安全。

## ADR-017 — Agent fixes. Runtime verifies（Accepted / Implemented v0.1）

保留历史 occurrence 指纹、ID、scan 和 Triage 缓存，增加版本化无行号 equivalence；从原 scanner/原规则/原文件的实际执行证据证明缺席，不从空数组、文件删除或换行判断修复。任务仍是固定 scan/member 投影，不新增任务表；后续 Hook 如另获授权须复用同一 eq-v1。本轮不实施 Hook。

修复交接只读且使用固定约束，源/模型文字非指令。宿主承担编辑，Runtime 默认离线复查，不自动下载引擎或数据库、不触发在线 dependency fallback，不构建目标、不调用宿主模型。缓存扫描按 provider/file 复用，成员仍逐条判断；组内任一未知阻止完成声明。无法证明 Gitleaks/IaC 原 detector/check 已执行时缺席保守 INCONCLUSIVE，这是能力边界，不借规则成功进程作充分证明。

宿主执行报告为未验证声明，与 Runtime 观察分离，不影响风险/覆盖、triage、修复状态或生成新的 AI 审阅。明确选中修复意图授权范围内本地修改，超出公网/生产/发布等仍遵守既有授权边界；不以普通用户重复确认替代精确引用。SDK 自动化与真实宿主 UX、独立人工真值分别验收。

本轮实现与分发依据：`1e10b53`；起始 `0f33d26`。Windows 独立包实际 source_commit 与实现一致，SDK 取得13工具及 v0.3 契约，真实 Semgrep 组内仍存在/部分/全部规则复查结果通过；本轮测试、package、compliance 和四平台 standalone CI 均 success，详见 AJ 与 [native/CI 证据](fix-verify-native-evidence.json)。文档最终 HEAD 用 `git log -1 --format=%H -- docs/PROJECT_STATE.md` 获取；代码之后若变化须重新验收。以上为历史 Fix & Verify 交付；当前 Hook 已完成实现与分发验收，真实 UX、三位试用与独立人工质量状态不变。

## ADR-018 — Advisory Hook 家族多重集（Accepted / Implemented v0.1）

Rule/file 覆盖决定能否证明消失；eq-v1 复用为 family key，并保存数量/安全坐标。不能 set-diff 家族后把第二处遗漏，不能把不同行的同家族当唯一 instance，不能在 scanner failure/删除/部分覆盖时 resolved。Secret 只存 detector/path/count/coords，未知缺席保留。Hook quick 使用变更文件完整候选，其前置适用规则规划、Raw历史指纹、风险策略和 MCP 校验保持；不调用模型，不执行构建/补丁或在线解析。

短进程使用跨进程持久冷却/OS lock。首次缺 session baseline 只建立基线；Stop 强制收敛或复用，不启动 watcher。项目 Hook 配置依据当前官方 schema，配置成功不等于 Host触发成功；Codex/Cursor fresh host trial Pending，未验证产品不生成 schema。依据本轮用户明确要求及 AK 证据，ADR-016 的旧 PREREQUISITE_MISSING 仅为历史记录。
