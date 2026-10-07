# AI Security Runtime — Architecture Decisions

## Current milestone — R0, 2026-10-07

R0 Rule Program v1 + Java High-Confidence Pack = IMPLEMENTED / LOCAL VERIFIED
in the uncommitted `feature/runtime-mvp` working tree. This current block
supersedes older roadmap/status entries below; historical evidence is retained.
See [Rule Program](RULE_PROGRAM.md), [coverage matrix](RULE_COVERAGE_MATRIX.md)
and [complete acceptance](rule-program-acceptance.md).

Cursor Host Adapter v1 detection, first-scan attribution, Finding/Policy and
Advisory Remediation = COMPLETE / DESKTOP VERIFIED from the user's observed
Desktop evidence. Native user-visible feedback is
HOST_CAPABILITY_UNAVAILABLE_ON_OBSERVED_PATH (Cursor 3.22.12 afterFileEdit path,
postToolUse NOT OBSERVED); automatic continuation is PENDING_HOST_CAPABILITY.
Do not describe the entire detection Runtime as PARTIAL. Production setup has
sessionStart/afterFileEdit/afterShellExecution/stop only. Signed old probe/fifth
entries migrate safely; custom user entries remain. No new pending feedback
delivery is created by this path; generic presentation storage is dormant.

10 product capabilities: 2 CORE (TLS + Gitleaks Secret), 8 VALIDATED (SQLi,
command injection, SSRF, path traversal, arbitrary read/write, XXE,
deserialization). Java Core Pack v1 and Validated Java Pack v1 are explicitly
separate tiers. VALIDATED detection/guidance is default-on and labelled;
8 retained unrelated legacy Java EXPERIMENTAL rules are default-off. The two
legacy Python rules remain default-on for compatibility. 19 owned Java/XML
Semgrep variants (18 for Java-only files); 29 installed rules including legacy.
No provider-owned Gitleaks rule-count or new automatic fixer is inferred.

Final actual managed corpus: 71 synthetic cases, 46 TP /28 TN /0 FP /0 FN.
These author-declared labels are not independent human or production-grade
ground truth. Findings retain source/sink/basis/location/underlying identity
and explicit limitations. MyBatis interpolation is structural with unknown
parameter trust. Read/write is primary at an overlapping traversal sink.
Capability variants share canonical Family identity; real absence proof must
execute all applicable variants. TLS original bytes/identity, Secret detector
identity, Episode/budget/opaque refs/receipts and Core-vs-Deep boundaries remain.
Historical non-TLS raw-rule identities are not silently migrated or retargeted.

Focused: 306 passed, 6 subtests passed in 460.88s (0:07:40). Full offline: 1783 passed, 9 skipped, 6 subtests passed in 2326.45s (0:38:46); skipped reasons are individually
listed in [regression](rule-program-regression.json). Actual local MCP TLS
inline/envelope/proof/CLOSED and recurrence PASS. Isolated offline wheel
installation and simulated Cursor native command+real Scanner PASS.
Wheel/sdist integrity/compliance PASS; 93 runtime Python modules and formal
rule data byte-equal; manifest/corpus/new tests included and probe code absent.
Fresh R0 Desktop NOT_RUN; historical actual Desktop results remain separate.

No commit/push, active Runtime replacement, actual user `.codex`/Cursor change,
model invocation, target build, dependency download or new scanner. Starting
and current HEAD: `ee1bfd9c12493683cc313cb3628753a51ae124ac`. Prior dirty work preserved by snapshot/diff audit.
Next recommendation is wider labelled OSS/internal FP/FN corpus and independent
review before CORE or automatic-fix graduation; no next implementation stage
has started. Cursor UI/continuation workarounds and new Hosts remain deferred.
Deep/Plus/Maven environment/human trials retain their prior Pending/Planned
state. Capability does not imply execution on the default Hook.

## P0-10.1 Cursor Visible Security Feedback

P0-10.1 uses documented Cursor postToolUse additional_context, not afterFileEdit fictional output or Stop followup. Retain advisory-only/no invocation authority. Presentation recurrence keys reuse existing NEW scan/family; no parallel security Episode model.

See [acceptance](cursor-visible-feedback-acceptance.md) for binding, bounds, privacy, native race evidence and manual UI trial.


## P0-9.6 — Transport capability is not policy authorization

不为 AdvisoryTransportConfig 补假 path。旧 path 是 policy 文件的状态位置与 mtime；Cursor 将不同职责对象注入 config 槽位是接线错误。使用真实用户配置，新增独立 immutable transport contract，从现有 Cursor continuation capability 映射，Core 无 Cursor hardcode。

AUTO_FIX decision 在 advisory-only Host 上保持，执行层返回 ADVISE / REMEDIATION_OFFERED，edit_authorized=false，不签发 grant、Ticket、confirmation token 或 continuation handoff。人工/确认 policy 亦保持原判断。优先复用已有 TaskFix resolver/固定安全计划，避免制造带自动授权的 Security Fix Context。缺 verified context、stale Finding、无能力或无可用上下文继续 inconclusive。

Cursor native post-edit output 不支持本轮承诺的自动 agent context delivery；保持 schema，只在 Runtime result/recent 明确 offer，不冒充 Desktop 已展示或自动闭环。未来 generic advisory Host 可复用，其他平台实现不在本轮。


## P0-9.5 — Digest-authenticated recovery, not guessed security baseline

保留 SessionStart filesystem-only 设计。HMAC inventory 无法反推出旧源码，本轮不引入源码 vault；仅尝试 Git index/HEAD bounded blob recovery，exact HMAC 证明才使用。标准 checkout LF→CRLF recovery 只有 exact HMAC 命中才成立，扫描的是原字节，BOM 不归一化。旧内容不可恢复是明确能力边界，不能用 HEAD 干净推断旧 snapshot 安全。

仅默认 managed Semgrep 的等价 targeted scan 支持本轮缺陷；unsupported provider/plugin/mixed risk 不做虚假 absence proof。版本号不足以证明同引擎，所以收集现有启动前 probe identity 并核对运行前后、rule pack/config/rule identity；不改 scanner、cache 或 Family schema。

同 rule instance 匹配采用 unchanged-span/line-motion 映射，无法确认旧实例映射时 inconclusive；保留原 family multiset 和 additional_occurrences semantics。不调整 policy 对多个候选的授权，不承诺 Cursor 自动修复闭环。独立 Cursor AdvisoryTransportConfig.path 错误超出冻结范围，记录 BLOCKED_PRE_EXISTING_CURSOR_POLICY_CONFIG_PATH。


## P0-9.4 — Cursor Event Lifecycle + Baseline Ordering

D-P094：轻量 SessionStart comparison baseline 与 scanner coverage 分开；首次 scanner observation 不以未扫描 baseline 伪造 NEW/自动修复授权，沿原 first-scan unattributed safe semantics。Cursor post event 没有可靠 invocation ID；只能用 filesystem comparison + OS single-flight 实现同 snapshot 收敛，不能声称 Host authenticated exactly-once delivery。

D-P094-order：pending arrival 与 snapshot publication 可跨进程观察；capture 期间已有 mutation 到达或文件不稳定即拒绝 attribution。无 Host pre-edit barrier 的迟到事件不能重建历史字节。超时只保留 bounded intent并返回retry，不引入 daemon、Stop补扫描或无限等待。Codex lifecycle保持原兼容，仅新 command transport显式选用该入口。

本轮只修 Cursor normalized lifecycle / baseline publication / 跨进程 ordering；用户最新真实 Desktop 已确认 P0-9.3 claims、anchor、generation、relative roots、file containment 通过，这些代码冻结。Cursor 新 lifecycle 真实 Desktop PENDING_USER_RETEST，不执行新 Desktop E2E。focused 343 passed / 331.23s；完整 offline regression PASS：1687 passed, 9 skipped, 6 subtests passed in 2141.83s (0:35:41)；skipped 单列，不计为通过。 installed native command + managed offline Scanner PASS / 37.76s，临时 venv 借用已有依赖；Codex local MCP + managed offline Scanner 两轮 recurrence PASS / 37.39s（模拟 Host、实际 MCP/Scanner，非 Desktop）。wheel/sdist/integrity/compliance PASS，88 module bytes 对照；最终 docs 后再构建核验。不 commit/push、不改真实 .cursor/.codex、不替换活动 Runtime；前序未提交工作和文档历史保留。详见 [P0-9.4 验收](cursor-event-lifecycle-acceptance.md)。


## P0-9.3 — Cursor workspace anchor compatibility

用户新增真实 Desktop evidence 已定位：workspace_roots shape VALID，但 POSIX 形态在 Windows 非 absolute、无 drive，旧实现先把 event root 当主路由调用严格 resolver，于 PATH_SHAPE/RAW_PATH_NOT_ABSOLUTE 拒绝；部分 sessionStart 合法空列表也曾提前拒绝。这取代 P0-9.2 对历史 raw shape 无法确定的结论。2026-10-07 重新核对 [Cursor 官方 Hooks](https://cursor.com/docs/hooks)：CURSOR_PROJECT_DIR Always Present/workspace root，afterFileEdit file_path absolute。

本轮仅 Cursor ingress：CURSOR_PROJECT_DIR 是 required strict canonical anchor；workspace_roots 仍 required typed/bounded string[]，empty 是 EMPTY_HOST_LIST，single native-relative 是 UNVERIFIED_RELATIVE，仅 metadata，不做 cwd/拼接/猜测/文件探测；single absolute 独立 canonicalize 并必须 MATCHED；multi-root 仍 CURSOR_MULTI_ROOT_UNSUPPORTED。anchor 缺失/invalid、来源冲突、file outside/nested/link、session cross-workspace 全部 fail closed。generation contract / CursorBindings / Core / Codex / scanner / remediation / Ticket / Exact Envelope / installer / shared resolver 不变。

新增闭合 enum/bool diagnostics：cursor_workspace_anchor、cursor_project_dir_valid、workspace_roots_state、workspace_root_relative、workspace_root_corroboration、file_path_absolute、workspace_binding_reason，复用原 prefix absolute/canonicalized/hash 与现有跨进程 bounded recent SQLite；无 raw path/env/root/ID/source/command/input/output/transcript/Secret 持久化。绝对来源冲突的诊断现在分区到已验证 anchor，不向旧 event-root 路由。

新增 25 cases；targeted 124 passed / 80.24 s，focused 254 passed / 261.39 s；full 1672 passed, 9 skipped, 6 subtests passed in 2110.34s (0:35:10)；离线 wheel/sdist/package integrity/compliance PASS。真实 Desktop PENDING_USER_RETEST，本轮不进行新 Desktop E2E；Cursor live continuation 仍 Pending。后续阶段仍 Planned。详情与最终证据见 [P0-9.3 验收](cursor-workspace-anchor-acceptance.md)。不 commit/push，不修改真实 .cursor/.codex，不替换活动 Runtime；前序未提交工作和文档历史保留。


## P0-9.2 — Cursor real SessionStart / workspace resolution

用户新增真实 Desktop 证据明确 sessionStart generation_id 是空字符串、后续 generation 有效；旧 common nonempty 校验因此拒绝 SessionStart。本轮按事件修正：sessionStart 以合法 session_id=conversation_id+workspace 建立 baseline，absent/exact-empty generation 标 NOT_YET_AVAILABLE；wrong type/oversized/control/Unicode/whitespace-only 仍拒绝，post/stop 仍要求有效非空 generation。signed CursorBindings 增加 bounded generation hashes：OBSERVED/UNCHANGED/UPDATED；合法新消息不视为 replay，cross-workspace session 仍拒绝；generation 不是 invocation/authorization。兼容旧三-key state，新 state 的旧 reader 会 fail closed，不与旧活动 Runtime 共享 candidate state。

真实 workspace 旧记录在 WORKSPACE_ROOTS 前 canonical identity 为 null；旧 generic code 对应 raw path admission/directory handling，不能归因于 generation 或 env source comparison。历史 raw path shape 没有留存，精确 predicate 仍 UNDETERMINED_FROM_RETAINED_DIAGNOSTICS。Project F 给定标准 Windows root 的 native/slash/case/trailing/subdir 只读 probe 全部 OK、同 canonical identity、没有 ownership 错误；不等于重构历史 claim。新增 Cursor-only preflight 分 path/filesystem/boundary/Git/shared resolver；先无 safe.directory override 只读 probe，dubious ownership 精确拒绝、不得 fallback，不修改 Git trust；共享 resolver/Git/Core/Codex 不变。event root primary+env independent corroboration，no cwd fallback；FILE_URI 明确 reject，nested/outside/link/session mismatch 保持 fail closed。

新增 safe path-shape/Git/status/step/reason 与 generation observation diagnostics，沿现有跨进程 bounded recent SQLite，不保存 raw path/ID/command/tool_input/source/output/transcript/Git stderr/Secret。新增 37 cases；targeted 124 passed，首轮仅两项新测试 state 属性断言错误已修正；最终 focused 265 passed；full offline PASS：1647 passed / 9 skipped / 6 subtests passed（skipped 单列）；native installed command/Scanner PASS 46.99s、Codex MCP regression PASS 40.18s，结果见 [P0-9.2 验收](cursor-session-workspace-acceptance.md)。package integrity/compliance PASS；真实 Desktop PENDING_USER_RETEST，continuation 原 Pending。无 commit/push/真实 .cursor/.codex 修改/活动 Runtime 替换/新 Desktop E2E；前序未提交与文档历史完整保留，本轮后停止。


## P0-9.1 — Cursor schema / workspace compatibility

Hook delivery 四事件已按用户真实 Desktop 证据 VERIFIED；本轮不重新调查 launcher，不运行新 Desktop E2E。旧代码没有 UUID/hex 校验，也未用 process cwd 做 root：它使用 event workspace_roots 并互证 CURSOR_PROJECT_DIR。原 identity 校验的 `${` 模板限制不适合 native opaque 字符串，已移除；保留非空/原始长度 500/类型/控制字符/Unicode 边界。null workspace_roots 在旧 shape guard 漏判现已 fail closed；0/multi-root 不猜 root。canonical resolver、conversation binding、filesystem digest、Core/Scanner/Policy/Ticket/Envelope/Codex 均不变。

新增安全诊断区分 generation 类型/存在/裁剪长度/原因，root count/shape，workspace source、env corroboration、canonical hashes、resolution stage、file containment。source mismatch / nested file-root mismatch 使用 Cursor 专属 fixed reason；先解析到 root 的拒绝可在该 root diagnostic 分区查询，无注册/扫描/授权。无 raw ID/path/command/edits/source/transcript/secret 持久化。Project F root/src/Java 子目录只读解析同 identity；历史失败行缺少具体 generation/source 元数据，精确真实原因仍 UNDETERMINED_FROM_RETAINED_DIAGNOSTICS，不伪称 UUID/cwd 根因。空 generation 仍拒绝，不绕过 claims。

新增 28 cases；首轮 targeted 112 passed / 74.97s。最终 focused 243 passed；full offline PASS：1610 passed / 9 skipped / 6 subtests passed，skipped 单列，结果见 [验收](cursor-schema-compatibility-acceptance.md)。真实 Desktop compatibility PENDING_NEXT_USER_RETEST，Cursor continuation 保持 Pending；不 commit/push/修改真实 .cursor 或 .codex/替换活动 Runtime。前序成果保留，不扩展后续阶段。


## P0-9 — Cursor Host Adapter v1

P0-7/P0-8 已按用户新增的真实 Codex Desktop TLS 验收封版（USER_REPORTED_DESKTOP_VERIFIED），与本轮 local fixture 分开。P0-9 当前 IMPLEMENTED / LOCAL VERIFIED，真实 Cursor Desktop PENDING。仅四个官方事件：sessionStart / afterFileEdit / afterShellExecution / stop → CursorHostEventAdapter → P0-8 NormalizedHostEvent → 原公共 dispatch / HookCoordinator；不复制 Scanner/Policy/Family/remediation。严格 canonical root/file containment、conversation/root 跨进程绑定、事件专属 claims 保留 fail closed；单本地 root，远程/multi-root 不猜。官方所选事件没有可靠 invocation ID，capability=false，序列仅本地记账；真实 digest / cooldown / single-flight 收敛，不宣称精确 Host replay authentication。SessionStart 复用 bounded real-scanner baseline capture，Host 参数默认 codex 向后兼容，重复启动保留原比较点。

Cursor native command Hook 不具备 Codex MCP 同连接 Ticket continuation；post-edit 无官方 Agent context 输出，Stop followup 本轮不自动启用。复用原 RemediationService report_only 作为 transport 能力上限，不写用户 policy、不授予源码写入；明确 PENDING_CURSOR_CONTINUATION_CAPABILITY，当前不宣称自动 AUTO_FIX/receipt/CLOSED 同等闭环。Codex 本地 MCP TLS 两轮 recurrence 原 Ticket/Envelope/receipt 流程继续 PASS。common capabilities 为有限 bool，Cursor transport 能力为有限 dataclass，capability != timing/authorization。Deep/其他 Host/Scanner/Ticket/新规则未扩展。

Global setup cursor --scope global 生成用户 hooks.json 的 installed absolute Python/venv/frozen command，不植入 repo/src/PYTHONPATH；签名 ownership exact merge，保留用户 command/prompt Hook、未知设置及 MCP bytes，healthy setup/repair 不重写，remove 只删自有内容。Recent 使用既有跨进程 SQLite journal，32/workspace、1024 total，新增闭集 Cursor schema/normalized 字段；不存 raw command/source/output/edits/transcript/secret/token/identity。候选 wheel 临时 venv 的真实 Windows command（带空格路径）+ managed offline Scanner local trial PASS / 40.06s；独立 CLI 查询、普通 delta/same bytes/TLS finding/模拟 Host 手工最小修复复扫/Stop/lifecycle 均通过，非实际 Desktop或自动 continuation。Codex local MCP trial PASS / 36.70s。新增 34 cases；最终 focused 215 passed / 208.65s。完整 offline 回归 PASS：1582 passed / 9 skipped / 6 subtests passed；skipped 单列于 regression artifact。wheel/sdist integrity + compliance PASS，87 module byte 对照；最终文档后已复核包；详见 package artifact。

[官方契约与映射设计](cursor-host-adapter-design.md)，[验收与下一次 Desktop 步骤](cursor-host-adapter-acceptance.md)，[Cursor installed local trial](cursor-host-adapter-local-trial.json)，[Codex regression trial](cursor-host-adapter-codex-trial.json)。前序 453 incoming 文件全部保留，无删除；Core/Codex Hook definition AST 不变；不 commit/push/替换活动 Runtime/修改真实 .cursor 或 .codex，三位试用及独立 Ground Truth 保留 Pending/未执行。后续阶段继续 Planned，本轮完成后停止。


## Core P0-8 — Host Event Normalization v1

P0-7 Global Codex Desktop E2E 根据用户提供的真实验收已 VERIFIED、封版；此结论与历史本地证据及本轮模拟 Host 分开记录。当前交付为增量控制流抽象：Codex Raw → CodexEventAdapter → NormalizedHostEvent / VerifiedHostContext → 公共 dispatch → 原 HookCoordinator / remediation / continuation。事件使用 SESSION_START / WORKSPACE_ACTIVITY / SESSION_STOP；operation 使用 READ_ONLY / DIRECT_FILE_MUTATION / POSSIBLE_WORKSPACE_MUTATION / UNKNOWN。strict claims、workspace/session/replay、原始 opaque refs 和签名命名空间不变；binding consistency 不等于 Host authentication。Core 用 normalized semantics 和真实 filesystem digest 判断扫描，mutation hint 不是证明。baseline/snapshot 发布顺序、Family/Episode、Ticket/Envelope、真实 scanner receipt 不变。Capabilities 是有限 bool 声明，不是执行时机或权限。默认 Core 不进入 build/test/Deep。Codex MCP schema/输出、Global Hook definition、setup/status/repair/uninstall 兼容；recent journal 增加闭集 normalized 字段，原 Codex ABI 保留。Session 原值仅在内部 context 私有字段中短暂保留以兼容旧命名空间，禁止序列化或持久化整份 context，诊断只用安全投影。Focused：182 passed in 170.80s (0:02:50)；full offline：1548 passed, 9 skipped, 6 subtests passed in 1804.88s (0:30:04)，零失败，skipped 单列不计 PASS。wheel/sdist integrity/compliance PASS。本地 stdio MCP + 真实离线 Scanner 的 TLS recurrence 两轮 PASS（模拟 Host，非 Desktop）。 [设计与验收](host-event-normalization-acceptance.md)，[最终回归及跳过原因](host-event-normalization-regression.json)。下一 Host 可复用安全 Core，但仍需自己的真实 claims/schema、输出/continuation 及 transport/install wiring；当前 GlobalWorkspaces 仍是 Codex transport router，不声称已有通用 installer。Cursor/Claude/Gemini/Copilot normalized adapters 仍 Planned，未实现、未验收。前序未提交成果完整保留；未 commit/push，未修改真实 .codex，未替换活动 Runtime，未执行新 Desktop E2E。本轮完成后停止。

## Core P0-7.3.3 — Real PostToolUse reconciliation

Project C 只读证据：SessionStart 比较点已经是 2400（摘要与当前及 2400 variant 匹配，与 2300 variant 不匹配）；目标 mtime 09:21:52 UTC，基线发布 10:27:13 UTC，10:30 PostToolUse 比较的是相同内容。旧 changed_file_count 是 Git dirty inventory，并非本次 delta，不能将该历史 NO_CHANGE 断言成 digest 漏检。修正 adapter 无条件 mutation=true；新增 bounded tracked/dirty raw-byte HMAC 比较和准确 delta count，保持 Git dirty 列表；重复 SessionStart/reconnect 保留当前 session 比较点。缺 pre-edit snapshot 的 lazy bootstrap 明确无法归因，不伪造 NO_CHANGE。新诊断跨进程 recent 可读，无源码/命令/原身份/Secret。Scanner/claims/workspace binding/remediation/Ticket/Envelope/rules/Deep 不改，Git 配置不改。旧 snapshot 保持可读，无历史 bytes 重建。最终 focused：281 passed in 293.87s (0:04:53)；full offline：1523 passed, 9 skipped, 6 subtests passed in 1838.52s (0:30:38)，零失败，skipped 单列不计 PASS。wheel/sdist integrity/compliance PASS / 4.58s。 [验收与生命周期](mutation-reconciliation-acceptance.md)，[最终回归及跳过原因](mutation-reconciliation-regression.json)。前序未提交工作完整保留；未 commit/push/替换活动 Runtime/修改真实 .codex 或 Project C 源码，Desktop 新候选试用 Pending，P0-8 未开始。

## Core P0-7.3.2 decision

The real Project C failure was an installed-runtime quality gate applied again while verifying an already enrolled DEV launcher, not a Windows cwd inequality. Separate read-only signed enrollment verification from new setup/repair opt-in, retaining HMAC/phase/current exact fingerprints. Do not allow workspace mismatch, unowned/stale config or replay. Do not retrofit historical package/source integrity into a launcher manifest that never attested it. Record fixed rejection phase/reason and hashed identity relations, rather than flattening every exception into a path mismatch. No scanner/remediation/Deep expansion. [Evidence](workspace-binding-acceptance.md).

## Core P0-7.3.1 decision

Synchronous Hook diagnostics cannot answer a later independent CLI query, especially before workspace admission. Persist a separate bounded SQLite observation projection, not an authority receipt or a process-memory ring. Commit ingress before claim validation, keep unsafe/unattributed requests explicitly unbound, and share one journal through nested Global dispatch. Real orchestration boundaries and the existing execution ledger distinguish trigger from invocation/completion. Diagnostic failures cannot retry the original handler, weaken claims or block mandatory safety behavior. Query is read-only; no transcript or arbitrary exception text is retained. [Details](recent-hook-acceptance.md).

## P0-7.2 decision

Bash is a valid Codex PostToolUse mutation channel, so excluding it from the matcher was a coverage bug. Classification is a fast path only; snapshot/content digest remains authoritative. `tool_input` is optional and never persisted. Read-only commands are skipped to protect Core latency; ambiguous commands are scanned fail-soft rather than trusted.

## Core P0-7.1 — Codex host-owned Hook state compatibility

仅修复配置兼容性，feature/runtime-mvp / ee1bfd9c12493683cc313cb3628753a51ae124ac 不变。不 commit/push、不替换活动 Runtime、不读写真实用户 CODEX_HOME；前序 dirty 保留，PROJECT_CONTEXT 未读写，P0-8 未开始。

已确认根因：_config 将 TOML hooks.state dict 当 event list；base/global 后续重复 Hook 检查也直接遍历所有 hooks 值。按当前官方 HooksToml / HookStateToml schema，仅对 TOML 的 state 建立明确 metadata 分支；每条 state 是 object，enabled 为 bool、trusted_hash 为 string。官方未封闭 state object 的扩展字段，保留其值；未知其它 hooks dict 不获得豁免。独立 hooks.json 保持 event-only 校验。真正 event groups/handlers、command/server/tool/input/timeout/statusMessage 校验与签名 ownership 冲突检查仍 fail closed。Runtime 不使用这些 host trust values 决定自有 ownership 或修改 trust。

只建立 event-only view，不改变原 parsed document；现有 signed managed block/CAS 合并保留 TOML 原字节，uninstall 恢复原 user bytes。state 与 node_repl、用户 inline/JSON Hook、未知 top-level 设置共存；setup/repair 两次稳定且无无意义重写。两种实际定义来源仍按既有 duplicate 检查处理；state 不算 event source。[详细验收及官方来源](codex-hook-state-acceptance.md)。

新增 25 cases；focused 160 passed / 121.85s；最终 full offline：1414 passed, 9 skipped, 6 subtests passed in 1853.57s (0:30:53)（runner 1854.15s），9 skipped 单列不计 PASS。[回归](codex-hook-state-regression.json)。wheel/sdist integrity + licenses/notices compliance PASS，[package](codex-hook-state-package.json)。temporary venv 强制安装本轮 wheel，确认 module origin 在其 site-packages，借用已有依赖、无网络下载；实际 CLI setup→setup→repair→repair→status→doctor→uninstall 全 PASS，实际 Codex CLI 0.159.2 正常解析脱敏 state 且同时发现 node_repl/ai_security_runtime。[安装验收](codex-hook-state-installed-trial.json)。修复前隔离结构 fixture 为 CONFIG_INVALID，修复后 MCP/Hook CONFIGURED；不是实际 Desktop Hook trial。

现有两份产品模块仅 narrow compatibility hunks；新增 test/fixture + MANIFEST fixture include。router/remediation/Ticket/Scanner/Deep/CET 与 incoming 字节相同；[前序工作区保留审计](codex-hook-state-workspace-audit.json)。真实 Desktop 验收仍 Pending，三位试用待验收、独立 Ground Truth 未执行，未扩大本轮范围。


## Global integration ownership / global capability / trust 不代授

仅 Core P0-7 Global Runtime Integration / Install Once。继续 feature/runtime-mvp / ee1bfd9c12493683cc313cb3628753a51ae124ac；414 incoming 文件已快照，前序 P0-1…P0-6.1 dirty 完整保留，PROJECT_CONTEXT 未读写。不 commit/push、不替换活动 Runtime、不修改真实用户 CODEX_HOME、不运行 Desktop trial。

用户新增真实验收将 P0-6/P0-6.1 更新为 USER_REPORTED_ACTUAL_DESKTOP_PASS：prepare=0、read=1、search=0、exact envelope MATCHED / outside=false，真实 Scanner proof 后 resolved/CLOSED/RETURN_TO_HOST；cycle≈65.9s、Host/Agent窗口≈51.6s。本轮不重跑或优化该 latency。

官方支持 user-level hooks/config/MCP；匹配 user/project Hooks 累加执行，项目 trust 与用户 Hook trust 分开，trust 由 Codex 对精确定义 hash 管理。Runtime 没有可靠官方 trust-state 查询，不读取/修改内部 DB。实际 Codex CLI 0.159.2 已在 temporary CODEX_HOME 中确认全局 MCP list/get。Hook discovery/trust reuse/真实 cwd event delivery 的 Desktop gate 保留 PENDING_ACTUAL_DESKTOP，不能由 fixture hash 稳定推断 PASS。[完整验收与官方来源](global-integration-acceptance.md)。

GlobalCodexIntegration 复用既有 HMAC ownership、exact fingerprints、bounded parser、preservation/CAS/rollback，只改变配置目的地与 launch scope。默认用户级 CODEX_HOME/config.toml + hooks.json；三份 released product_hooks 定义不改、所有 workspace 使用 ${cwd}。默认不生成项目 .codex。installed Python -I module 或 frozen launcher；无永久 repo/src/PYTHONPATH 配置。DEV 显式 opt-in，且 CLI + 实际 MCP 的 global_runtime_integration=v0.1 / integration_scope=GLOBAL / 路由 schema 握手必须通过；同版本旧 Runtime 不可假装全局支持。没有 updater。

GlobalWorkspaces 仅 transport router，复用现有 workspace-bound MCP/HookCoordinator/RemediationService。每 canonical root 独立 DB、Hook state/key、baseline、Family/Episode、receipts、live tickets/triage；opaque refs 原样转交。不按 refs 反推 root、不使用 last workspace/单个已登记 root 作为默认。全局 workspace 请求必须明确 workspace_path（或原 scan path alias），即使只有 A 已登记也不能猜 Host 未切换到 B；缺少 claim 拒绝。global-only ref tools 增补 workspace_path；项目工具原 schema 保持。一个 session 不可换 root；16 roots / 64 sessions budget 不驱逐已有 live authority。静态 Scanner cache 保持既有安全进程生命周期，不缓存/共用 proof。显式 manual MCP scan 保留原完整 ScannerRegistry；Core Hook 与初次比较基线只用 SAST/Secret registry。

Git cwd→最近 repo root（含 subdir/nested），非 Git→bounded name-only project layout/source recognition。拒绝 home/drive/system/state/CODEX_HOME、UNC、traversal/template、symlink/junction ancestors。非 Git source inventory 有界，支持 advisory Hook checks，不升级 Git-dependent AUTO_FIX proof。当前非 Git inventory 并非 Git dirty diff，此限制如实保留。

SessionStart → NEW_WORKSPACE / INITIALIZING → READY 或 DEGRADED/ERROR。两线程 in-process bounded quick baseline，非 daemon/Scanner worker；复用既有 bounded tracked/untracked source inventory 与 coverage/byte recheck，在同一 workspace lock 内发布当前 session 比较点，防止 clean tracked 旧风险被普通编辑误归为 NEW。超预算/失败/partial/moving source 不发布基线。普通 Edit 仍增量，不调用 Full Scan API、不 build/Functional。初始化仅 hashes + safe Hook projection，初次 Finding/source packet 不存 DB。READY 是比较基线/连接观察，不是安全证明。尚未 ready 或 startup Hook 未交付，first edit fail-soft/inconclusive，不假造 NEW/AUTO_FIX；需要可用基线后后续事件收敛。重连新建 live contexts，不恢复 Ticket authority。

只检查当前 root→cwd active project .codex layers。证明 Runtime ownership 才迁移/移除旧 entries，mixed user handler 与 unrelated config 保留；未知 related entries、改名 Runtime launcher/MCP/Hook alias conflict，不能按名字删除。新遇到旧项目可 LEGACY_PROJECT_CONFIGURATION_REQUIRES_REPAIR，需要显式 repair --path，不遍历整盘。已 admit child 也继续检查新出现的子目录 duplicate。Global uninstall 只删自有全局配置，不删 workspace history。旧安全历史留在原 namespace，不搬运历史 receipt/grant、不重解 opaque refs；旧引用 stale 时需取得当前 workspace 新结果。

默认 CLI setup/status/doctor/repair/uninstall。旧 setup codex --path、setup --scope project、integration ... codex 保留；doctor --project 保留原 Scanner/project doctor（原测试明确加 --project），--path 的既有 project doctor 行为兼容。setup --scope global --path 指定迁移来源。仅 readiness 未观察不制造 repair 要求。

Core 仍 incremental scan → policy → AUTO_FIX → real targeted security recheck → return。Hook 名称/claims/Ticket/envelope/receipt/Episode/risk policy/cache/timing 不重定义，Deep API 兼容保留但不自动调用。无新 Scanner、第二规则、Persistent Scanner、Functional扩展、Sandbox/CET、商业权限或云服务。

最终 explicit-routing focused PASS：253 passed / 290.34s；新增 64 cases。[最终完整回归](global-integration-regression.json) PASS：1389 passed / 9 skipped / 6 subtests passed / 1821.36s（30:21）。Skipped 单列：3个需显式开启的 managed performance tests，6个旧 real E2E 的 binaries 前提未满足；不冒充 PASS。focused 有1条既有依赖 lifespan forward-reference warning，无失败。产品/测试/验收脚本137文件的final freeze在完整运行后仍一致。[SDK](global-integration-sdk-final.json) PASS / 119.99s：真实 offline Scanner 的 A1/B1/A2 recurrence 都 resolved/CLOSED/RETURN_TO_HOST、prepare=0、Stop ALLOW_STOP；A refs在B拒绝、多root缺claim拒绝，单A已登记缺claim也拒绝；每次initial Hook Semgrep/Gitleaks各1调用。初始baseline DB不存scan/Finding packet、fixture连接及临时目录清理通过。单 root implicit fallback 收紧前 full 1388 passed / 9 skipped / 6 subtests / 1958.99s，这是修正前结果，不能替代最终回归。baseline专项 94 passed / 88.07s。最终 package/wheel/sdist integrity + licenses/notices compliance PASS，78 Python源 bytes 对照，6.30s。[package](global-integration-package.json)。temporary clean venv 使用已有 deps --no-index --no-deps --system-site-packages；Runtime wheel 强制放入临时 venv 并校验真实 module origin，不能误验基础环境同版本旧包。不是第三方依赖完全空白安装，也不是 Desktop/model trial。没有 network/model/target build/raw-ref report persistence。

历史初轮：26-case 用例的结果解析 helper 把 SDK text list 当 dict，修正测试 helper；握手 mock 漏 get_findings 和 SDK report 读取不存在 scanner_runs，均仅修 fixture。三个审查期间的 full run 主动中止，不记 PASS；最终结果从 frozen delivery source 获取。最新 SDK 增加初次 DB 空表检查后未关闭 fixture SQLite 导致 Windows cleanup 失败，已显式关闭并重验，不放宽验收。日志保留，不以文档覆盖失败。

用户 Desktop 下一步：自行加载交付包后 setup一次 → review user Hook → reconnect → clean Project A bootstrap/编辑 → Project B不setup、确认同定义不重复review与独立状态 → disposable TLS inline fix真实安全闭环 → old owned project repair/重复setup/uninstall验证preservation。本轮绝不代用户执行这些动作。[步骤和限制](global-integration-acceptance.md)。

三位独立试用仍 Pending；Ground Truth UNREVIEWED/null；Maven PENDING_ENVIRONMENT_PREREQUISITES；其它未授权阶段 Planned。本轮 gate 完成后停止。



## Core P0-6.1: preserve exactness with enumerated original-byte results

仅 Core P0-6.1 Post-edit Exact Target Verification correctness bugfix。继续 feature/runtime-mvp / ee1bfd9c12493683cc313cb3628753a51ae124ac，168 incoming 文件已保存快照，P0-1…P0-6 前序 dirty 完整保留；不 commit/push/install/替换活动 Runtime，不运行新 Desktop E2E。

根因：原 FastFix.removal 从 raw UTF-8 bytes 计算整行 range/segment/preimage/canonical postimage SHA，但 Agent Ticket 只保留整文件 preimage 和唯一 postimage SHA。post_failure 只接受“删除风险整行、保留后续空行”的唯一结果；真实 Desktop patch 删除风险整行及其后一个空行，所以 Scanner 已观察风险消失仍无法授权 canonical proof。只读读取已有试验记录：新增/删除均 8-space statement + 1 empty line，记录无其它 changed lines；当前文件 UTF-8 BOM / MIXED EOL。完整旧 Ticket/raw preimage 未捕获，[forensic](inline-exactness-forensic.json) 中 preimage/expected SHA 与 offset **明确为重建假设**，不冒充原凭据。未发消息、未使用旧 opaque refs、未编辑或持久化真实目标源码。这是历史取证，不是新 Desktop E2E。

没有证据表明原 raw-byte helper 存在 decode→newline normalize→encode、BOM 删除、字符/byte offset、pre/postimage 混用或错误 snapshot 来源。具体 mismatch 是 following-empty-line cleanup；设计过窄而不是取消 whole-file hash 本身。构造现在复核 original file/segment/canonical result SHA 来保证同一 preimage。

新 signed edit_envelope = 原 risk physical line + 至多一个已存在的、真正空的紧邻 LF/CRLF line。不含业务代码/注释/indented blank/第二空行。预枚举 ≤3 exact byte variants：REMOVE_LINE（旧结果）、REMOVE_STATEMENT（只移除 statement，原缩进/尾部/EOL/后空行精确保留）、REMOVE_LINE_AND_EMPTY_LINE（只在原已有该空行时）。签入 range、statement range、原 segment/statement SHA、原字节总长、prefix/suffix SHA、EOL/BOM、variant segment length/SHA/whole-result SHA。所有结果从原 bytes 得到；无 post-edit normalize/fuzzy/diff/formatter tolerance/语义等价推断。新缩进/空格、whole-file EOL/BOM 改动均拒绝。

Post-edit 比较原长度定位的 prefix 与右锚定 suffix SHA，验证 envelope 内长度/segment SHA 为预枚举结果，再验证该 variant whole-file SHA；外部 byte-for-byte preservation 保持。原 HMAC、workspace/task/remediation/Episode/grant/scan/snapshot、policy/TTL/attempt、source/preservation/scope guards 原样执行。成功后仍走原当前 snapshot + TaskFix/Verification **真实原规则 Scanner recheck**，签名 receipt 才能 CLOSED；Ticket MATCHED + scanner FAILED/UNAVAILABLE 仍 INCONCLUSIVE。原 Fast Fix 单结果 contract 不变、legacy 无 envelope Ticket 保留旧严格 SHA 分支。已有旧客户端 prepare/Context hint/fallback 不变；正常 inline prepare RPC 仍 0。

非敏感 exact_target_verification diagnostics：MATCHED/REJECTED、subreason、expected preimage/current/canonical SHA、expected envelope length/actual result length/deleted bytes、prefix/suffix/outside changed、expected/actual EOL/BOM/encoding、accepted variant、preservation guard bool。无源码、Secret、byte diff、模型内容。顶层兼容 TICKET_TARGET_NOT_EXACT，子原因 TARGET_PREIMAGE_NOT_REMOVED / TARGET_RESULT_MISMATCH / OUTSIDE_EDIT_ENVELOPE_CHANGED / LINE_ENDING_IDENTITY_MISMATCH / ENCODING_IDENTITY_MISMATCH / TARGET_RANGE_DRIFT / RESULT_HASH_MISMATCH；原 ticket-binding/scope/clock/expiry reason 不改。

产品 hunk 仅 agent_fix_ticket.py + 新 agent_fix_envelope.py；新增 tests/test_agent_fix_envelope.py（48 cases）、scripts/inline_exactness_acceptance.py，MANIFEST 加一行及文档/安全报告。Security Context、Fast Fix、Hook schema/MCP names/4 claims、remediation/receipt/Family/Episode、timing、scanner/cache、Deep/Functional/BOM/CET 文件与 incoming **字节相同**。不增加 prepare RPC、新规则、daemon/bridge/build/Deep。普通 Agent 编辑仍是 post-validation，未观测 edit-and-restore ABA 不可证明，没有原子编辑承诺。



## Core P0-6: Inline preparation and reliable handoff

仅 Core P0-6 Inline Prepared Agent Fix Ticket / Reliable Handoff。继续 `feature/runtime-mvp` / `ee1bfd9c12493683cc313cb3628753a51ae124ac`，165 个 incoming 文件已快照；前序 P0-1…P0-5 dirty 保留。P0-5 wheel SHA `fa1a1e90ab5df6b9d2a46a2ef8b66cceb53922a07d2c1286d36a7cbc4658ef3e` 校验后仅提取源码作 A/B，不安装。用户提供 Episode 8 的 cycle 90854.049ms、continuation wait 61355.587ms、prepare 1133.092ms、约 12 次编辑前 Agent calls / 1 read / 0 search / 1693 context bytes，标 `USER_REPORTED_ACTUAL_DESKTOP`；本轮未自行复现 Desktop。

先完成 [prepare A/B 安全职责分析](inline-ticket-safety.md)：所有 POLICY_AUTO TLS **preparation** 必需项可在原 workspace 锁内完成，包括 workspace/Episode/grant/授权/预算/成员/origin scan/snapshot/source/scope、TaskFix bounded evidence、prepared attestation 与提交依赖。B 是 USER_CONFIRMED 的用户选择及实际编辑/后续 scanner receipt，不从 initial Hook 推断。原 `_prepare` 完整执行，不删检查。P0-5 历史将 prepare 保守保留为独立 RPC；本轮在此窄 eligibility 内复用同一函数到 Hook 事务，不改变 generic/confirmed prepare 或安全 proof。

只在 connected MCP Hook（可信 embedding 可显式 opt in）、POLICY_AUTO / SAFE_DETERMINISTIC_FIX / AGENT_FIX / Fast Host capability unavailable / 唯一 `ai-security.java.trust-all-hostname`、attempt 1、当前 scan/Episode/grant/snapshot/target 且唯一整行可精确删除时签发 Ticket。命令 adapter 默认保留原 prepare。正常窄路径为 Hook → 原 prepare 检查在 Hook 内完成 → structured Ticket + Context → Host read/edit → post-edit incremental scanner + 原规则 targeted real recheck → 签名 receipt / CLOSED / RETURN_TO_HOST；无额外 prepare MCP。没有 Runtime source writer、模型调用、原子编辑桥、Scanner worker、新规则、Deep/Functional/build/test/Sandbox/CET/Plus/Pro。

`agent-fix-ticket-v1` 正式字段位于 `structuredContent.remediation.agent_fix_ticket`：version/mode/fix_path、workspace_id、episode_id、grant_id、原 task_ref/remediation_ref、finding_id/origin_scan_id、security_context_ref、snapshot_digest/scope_hash、allowed_target_paths/rule_id、authorization_kind、attempt_count/max_attempts、prepared_attestation、connection-scoped 900s expiry、精确 removal operation、原文件/预期结果 SHA、ordinary Agent post-validation edit contract、real-scanner success/CLOSED/RETURN_TO_HOST 及 production UNKNOWN / no Deep。上限 4096 canonical bytes；Context 仍独立解释 What/Where/Why/建议/范围/成功条件，不成为 credential。inline Context 的 `prepare_required=false` 仅描述已签发 Ticket；原 refs 不解析重建、不改字，informational context ref 对当前小对象重新计算，不是 bearer grant。

原 authorization、2-attempt budget、membership、source/preservation、receipt binding、真实 scanner proof 保留。inline 额外要求 whole-file expected result bytes，连接内 ≤32 Ticket + 单调 TTL + policy revision binding。磁盘仅存签名 attestation HMAC/状态/固定原因，绝不恢复 live authorization；重启丢 Ticket/prepared，不伪造延续。unexpected target、额外文件、expiry、wrong binding、lost attestation 不能 CLOSED；观察到 stale 后持久拒绝，不被后续 manual-recovery Hook 漂白。未编辑且原 freshness 仍有效时，可用**原两个 refs**走 legacy prepare 重新检查并替换未消费/过期 preparation；可不传 hint，旧 Host 也可传当前 inline Context ref，Runtime 在完整原检查内从当前事实重建这个 informational 对象（只差 prepared flag），不是从 hint 接受授权。已 drift/escalated 要刷新当前任务，不盲目重试旧授权。已签发 CLOSED security proof 不被 Ticket expiry/重连或 Deep unavailable 降级。

没有 Host 原子编辑锁，未观测的 edit-and-restore ABA 无法证明，旧 prepare 同样无法检测；不声称阻止每次外部写入或证明模型读了哪份 Ticket。可观测的异常编辑被当前字节/snapshot/其它文件 preservation 和编辑后 scanner 阶段拒绝。完整 machine Ticket 不依赖 prose：测试删除或截断文本后仍从原 structuredContent 完成闭环。官方 [Codex Hooks](https://learn.chatgpt.com/docs/hooks) 于 2026-10-05 实际读取，说明 MCP 与 command Hook 输出契约一致、大输出可 spill/truncate；没有 arbitrary structuredContent 独立向模型展示的官方保证。保留正式 SDK 字段，同时 documented additionalContext 只投影完整同一 Ticket/Context 与短固定说明，去掉重复 refs/报告/scanner diagnostics。**SDK 完整性 PASS 不等于 Desktop 模型一定见到完整对象**，其 gate 仍 Pending；不改 config/schema/四个输入 claims，不猜官方字段。

observability：agent_fix_ticket_version/mode、prepare_task_fix_required、Runtime 工具函数入口计数（当前 grant/当前连接）、handoff_recovery_required、structured_handoff_complete、inline_prepare_reason、ticket_stale_reason/ticket_status；Host retry/read/search/model CPU 未观测仍 null。P0-3 timing 保留：inline_prepare_started/finished 在 initial runtime 内；独立 inline_host_edit_window 为 response-ready→post-edit Hook，混合 Host/Agent/transport，不叫模型 CPU。正常 inline 不制造 prepare MCP/Host received 端点；旧 prepare windows 为 null，不重复相加。recurrence 独立新 Episode/grant/scan/Ticket；相同字节的 snapshot digest 可以相等，隔离靠新身份，绝不伪造 hash。

Fresh Desktop P0-6自然续行/模型看到完整Ticket、p95/p99、三位真实试用仍 Pending；Ground Truth UNREVIEWED/null；Maven PENDING_ENVIRONMENT_PREREQUISITES；Fast Host atomic bridge PENDING_HOST_ATOMIC_EDIT_BRIDGE。其它阶段继续 Planned。当前无需继续压缩 Security Context；先验证本轮 Ticket 自然交接，不能把协议减少一次 RPC 宣称模型已少12次调用。

下次人工 Core E2E（本轮未执行）：用户自行安排加载本轮 Runtime 后，新建隔离 Java 项目与 fresh Codex chat；普通安全编辑建立 baseline，再只引入 standalone always-true hostname override。确认初次 Hook 的 INLINE_PREPARED、完整两个原 refs/attestation/context/target、prepare_required=false、工具调用计数0；Agent只read该target和删除该行、保留所有其它字节。不主动扫描/prepare/Deep/build。确认post Hook真实Scanner原规则proof、matched task/grant receipt、CLOSED/RETURN_TO_HOST、计数仍0和inline cycle窗口。再引入同family核对新Episode/Ticket/scan/grant、旧ref拒绝。遇到缺失/截断/stale字段停止，不从路径重建引用；记录实际Host工具数及wall-clock，若仍恢复summary则保留失败事实。



## Core P0-5: Agent Fix Context Compression

仅Core P0-5 Agent Fix Context Compression，继续feature/runtime-mvp/ee1bfd9c12493683cc313cb3628753a51ae124ac与前序全部dirty；162文件incoming快照，P0-4 wheel SHA85576795657bba49bd1380bc1471097630e8f57cb7ed80f1de976f14b712accc只读校验/提取为本地A/B baseline，无安装。Fast Fix文件原bytes保留，PENDING_HOST_ATOMIC_EDIT_BRIDGE；不扩第二条规则、不新增Scanner/daemon/Functional/BOM/CET/Sandbox/Plus/Pro。Runtime仍不写项目源码，Host编辑。

初次Hook携带短context与informational security_fix_context_ref；prepare/verify/Stop handoff仍原两个task/remediation opaque values逐字保留，不改参数字典或重记continuation。仅保留context的Host可在prepare_task_fix调用额外传可选security_context_ref，其值为原context ref；不能让所有旧调用/verify/Deep继承未知参数。接口向后兼容：无hint（包括Stop fallback）返回INLINE compact context；匹配hint时在原ref/snapshot/source/preservation/budget门禁内重建并核对，REUSE_HOOK_CONTEXT仅回指事实，不重复整段信息；不匹配REFRESH_REQUIRED且无prepared attestation。hint单独不能授权，没有remediation grant时固定拒绝；context/ref不持久化，不成为新grant或缓存proof。所有generic selected-task以及USER_CONFIRMED preparation保留旧完整接口；legacy host_protocol.instructions保留短Core结束语，不重复guidance。POLICY_AUTO packet的旧报告/代码excerpts不再输出，bounded_evidence只保留UNTRUSTED_CODE locator兼容标记，不是source packet。

压缩重复信息，不删除prepare授权/新鲜度检查；风险Hook+prepare+post-edit仍3Runtime MCP。保留原post-edit+original-rule实扫，不合并proof。短自然语言只指向协议，Hook stopReason/systemMessage不再重复整段guidance；prepare不返回通用TLS分析/代码报告/回归任务。用户确认分支长说明保留，因为本轮不改变其审批语义。

真实managed Scanner+actual stdio MCP；Host是SIMULATED_WINDOWS_NATIVE_EDIT_FIXTURE，无LLM、无sleep、offline。相同facts+guidance投影8203→4825bytes（减少41.18%），非整个Hook wire payload；final与focused并行负载，修正前串行报告另存agent-context-core-before-review-correction.json；1699bytes为新context本身，legacy不存在该schema故null。MCP主流程仍3=风险Hook/prepare执行前门禁/修复后Hook；额外Host fixture edit RPC单列1，不隐藏成0；Scanner每cycle仍3SAST+2Secret。before cycles23391.335/21004.801ms，after22553.257/22981.665ms。有限样本不证明wall改善，不声称reasoning加速或Host动作减少，固定Host双方同为1read/0search。recurrence旧ref拒绝在已测cycle结束后另作诊断，不混入比较。Runtime context构造有新增绑定/成员校验成本，Scanner/运行波动也存在；未测完整归因，不将全部差值归因模型或context CPU。初轮8203→4424byte报告早于兼容修正，不替代final；并行版119.93s只单列。

新增test_fix_context.py 11functions/21cases；已有host orchestration及Code Mode契约测试只将smart_auto长prose断言替换为context/自动授权/不重复编辑/实扫等协议语义断言，ask_before_fix与其它旧tests保留。final focused PASS：205passed/822.16s（wrapper823.30s）；final full offline PASS：1240 passed, 9 skipped, 6 subtests passed in 1991.19s (0:33:11)（wrapper 1992.56s）；9 skipped单列BF，不计PASS。第二轮全量早期发现Code Mode旧测试要求stopReason重复完整guidance，单测1failed/4passed/21.99s；仅将该smart-auto文字断言改为精简协议语义，保留completed-edit/授权/两原refs/confirmed/Stop/ABI检查，产品代码未变。第二轮focused/full分别383.65/384.07s中止return130，不计PASS；修正后该模块5passed/19.71s。第三轮focused发现新增context把VALID AI review误判为Scanner过期，既有receipt单例1failed/3.76s；修正仅删除新增review-status条件，原grant/snapshot/source/ref与receipt校验未改。第三轮focused/full分别1139.69/1139.58s中止return130，不计PASS。随后context+receipt 47passed/1failed/316.60s为新fixture伪造VALID但缺ai_review时错误期待授权；已改为断言原TaskFix拒绝且不建立prepared，既有receipt测试原文保留。第四轮full200.13s中止return130，不计PASS。最终focused聚焦直接受影响7模块/205cases，先通过再跑full；新增仍21cases，完整1249收集/9skipped。final MCP A/B PASS/118.06s；原Fast/recurrence/fallback compatibility PASS/112.33s；package integrity/compliance PASS/7.28s，107Runtime文件bytes核对，dist/agent-context-final，无安装。初轮3failed/104passed为新测试过宽source子串及既有_fail无status断言错误，已修；诊断1failed/1passed，v2 context19passed/104.71s。后发现legacy instructions字段缺失、prepare arguments新增hint泄漏到旧verify/Deep/Stop消费者；已修正原两个args与短legacy字段。隔离诊断18passed/1failed/22.15s；失效门禁focused/full在631.58/631.65s中止return130，不计PASS；兼容复核129passed/457.00s。首轮MCP/package/Fast evidence另存initial；并行负载A/B另存concurrent，修正前串行证据另存；final与focused并行重测。产品/测试/脚本158文件冻结。

不扩SQLi/SSRF等CONTEXTUAL_TECHNICAL_FIX：其根因/数据流/业务条件不是这条规则的确定事实；没有真实LLM A/B证据，不推出推广结论。

## Core P0-4: Deterministic Fast Fix Path

2026-10-05实际读取[OpenAI官方Hooks](https://learn.chatgpt.com/docs/hooks)：MCP Hook调用已连接server并遵循Hook输出协议，PostToolUse的additionalContext/continue:false提供模型可见反馈；PreToolUse updatedInput只能重写已排队工具。未发现PostToolUse响应能直接启动原生edit、检查当前Episode并原子CAS的官方契约。现有Codex Runtime integration也只输出反馈、四个metadata claims与Agent handoff，apply_patch无whole-file digest CAS参数。因此默认Codex严格保持AGENT_FIX/FAST_FIX_HOST_CAPABILITY_UNAVAILABLE；未实现、未宣称Codex machine-executable或无LLM apply。

不在Runtime实现patch writer，也不将结构化文本当成Codex原生调用指令。先交付单规则规划/校验/Host admission vertical slice；当前Host limitation是实际发布边界，默认仍Agent Fix。测试中使用单独Host fixture的真实Windows文件句柄拒绝其他写/删除；Runtime只在句柄持有期间验证authority，Host写fixture源码；不把测试工具注册到生产server。无新CET/sandbox/执行环境。

REMOVE范围比原Agent确定性source guard更窄，以整行唯一inline expression为限，保留UTF8/CRLF与所有周边bytes；不做BOM normalization、AST重写或通用patch。Plan身份是服务器保留原对象的strict JSON metadata identity；修复bool/int与int/float字典等价隐患，opaque ref字串仍逐字不解析。旧计划不持久/不复活，recurrence新Episode/grant/plan，重复claim拒绝；attempt budget仍原语义。

本轮不合并Scanner窗口：现有安全projection不能替代实时canonical verifier proof；保留真实post-edit扫描及原rule复扫。模拟数据证明少一次Runtime prepare往返，不能证明Desktop Host等待已删除；首轮Agent16.676s/Fast16.775s未更快，final Agent18.547s/Fast16.806s亦仅有限顺序fixture样本，不推统计收益，不加入sleep/fake model时延。先补真实Host contract，不扩第二规则。

新增test_fast_fix.py共44cases（18functions），最终focused PASS：392 passed in 1003.12s (0:16:43)（wrapper 1004.17s）；final full offline PASS：1219 passed, 9 skipped, 6 subtests passed in 1450.17s (0:24:10)（wrapper 1451.03s）；9 skipped单列如下BE，不计PASS。final local MCP + managed Scanner PASS/93.04s（无sleep，无model、network或Deep）；四个cycle均真实resolved/CLOSED，含Fast recurrence与篡改plan后的Agent fallback。final wheel/sdist/package integrity/compliance PASS/5.82s，106Runtime文件bytes一致，dist/fast-fix-final；未安装。首轮测试接线/文本拼接/CRLF断言修正、首次sdist缺脚本、为严格JSON防篡改中止的旧门禁均另列BE，不算PASS。 验收完成，停止，无commit/push/install/Desktop trial。

## Core P0-3: AUTO_FIX Continuation Latency Observability

保留错误Chat产生的可用观测实现，不以所有权为理由重写；使用P0-2.1已验收wheel/sdist哈希而非Git HEAD作为真实dirty基线，保存进入231文件快照。发现的架构问题为计时关联/归因：跨workspace singleton fallback、未验证ref提前标记、进程变化/完成后仍mark、shared pending、sent/edit标签、粗分项相加隐藏overlap。局部修复，不触碰Family/Episode授权/receipt/opaque ref安全语义；原_close体与11个关键函数AST保持。

36170ms Desktop cycle不能由3670/2840/2880ms阶段相减就说剩余为模型时间，scanner包含于Hook且缺post-edit Hook/prepare/队列端点。采用真实Runtime边界分区与嵌套detail；跨Runtime/Host/transport窗口只能命名为混合窗口，缺直接观测则null。cycle仍单调端点差，所有point均连接内当前instance/Episode；重启不从DB/wall clock重建。观测非Core必需动作，观测失败不改变Core判断；scanner/proof失败仍不得伪装成功。

rule-plan key包括workspace/pack/checksum/files/目标bytes；普通源码每次变化MISS是正确保守失效，static version/pack/config可HIT。不为漂亮cache数字移除byte binding，实际planning耗时另列BD，非本轮优化目标。

Deterministic Fast Fix Path仅技术分析：当前单一JDK inline hostname rule已有scanner corroboration/source skeleton/preservation guards，是狭窄候选；未来可以考虑Host执行受约束确定性patch减少模型编辑窗口。仍需原AUTO授权/opaque refs、expected bytes/snapshot、单文件范围、原保存guard和freshScanner；歧义/自定义TLS/多安装/并发编辑fail closed到原Host协议，不能推出业务或生产正确性。新增Runtime写文件能力或Host命令协议都需独立设计，不在本轮实现，不扩展规则/扫描器/风险策略/entitlement。默认Core仍no Deep，Stop仅现有fallback。门禁完成后停止、不commit/push/部署。

最终focused 348passed/782.04s；full offline 1175passed/9skipped/6subtests passed/1206.43s；本地MCP simulated Host PASS/65.10s，两Episode（direct prepare/Stop fallback）分别cycle 14353.014/15369.367ms，均真实Scanner resolved/CLOSED/RETURN_TO_HOST，functional 0、build/test/sandbox false。final wheel/sdist/package integrity/compliance PASS/4.57s，105Runtime文件bytes核对一致，独立dist/continuation-latency-final；未安装。初轮MCP/package另存initial证据，不能替代final。v1三项诊断WAIT标签冲突及中止的full如实见BD，旧断言未改。 initial_hook_response_ready具体为adapter advisory数据已就绪、尚未将新增additionalContext编码或发送；后续编码、MCP传输、队列和Host工作只能落在混合窗口，不据此单独归因。RETURN_TO_HOST端点表示Runtime返回决策，不能声称Host已经收到。 本阶段验收后停止，未实施Fast Fix Path。

## Core P0-2.1: Cache Lifetime & Scanner Invocation Reduction

先解决对象生命周期而不引入常驻Scanner。BB cache是对象私有，即使PID未变化也能因factory/registry重建MISS；此前Desktop没有instance诊断，不能把复现机制强行写成那一次唯一原因。runtime_instance_id稳定+cache_generation稳定用于区分当前进程内请求，重启的新identity和MISS属于预期安全边界。process缓存只保存内容验证过的准备信息，不跨workspace复用目标/配置上下文，不持久化正向扫描结果。

五次process_invocations来自原Gitleaks per-target dir循环，version probe另计；Core scope包含dirty/retained/context状态，单文件编辑不代表scope只有一个文件。保留全部scope，使用受控临时镜像batch为一次，不删Secret能力或只挑Java文件。实际Desktop五个target没有原始清单，仍未知；新诊断与五文件真实fixture不混同。

新增cycle是单调端点差，包含模型/Host等待/编辑而非ScannerCPU。只在当前连接观察同一Episode完整起止时OBSERVED，重连/重启UNKNOWN，绝不从旧阶段加和或持久墙钟重建。安全事实独立于性能metadata；重复verify不延长已完成cycle，recurrence不继承历史时间。既有authorization/receipt/Family/Episode/CET/Deep/Hookschema/setuprepair保持。

不实现worker/daemon。最终串行对照不隐藏不利数据：cold7835.689→8115.247ms未改善，两次warm仅小幅变化；同进程registry重建7592.651→4220.139ms、五目标Gitleaks invocation总2578.249→502.758ms明确减少浪费。Semgrep invocation仍主要成本（串行bench3.35–3.88s，独立SDK2.44–2.90s），内容校验仍约0.4–0.5s，没有mtime-only/TTL降级。已有足够证据评估后续persistent设计，但没有证明支持的reuse接口、失效/隔离模型或收益；下一轮应先Desktop实例诊断与设计评审，本轮不自动启动PoC。真实managed性能tests无sleep/假scanner；MCP driver保留已存在1.1s cooldown等待，cycle约12.73s是真实本地driver、不是Desktop模型体验，也不能与不存在的旧cycle作提升对照。focused/full/realmanaged/MCP/package/compliance已PASS，跳过及原始证据见BC；门禁与记录完成后停止，不commit/push/部署。


## Core P0-2: Scanner Hot Path Performance

先测后改：真实managed baseline只有1文件21规则，反复 --version 约1.7s不是源码范围扩张，scan invocation另约2.4s。先消除重复能力probe、YAML解析和Git discovery，再让安全proof只复查原规则；不取消独立安全复扫。版本cache内容hash成本约0.3s仍保留，不用mtime-only/TTL代替安全失效。Static准备信息不是scanner结果；每次需要新的engine process、rule/file确认与原bound receipt。

缓存均连接内、有界、按内容/配置/版本/环境/workspace失效；rule/config和目标内容每次验证。失败/不完整结果不能提升后次coverage，restart冷启动；recurrence新episode新refs仍真实扫描。保留当前dirty+retained candidate范围以维持Family收敛，不为缩scope引入跨事件旧result proof。只有verification原规则集合变窄，第一次风险发现保持全部适用规则。

不引入worker/daemon。Priority A已证明收益；剩余约2秒以上CLI invocation含未可靠拆分的初始化/执行，只能说明边界、不能伪造Python启动/CPU时间。若未来做process reuse，需先独立隔离/失效设计，当前不做。既有Deep/API、Core no Deep、CET/BOM、setuprepair/官方Hook ABI、receipt/预算保持；没有模型、用户源码编辑/构建/依赖下载/活动Runtime替换。原测试不放宽；新性能test使用真实managedprocess，无sleep/假时延，SDK cooldown等待只属模拟Host窗口，不是性能收益。最终串行managed数据及MCP两episode已通过（safeHook5142→3533ms、resolvedHook10097→6868ms），并行负载原记录保留；不当Desktop/p95承诺。focused/full/package/compliance门禁已完成，当前成果未提交推送，停止本轮。

## Core P0-1: Hot Path Policy & Integration Hardening（2026-10-04）

Core Hook 结束条件是原风险的可信 scanner resolution，不是 compile/build/test 或 production correctness。默认修复后返回 Host；Functional Verification 保留为显式 Deep 请求，不能因失败/不可用/慢阻塞 Core。未请求 Deep 时 verify_task_fix 不调用 functional.finalize/discovery；Security 状态独立，不把 Deep 当 Core readiness prerequisite。Capability != Execution Timing，六种 trigger 只作元数据，不做 entitlement。

耗时记录真实观测，不改变扫描/授权/风险语义。未执行为 null；auto_remediation 明确为 HOST_CONTINUATION_WINDOW_NOT_EDIT_CPU_TIME，不声称测到模型编辑 CPU 时间，不持久化用户数据、不信任 Host timestamp。先记录增量检查和 TaskFix proof recheck 双成本，不能为了速度删除必须安全动作。SDK driver 不是 Desktop 模型证据，尚未证明常开不打断目标。

setup/repair 先证明所有权再迁移，不能按 server 名称、Runtime 字样或 marker alone 抢占用户配置。支持 signed v0.1→v0.2、精确旧生成器与重复 attested block/handler；CRLF 等价但健康 bytes 不变。unknown/tampered ownership、用户修改同名 MCP 或近似 Hook 继续 fail closed。旧 command 支持和官方 Hook ABI 保留，不写 Host 信任数据库。

本轮未提交/推送/安装/替换活动 Runtime，无新 CI。下一次 Core Desktop 需核对 execution_timing，不能凭0.3.1确认新代码；不继续 Functional E2E。BOM/CET/执行安全模块/receipt binding 未变；旧默认自动 functional 指导由本节取代。验收见 BA。

## Deep Verification protocol correctness fix（2026-10-04）

SCANNER_VERIFIED_RESOLVED/CLOSED 是安全 episode 事实，不是 functional PASS；不应因 AI review 变 STALE 或功能凭据读取失败被改成 NOT_VERIFIED。用已保存原 finding scope 和 signed resolved scan 校验授权，而不放宽验证为仅检查 CLOSED。generic SECURITY_RECEIPT_REQUIRED_REFRESH 保留兼容，增加具体失效枚举与当前 snapshot validity；旧 episode/context 错误要求刷新但不能自动换对象。状态提交繁忙只允许重试同一 prepare。

新 proof 唯一绑定当前 workspace/task/grant/episode/目标 scope/scan/snapshot。不通过自动新发 token 或猜 refresh 工具修复。旧格式 proof 缺少完整 binding 时，只提供现有 verify_task_fix + 原始 refs 的实际 scanner recheck handoff；该复核成功后才生成新 binding。确认授权过期/重连限制不自动续期。duplicate verify 保持有效 proof identity，避免破坏已签发 functional plan；换 proof 后原报告拒绝。task-v1/rem-v1、Family identity、episode recurrence 和每 episode 两次预算不变；新增状态向旧 Runtime 回滚会 fail closed，不能承诺旧版本读取新 binding。

产品定位为 Deep Verification protocol correctness fix，已有 verification 能力保留兼容，重验证留给未来 Plus/Pro/Manual/Stop/PR/CI。本轮不向默认 Hook 热路径新增规划、执行或更强指导，不调整 BOM/CET、不安排新的 Desktop BOM/Functional E2E。完成既定定向/full offline 回归后停止，不提交推送或部署。详见 AZ。

## javac UTF-8 BOM compatibility（2026-10-04）

javac -encoding UTF-8 不消除源码开头 BOM，因此选择 Runtime 专用临时副本，而非修改用户源码或更换编译器/沙箱。只处理一份开头 UTF-8 BOM，所有其他字节及原成员路径不变；有 BOM 的多成员计划全部使用副本以保持 cwd 一致，无 BOM 继续原路径。对未知编码/NUL/重复 BOM fail closed / FUNCTIONAL_INCONCLUSIVE；真实语法/类型错误仍可 FAILED，baseline UNKNOWN、regression_attribution NOT_PROVEN，不推断由安全修复引起。

元数据为 additive，MCP 名称/参数/引用/结果回传模型及旧 Host 执行协议不变；BOM 时 Host 必须遵循 Runtime 签发的 argv/cwd，不能改为编译用户原路径。只使旧 javac 缓存 namespace 失效，不迁移 DB/key，也不提升 COMPILE_ONLY。保留 scanner resolved 与独立 functional 状态，Runtime 无命令执行/模型/目标编辑，CET 与 Hook 不变。用户最新真实 Desktop 编排 PASS / BOM FAIL 已记录，本次 Desktop 修复复验 Pending，不替换活动 Runtime、不提交推送。见 AY。

## 功能验证器发现与宿主执行编排 v0.1（2026-10-04）

Runtime发现/规划/验收，AI Coding Host原生执行；扩展prepare_functional_verification/run_functional_verification/verify_task_fix，不新增平行工具或CET。默认MCP去除LocalSandbox执行选择，原内部注入executor测试保留，既有sandbox源码不修改。FUNCTIONAL_VERIFICATION_READY不是PASS；无报告调用返回计划、不启动进程。功能失败保留SCANNER_VERIFIED_RESOLVED与原顶层scanner status，不自动回滚安全修复、修改测试或重试；production_correctness永远UNKNOWN。compile成功仅COMPILE_ONLY，不等同业务测试或SAFE_TO_SHIP。

Java fallback仅没有Maven/Gradle配置时使用已有javac；不安装、不猜依赖classpath、不隐式编译兄弟源码或运行annotation processors，输出项目外。既有build/scripts在有界瞬时副本执行，需要Host审阅项目代码并拒绝网络；Runtime不声称能控制宿主OS或认证报告真实性。报告闭合有界，带UNTRUSTED_HOST_EXECUTION_REPORT来源，文字只作固定分类与keyed摘要，不回显/持久化。

兼容：工具名称/原refs格式不变；run新增可选execution_result，旧无报告调用不再在Runtime执行、返回Host计划；prepare默认PLANNED改FUNCTIONAL_VERIFICATION_READY，Host需按新交接走。verify原status/verification_status保留，新增functional_status与overall。schema/key/DB不迁移；cache独立namespace不误用原Runtime执行记录。Runtime版本仍0.3.1，runtime-info增加functional_host_execution=v0.1识别能力；未发布安装。Desktop与Maven真实执行Pending，不增加daemon/沙箱基础设施。详见AX。

## Finding Family / Remediation Episode lifecycle（2026-10-04）

稳定 family 与独立 episode/attempt 分开，修复 CLOSED family recurrence 被永久阻挡。保留原 session envelopes、flat current record、task-v1/rem-v1、max_attempts=2；增加随机 episode identity、正向 scanner resolution receipt、有界 metadata history。workspace lock 下原子写新 episode，workspace 最新 episode 查找防止跨 session 重置/旧授权复用。首次 AUTO 分配 attempt 1、确认批准前0、重试2，与原客户端含义一致。

reason 迁移：不再输出混合 `FAMILY_CLOSED_OR_BUDGET_EXCEEDED`，拆为 EPISODE_ATTEMPT_BUDGET_EXCEEDED、EPISODE_ALREADY_EXISTS、EPISODE_RESOLUTION_NOT_PROVEN、REMEDIATION_FAMILY_BUDGET_EXCEEDED、EPISODE_HISTORY_BUDGET_EXCEEDED。原 ATTEMPT_LIMIT 改 episode budget enum，action仍ESCALATE。AUTO 的 SAFE_DETERMINISTIC_FIX 和确认的 USER_CONFIRMATION_MODE 保持；新增 episode_reason_code=RECURRENCE_AFTER_RESOLUTION / FIRST_OCCURRENCE，区分生命周期与策略原因，不让客户端自行构造引用。无合法“family 永久关闭”语义，不新增 FAMILY_CLOSED。

无 SQLite/key migration；旧 MAC-valid rows 只读视作 #1、保留attempt。旧 CLOSED alone 不是 receipt；但其已签名 SCANNER_VERIFIED_RESOLVED + 有效安全snapshot/source/preservation guards 是旧 Runtime 已成立的正向 scanner proof，迁移保留它（hook scan ID未知），允许之后真实新scan识别复发，不迫使用户重复证明旧事实。缺少这些字段须新核查补证。变更时写新字段；损坏/歧义 fail closed，不恢复预算。当前策略仅建议时用新 OBSERVED phase 建立 recurrence episode，attempt=0，不发 token；旧 Runtime 不支持该 phase，会 fail closed，不能承诺向旧版本回滚状态兼容或以旧包验收新行为。历史达到16后明确停止，不丢历史重置。Hook prompt/Agent continuation/CET/functional credential 不扩展；真实 Desktop人工验收Pending，driver不冒充宿主模型。未经用户明确要求不 commit/push，不部署替换活动包。

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
## Core P0-7.3: propagate native event identity, do not bypass missing claims

使用官方 Codex PostToolUse turn_id/tool_use_id 作为 required invocation claims，经 whole-value JSON 模板传入 MCP。permission_mode 仅描述、严格 enum，不提升权限。SessionStart/Stop 各用官方可提供的字段；Stop 不需要 tool identity。缺失/错误/重放/绑定错误都 fail closed；不通过 transcript、自然语言、workspace 推导或伪造缺失 ID。

当前 live server 中保留有限 identifier hashes，拒绝 invocation 在不同 session/turn/tool/workspace 复用，也拒绝完全重复；预算满时拒绝，不通过 eviction 重新接纳。restart 不声称延续 identity 历史；已有 signed proof 保持原协议。命令 Hook 与直接嵌入 coordinator API 保留；MCP config 输入升级是显式契约变化，旧手写 definition 必须重新生成/review。

拒绝诊断按 schema 字段分类，不回显未知字段名和值。实际 Desktop 历史 payload 缺失，不能将“旧配置未传 turn/tool_use_id”冒充已证明的具体拒绝原因，因为旧 validator 没有要求它们。记录 UNDETERMINED_PENDING_ACTUAL_DESKTOP_DIAGNOSTICS，使用下一轮非敏感 diagnostics 验证。无 Scanner/Family/Episode/receipt/remediation/Ticket/Deep 改动。
