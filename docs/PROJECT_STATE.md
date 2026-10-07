# AI Security Runtime — Project State

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

P0-10.1 Cursor Visible Security Feedback: delivery implementation/local native checks complete; final regression PASS (LOCAL VERIFIED; actual visible Cursor UI Pending); actual Cursor visible UI PENDING. Prior detection/advisory Desktop verified by user. No commit/push/active install.

See [acceptance](cursor-visible-feedback-acceptance.md) for binding, bounds, privacy, native race evidence and manual UI trial.


## P0-9.6 — Advisory remediation contract

Final focused: **397 passed in 1074.60s (0:17:54)**. Full offline: **1730 passed, 9 skipped, 6 subtests passed in 2361.35s (0:39:21)**. Package/integrity/compliance/candidate install PASS; actual Desktop NOT_RUN, Cursor continuation Pending.

Cursor 的 transport-as-policy-config 接线错误已修：原 .path 是 policy 配置存储位置，不是 workspace。真实用户偏好与不可自动 continuation 的 Host 能力分开。当前 Runtime 可以保持 policy AUTO_FIX，同时返回 ADVISORY_ONLY / REMEDIATION_OFFERED；不签发 grant/Ticket，不自动编辑，不伪造 verified/CLOSED。旧 P0-9.5 独立 config.path 阻塞已在本轮处理。

已完成 managed Scanner Cursor command fixture 和 Codex 本地 MCP 两轮 recurrence 验收；最终 focused/full 结果见 [本轮验收](cursor-advisory-remediation-acceptance.md)。Cursor Event Adapter/schema/anchor/generation/lifecycle 与 P0-9.5 attribution 冻结，原 Finding/Policy/Family/Episode/receipt/Ticket/Envelope/Scanner proof 保留。Cursor 原生 post-edit 输出仍 {}，Runtime OFFERED 不等于 Desktop 展示或自动 Agent Fix。

Agent Handoff：只完成 P0-9.6 后停止；Cursor continuation 仍 PENDING_CURSOR_CONTINUATION_CAPABILITY。真实 Desktop 未执行，不改用户 .cursor/.codex，不替换活动 Runtime，不 commit/push，前序未提交工作完整保留。三位试用及独立 Ground Truth 保持 Pending，其他阶段保持 Planned。


## P0-9.5 — First-scan attribution

共享 HookCoordinator 现在可在 SESSION_BASELINE / COMPARISON_BASELINE 后，对首次风险进行真实、等价的 targeted pre-edit Scanner 归因。SessionStart/Stop 不扫描；Cursor Adapter、anchor、generation、lifecycle、HostEvent contract、Scanner、Family/Episode、remediation、Ticket、Envelope、rules、Deep 实现保持冻结。P0-9.4 lifecycle 已获用户真实 Desktop 验证；本轮未执行 Desktop E2E。

旧 snapshot 仅存 keyed digest，不存源码。恢复源限既有 Git index/HEAD，旧字节必须逐字节 HMAC 匹配可信 snapshot；Git clean 状态本身不是 proof。不可恢复的 dirty/untracked/non-Git 旧内容继续 inconclusive。只 materialize 发生当前风险的 changed files 到可清理临时目录，真实 Semgrep 同版本/同规则/同配置/同 normalization/执行 identity 校验后交给原 family multiset delta；不猜 NEW，不新增来源持久化。

最终 focused 164 passed；full offline 1712 passed / 9 skipped / 6 subtests passed，skipped 不计通过。25 个新增归因 cases、真实 managed Scanner、Codex 本地 MCP 两轮闭环、wheel/sdist/integrity/compliance 和候选安装已验收；具体结果及冷进程单样本成本见本轮验收。

当前本地归因 assertions PASS；实际 Cursor command policy 仍存在独立接线阻塞：只读 AdvisoryTransportConfig 无 path，RemediationService 读取时返回 REMEDIATION_INCONCLUSIVE。用户明确要求保持冻结、记录独立阻塞、后续再修，不冒充完整 Remediation Offered 验收。Cursor continuation 仍 PENDING_CURSOR_CONTINUATION_CAPABILITY。

Agent Handoff：只完成 P0-9.5；测试、包和真实性能记录见 [本轮验收](first-scan-attribution-acceptance.md)。不 commit/push、不改真实 .cursor/.codex、不替换活动 Runtime、不进入下一阶段。前序未提交代码与文档历史完整保留；真实试用/独立 Ground Truth 保持原 Pending。


## P0-9.4 — Cursor Event Lifecycle + Baseline Ordering

Cursor SessionStart 不再调用会扫描的 capture_session；只发布原子、稳定 filesystem comparison snapshot，coverage UNKNOWN/NOT_EXECUTED。activity 基于已有 snapshot digest delta 使用原增量 Scanner；Stop 仅 finalization，缺 baseline 返回 SESSION_STOP_WITHOUT_BASELINE。旧 HANDLER_EXCEPTION 的精确异常文本未保留，历史根因不可唯一确定。

Agent Handoff：当前仅 P0-9.4。本地三路 lifecycle 已实现；new Core opt-in 不改变 Codex legacy convergence。下一工作是用户自行候选更新后的最小 Cursor Desktop 普通 timeout edit 复测；本轮停止，不开始新阶段。Cursor live continuation、三位试用、独立人工 Ground Truth 保持真实 Pending。

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

## Core P0-7.3.2 — Global workspace binding

真实只读复现：Project C cwd/大小写/slash/trailing 均解析到同一 Git root，旧 recent root hash 正确；实际异常是 active editable DEV Runtime 的 configuration_status 重新触发 INSTALLED_RUNTIME_REQUIRED，随后被 Global catch 错记为 workspace_claim_match=false / WORKSPACE_OR_REFERENCE_REJECTED，session 尚未比较。现有 COMMITTED HMAC enrollment 只读校验与新安装 DEV gate 分开，现有 server/Hook fingerprints 仍须精确匹配；setup/repair 新安装限制保留。增加 stage/reason 和 cwd/resolved/registered/session hash diagnostics，不改变严格 resolver/session/replay/bootstrap/Scanner/remediation。最终 focused 180 passed / 263.29s；full offline 1498 passed / 9 skipped / 6 subtests passed / 2034.91s，零失败，skipped 不计 PASS。[完整回归及跳过原因](workspace-binding-regression.json)。候选 wheel/sdist integrity/compliance PASS / 7.78s。真实用户配置仅只读且 bytes 不变，Project C 无源码修改/扫描；未安装/替换活动进程，未 commit/push。Desktop 新扫描待用户复测。[精确根因及验收](workspace-binding-acceptance.md)。

## Core P0-7.3.1 — Recent Hook Diagnostic

仅 observability：入口 HOOK_RECEIVED、闭合安全字段和真实阶段写入 Runtime state 的独立 SQLite hook-diagnostics.db；workspace 32 条、全库 1024 条，跨进程/重启可读，单调 marker 仅在同 process scope 内有意义。Global→child 一条记录；SDK 校验仍原样执行。hooks recent 默认当前 canonical workspace，支持 --path/--limit/--json；unbound 必须显式查询。CLI 只读，不初始化扫描/授权/基线。写入失败不改变安全行为，不重试执行原 handler。

最终观测专项 25 passed / 52.06s；最终 frozen focused 190 passed / 293.43s；完整离线回归 1470 passed / 9 skipped / 6 subtests passed / 2722.77s，零失败（runner 2723.91s）。9 skipped 单列：3 项需要显式 managed Scanner benchmark 环境，6 项需要真实 scanner binaries，不能计为 PASS。[完整回归证据](recent-hook-regression.json)。最终包 integrity/compliance PASS / 8.67s；最终临时候选安装及实际 Global stdio MCP 写入→退出→独立候选 CLI 只读读取 PASS / 51.31s，DB bytes 不变、配置生命周期/host-owned state 保留通过。真实 Desktop gate 待用户切换候选并复测，旧编辑不回填。前序 dirty 保留，未 commit/push/替换活动 Runtime/读取或修改真实 CODEX_HOME。详细生命周期和复测见 [验收](recent-hook-acceptance.md)。

## Core P0-7.3 — Codex Global Hook Host Claim Propagation

当前只修 claims propagation/binding/diagnostics。PostToolUse MCP 必须提供 turn_id/tool_use_id；生成配置同时正式传 permission_mode/native tool_input。SessionStart/Stop 各自契约，不伪造 tool-use。workspace/session 绑定也适用于 READ_ONLY Bash；连接级有限哈希重放记录拒绝同 tool_use_id 的重复/跨 session/turn/tool/root 使用，缺失/malformed 仍 fail closed。Host claims 仅证明一致性，不认证 Host 或授予 AUTO_FIX。

用户报告的 Desktop INVALID_HOST_CLAIMS 确认发生在扫描前；历史原 payload 未捕获，不能断言具体字段。旧 validator 并不要求 turn/tool-use，所以“遗漏这两项直接导致旧拒绝”不是已证明根因。已修复契约缺口和泛化错误，新增固定字段名 diagnostics，精确历史拒绝字段留待 Desktop 复测。无 transcript 恢复、无真实 CODEX_HOME 访问。[契约与验收](codex-host-claims-acceptance.md)。

本地 claims 专项 27 cases；顺序/Global/Stop 兼容专项 92 passed，重放在 classification/bootstrap 前拒绝，不创建新 session scan job。temporary venv 原生安装、Global 生命周期、Codex CLI 0.160.0 配置发现及 hooks.state/user byte preservation PASS；wheel/sdist/source byte integrity 与 compliance PASS；真实本地 stdio MCP/scanner A1/B1/A2 PASS，opaque refs 原样、实际 resolved proof，无 Deep。最终冻结 focused 419 passed / 849.26s；full offline 1445 passed / 9 skipped / 6 subtests passed / 2463.32s，零 failures；skipped 单列原因见 [回归](codex-host-claims-regression.json)，不能将此前修正前失败或中止运行当 PASS。Desktop/trust UI Pending，不替换活动 Runtime，不 commit/push；前序 dirty 保留，Scanner/remediation/Ticket/global workspace/Deep 实现字节不变。P0-8 未开始。

P0-7.2 历史证据纠正：其全量日志为 **4 failed / 1414 passed / 9 skipped / 6 subtests passed**；之后仅四项预期修正专项通过，不代表那一轮最终完整回归已通过。P0-7.3 最终冻结代码回归将单独记录，不覆盖旧日志。

## Core P0-7.2 — Codex Tool Coverage + Lazy Workspace Bootstrap

本轮已将 Global Codex PostToolUse matcher 扩展为 `^(Bash|apply_patch|Edit|Write)$`，增加可选 `tool_input` 的非敏感分类：只读 Bash 返回 `NOT_SCANNED`，可能 mutation/UNKNOWN 仍走 HookCoordinator 的真实 snapshot/digest/scanner；首次 mutation 在 SessionStart 缺失时走受限 lazy bootstrap。未触及 remediation/Ticket/Scanner/Functional/Sandbox/CET；真实 Desktop 仍 Pending，不 commit/push。

## Core P0-7.1 — Codex host-owned Hook state compatibility

仅修复配置兼容性，feature/runtime-mvp / ee1bfd9c12493683cc313cb3628753a51ae124ac 不变。不 commit/push、不替换活动 Runtime、不读写真实用户 CODEX_HOME；前序 dirty 保留，PROJECT_CONTEXT 未读写，P0-8 未开始。

已确认根因：_config 将 TOML hooks.state dict 当 event list；base/global 后续重复 Hook 检查也直接遍历所有 hooks 值。按当前官方 HooksToml / HookStateToml schema，仅对 TOML 的 state 建立明确 metadata 分支；每条 state 是 object，enabled 为 bool、trusted_hash 为 string。官方未封闭 state object 的扩展字段，保留其值；未知其它 hooks dict 不获得豁免。独立 hooks.json 保持 event-only 校验。真正 event groups/handlers、command/server/tool/input/timeout/statusMessage 校验与签名 ownership 冲突检查仍 fail closed。Runtime 不使用这些 host trust values 决定自有 ownership 或修改 trust。

只建立 event-only view，不改变原 parsed document；现有 signed managed block/CAS 合并保留 TOML 原字节，uninstall 恢复原 user bytes。state 与 node_repl、用户 inline/JSON Hook、未知 top-level 设置共存；setup/repair 两次稳定且无无意义重写。两种实际定义来源仍按既有 duplicate 检查处理；state 不算 event source。[详细验收及官方来源](codex-hook-state-acceptance.md)。

新增 25 cases；focused 160 passed / 121.85s；最终 full offline：1414 passed, 9 skipped, 6 subtests passed in 1853.57s (0:30:53)（runner 1854.15s），9 skipped 单列不计 PASS。[回归](codex-hook-state-regression.json)。wheel/sdist integrity + licenses/notices compliance PASS，[package](codex-hook-state-package.json)。temporary venv 强制安装本轮 wheel，确认 module origin 在其 site-packages，借用已有依赖、无网络下载；实际 CLI setup→setup→repair→repair→status→doctor→uninstall 全 PASS，实际 Codex CLI 0.159.2 正常解析脱敏 state 且同时发现 node_repl/ai_security_runtime。[安装验收](codex-hook-state-installed-trial.json)。修复前隔离结构 fixture 为 CONFIG_INVALID，修复后 MCP/Hook CONFIGURED；不是实际 Desktop Hook trial。

现有两份产品模块仅 narrow compatibility hunks；新增 test/fixture + MANIFEST fixture include。router/remediation/Ticket/Scanner/Deep/CET 与 incoming 字节相同；[前序工作区保留审计](codex-hook-state-workspace-audit.json)。真实 Desktop 验收仍 Pending，三位试用待验收、独立 Ground Truth 未执行，未扩大本轮范围。


## Global Integration / Install Once — 本地门禁与 Desktop 边界

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



## Core P0-6.1: Post-edit Exact Target Verification

本地既定门禁完成，停止本轮；Desktop 重试未执行。

仅 Core P0-6.1 Post-edit Exact Target Verification correctness bugfix。继续 feature/runtime-mvp / ee1bfd9c12493683cc313cb3628753a51ae124ac，168 incoming 文件已保存快照，P0-1…P0-6 前序 dirty 完整保留；不 commit/push/install/替换活动 Runtime，不运行新 Desktop E2E。

根因：原 FastFix.removal 从 raw UTF-8 bytes 计算整行 range/segment/preimage/canonical postimage SHA，但 Agent Ticket 只保留整文件 preimage 和唯一 postimage SHA。post_failure 只接受“删除风险整行、保留后续空行”的唯一结果；真实 Desktop patch 删除风险整行及其后一个空行，所以 Scanner 已观察风险消失仍无法授权 canonical proof。只读读取已有试验记录：新增/删除均 8-space statement + 1 empty line，记录无其它 changed lines；当前文件 UTF-8 BOM / MIXED EOL。完整旧 Ticket/raw preimage 未捕获，[forensic](inline-exactness-forensic.json) 中 preimage/expected SHA 与 offset **明确为重建假设**，不冒充原凭据。未发消息、未使用旧 opaque refs、未编辑或持久化真实目标源码。这是历史取证，不是新 Desktop E2E。

没有证据表明原 raw-byte helper 存在 decode→newline normalize→encode、BOM 删除、字符/byte offset、pre/postimage 混用或错误 snapshot 来源。具体 mismatch 是 following-empty-line cleanup；设计过窄而不是取消 whole-file hash 本身。构造现在复核 original file/segment/canonical result SHA 来保证同一 preimage。

新 signed edit_envelope = 原 risk physical line + 至多一个已存在的、真正空的紧邻 LF/CRLF line。不含业务代码/注释/indented blank/第二空行。预枚举 ≤3 exact byte variants：REMOVE_LINE（旧结果）、REMOVE_STATEMENT（只移除 statement，原缩进/尾部/EOL/后空行精确保留）、REMOVE_LINE_AND_EMPTY_LINE（只在原已有该空行时）。签入 range、statement range、原 segment/statement SHA、原字节总长、prefix/suffix SHA、EOL/BOM、variant segment length/SHA/whole-result SHA。所有结果从原 bytes 得到；无 post-edit normalize/fuzzy/diff/formatter tolerance/语义等价推断。新缩进/空格、whole-file EOL/BOM 改动均拒绝。

Post-edit 比较原长度定位的 prefix 与右锚定 suffix SHA，验证 envelope 内长度/segment SHA 为预枚举结果，再验证该 variant whole-file SHA；外部 byte-for-byte preservation 保持。原 HMAC、workspace/task/remediation/Episode/grant/scan/snapshot、policy/TTL/attempt、source/preservation/scope guards 原样执行。成功后仍走原当前 snapshot + TaskFix/Verification **真实原规则 Scanner recheck**，签名 receipt 才能 CLOSED；Ticket MATCHED + scanner FAILED/UNAVAILABLE 仍 INCONCLUSIVE。原 Fast Fix 单结果 contract 不变、legacy 无 envelope Ticket 保留旧严格 SHA 分支。已有旧客户端 prepare/Context hint/fallback 不变；正常 inline prepare RPC 仍 0。

非敏感 exact_target_verification diagnostics：MATCHED/REJECTED、subreason、expected preimage/current/canonical SHA、expected envelope length/actual result length/deleted bytes、prefix/suffix/outside changed、expected/actual EOL/BOM/encoding、accepted variant、preservation guard bool。无源码、Secret、byte diff、模型内容。顶层兼容 TICKET_TARGET_NOT_EXACT，子原因 TARGET_PREIMAGE_NOT_REMOVED / TARGET_RESULT_MISMATCH / OUTSIDE_EDIT_ENVELOPE_CHANGED / LINE_ENDING_IDENTITY_MISMATCH / ENCODING_IDENTITY_MISMATCH / TARGET_RANGE_DRIFT / RESULT_HASH_MISMATCH；原 ticket-binding/scope/clock/expiry reason 不改。

产品 hunk 仅 agent_fix_ticket.py + 新 agent_fix_envelope.py；新增 tests/test_agent_fix_envelope.py（48 cases）、scripts/inline_exactness_acceptance.py，MANIFEST 加一行及文档/安全报告。Security Context、Fast Fix、Hook schema/MCP names/4 claims、remediation/receipt/Family/Episode、timing、scanner/cache、Deep/Functional/BOM/CET 文件与 incoming **字节相同**。不增加 prepare RPC、新规则、daemon/bridge/build/Deep。普通 Agent 编辑仍是 post-validation，未观测 edit-and-restore ABA 不可证明，没有原子编辑承诺。

### Agent Handoff

focused：PASS: 138 passed in 811.85s (0:13:31)。

full offline：PASS: 1325 passed, 9 skipped, 6 subtests passed in 2131.43s (0:35:31)。skipped 单列不计 PASS；此前 9 skips 的 PATH/opt-in managed 条件保留，真实 Scanner 另走 SDK gate。

MCP / managed Scanner：PASS / 341.96s。[core](inline-exactness-core.json)、[legacy fallback](inline-exactness-fallback.json)、[legacy client](inline-exactness-legacy-client.json)。实际 stdio MCP + 离线 managed Semgrep/Gitleaks；Host 编辑是一次性 native fixture simulation，**不是 Desktop**。旧 P0-6 hash-verified wheel source 重现 risk absent 仍 TICKET_TARGET_NOT_EXACT/ESCALATED；新 LF/CRLF × BOM/no BOM、mixed+BOM、statement/old canonical、recurrence 取得当前 original-rule proof；邻接业务编辑在 Scanner risk absent 时仍拒绝且无 resolution。旧 refs 在 recurrence 计时后拒绝，不序列化/重建引用。正常每 cycle 2 Runtime Hook MCP、0 prepare、1独立 test Host RPC；额外状态检查 RPC 在计时后单列。每成功 cycle 仍 2 Hook SAST + 2 Hook Secret + 1 canonical rule recheck，共5真实进程 invocation；失败 envelope 在4次增量进程后拒绝、不会伪造第5次 proof。并发 focused 测试期间样本仅证明 correctness，不作性能提升结论。

wheel/sdist package integrity / licenses+notices compliance：PASS / 7.81s，[package](inline-exactness-package.json)。没有 clean install、standalone、CI 或活动替换，未请求新增这些 gate。

初轮新增 direct cases 32 passed / 1 failed：mixed EOL 改动且尺寸缩短时，诊断优先给 TARGET_RANGE_DRIFT；只修诊断分类优先级，不放宽 acceptance。下一轮 35 passed / 13 setup errors：新 module 导入 fixture 时缺少 repo fixture，补显式 fixture import，旧测试未改。修正后 48 passed（46新+2旧 inline契约）；最后再加2个合法 statement variant + scanner FAILED/UNAVAILABLE 不能关闭的 case。历史日志均保留，最终以 focused/full 为准。

Fresh Desktop 本轮 NOT_RUN，下一次仅用户自行安排加载本轮 Runtime 后，隔离 fresh chat：safe baseline → 引入唯一独立 TLS 风险及一个紧邻真空行 → Hook INLINE_PREPARED → Agent read一次并按 envelope删除风险行及该空行 → post-edit Scanner + canonical proof → CLOSED/RETURN_TO_HOST；核对 accepted_variant、outside_changed=false、原 refs逐字、prepare count0和原timing。另验证 statement-only、CRLF/BOM 原样保持，以及风险移除同时改邻接业务行仍拒绝。缺字段/stale立即停，不恢复或重建 opaque refs，不主动 build/Functional/独立扫描。

三位真实试用 Pending；Ground Truth UNREVIEWED/null；Maven PENDING_ENVIRONMENT_PREREQUISITES；Fast Host atomic bridge PENDING_HOST_ATOMIC_EDIT_BRIDGE；其它阶段 Planned。PROJECT_CONTEXT 未读写。完成既定门禁即停止。



## Core P0-6: Inline Prepared Agent Fix Ticket / Reliable Handoff

本地实现及既定门禁完成，停止本轮。

仅 Core P0-6 Inline Prepared Agent Fix Ticket / Reliable Handoff。继续 `feature/runtime-mvp` / `ee1bfd9c12493683cc313cb3628753a51ae124ac`，165 个 incoming 文件已快照；前序 P0-1…P0-5 dirty 保留。P0-5 wheel SHA `fa1a1e90ab5df6b9d2a46a2ef8b66cceb53922a07d2c1286d36a7cbc4658ef3e` 校验后仅提取源码作 A/B，不安装。用户提供 Episode 8 的 cycle 90854.049ms、continuation wait 61355.587ms、prepare 1133.092ms、约 12 次编辑前 Agent calls / 1 read / 0 search / 1693 context bytes，标 `USER_REPORTED_ACTUAL_DESKTOP`；本轮未自行复现 Desktop。

先完成 [prepare A/B 安全职责分析](inline-ticket-safety.md)：所有 POLICY_AUTO TLS **preparation** 必需项可在原 workspace 锁内完成，包括 workspace/Episode/grant/授权/预算/成员/origin scan/snapshot/source/scope、TaskFix bounded evidence、prepared attestation 与提交依赖。B 是 USER_CONFIRMED 的用户选择及实际编辑/后续 scanner receipt，不从 initial Hook 推断。原 `_prepare` 完整执行，不删检查。P0-5 历史将 prepare 保守保留为独立 RPC；本轮在此窄 eligibility 内复用同一函数到 Hook 事务，不改变 generic/confirmed prepare 或安全 proof。

只在 connected MCP Hook（可信 embedding 可显式 opt in）、POLICY_AUTO / SAFE_DETERMINISTIC_FIX / AGENT_FIX / Fast Host capability unavailable / 唯一 `ai-security.java.trust-all-hostname`、attempt 1、当前 scan/Episode/grant/snapshot/target 且唯一整行可精确删除时签发 Ticket。命令 adapter 默认保留原 prepare。正常窄路径为 Hook → 原 prepare 检查在 Hook 内完成 → structured Ticket + Context → Host read/edit → post-edit incremental scanner + 原规则 targeted real recheck → 签名 receipt / CLOSED / RETURN_TO_HOST；无额外 prepare MCP。没有 Runtime source writer、模型调用、原子编辑桥、Scanner worker、新规则、Deep/Functional/build/test/Sandbox/CET/Plus/Pro。

`agent-fix-ticket-v1` 正式字段位于 `structuredContent.remediation.agent_fix_ticket`：version/mode/fix_path、workspace_id、episode_id、grant_id、原 task_ref/remediation_ref、finding_id/origin_scan_id、security_context_ref、snapshot_digest/scope_hash、allowed_target_paths/rule_id、authorization_kind、attempt_count/max_attempts、prepared_attestation、connection-scoped 900s expiry、精确 removal operation、原文件/预期结果 SHA、ordinary Agent post-validation edit contract、real-scanner success/CLOSED/RETURN_TO_HOST 及 production UNKNOWN / no Deep。上限 4096 canonical bytes；Context 仍独立解释 What/Where/Why/建议/范围/成功条件，不成为 credential。inline Context 的 `prepare_required=false` 仅描述已签发 Ticket；原 refs 不解析重建、不改字，informational context ref 对当前小对象重新计算，不是 bearer grant。

原 authorization、2-attempt budget、membership、source/preservation、receipt binding、真实 scanner proof 保留。inline 额外要求 whole-file expected result bytes，连接内 ≤32 Ticket + 单调 TTL + policy revision binding。磁盘仅存签名 attestation HMAC/状态/固定原因，绝不恢复 live authorization；重启丢 Ticket/prepared，不伪造延续。unexpected target、额外文件、expiry、wrong binding、lost attestation 不能 CLOSED；观察到 stale 后持久拒绝，不被后续 manual-recovery Hook 漂白。未编辑且原 freshness 仍有效时，可用**原两个 refs**走 legacy prepare 重新检查并替换未消费/过期 preparation；可不传 hint，旧 Host 也可传当前 inline Context ref，Runtime 在完整原检查内从当前事实重建这个 informational 对象（只差 prepared flag），不是从 hint 接受授权。已 drift/escalated 要刷新当前任务，不盲目重试旧授权。已签发 CLOSED security proof 不被 Ticket expiry/重连或 Deep unavailable 降级。

没有 Host 原子编辑锁，未观测的 edit-and-restore ABA 无法证明，旧 prepare 同样无法检测；不声称阻止每次外部写入或证明模型读了哪份 Ticket。可观测的异常编辑被当前字节/snapshot/其它文件 preservation 和编辑后 scanner 阶段拒绝。完整 machine Ticket 不依赖 prose：测试删除或截断文本后仍从原 structuredContent 完成闭环。官方 [Codex Hooks](https://learn.chatgpt.com/docs/hooks) 于 2026-10-05 实际读取，说明 MCP 与 command Hook 输出契约一致、大输出可 spill/truncate；没有 arbitrary structuredContent 独立向模型展示的官方保证。保留正式 SDK 字段，同时 documented additionalContext 只投影完整同一 Ticket/Context 与短固定说明，去掉重复 refs/报告/scanner diagnostics。**SDK 完整性 PASS 不等于 Desktop 模型一定见到完整对象**，其 gate 仍 Pending；不改 config/schema/四个输入 claims，不猜官方字段。

observability：agent_fix_ticket_version/mode、prepare_task_fix_required、Runtime 工具函数入口计数（当前 grant/当前连接）、handoff_recovery_required、structured_handoff_complete、inline_prepare_reason、ticket_stale_reason/ticket_status；Host retry/read/search/model CPU 未观测仍 null。P0-3 timing 保留：inline_prepare_started/finished 在 initial runtime 内；独立 inline_host_edit_window 为 response-ready→post-edit Hook，混合 Host/Agent/transport，不叫模型 CPU。正常 inline 不制造 prepare MCP/Host received 端点；旧 prepare windows 为 null，不重复相加。recurrence 独立新 Episode/grant/scan/Ticket；相同字节的 snapshot digest 可以相等，隔离靠新身份，绝不伪造 hash。

### Agent Handoff

focused：PASS: 112 passed in 823.71s (0:13:43)。

full offline：PASS: 1277 passed, 9 skipped, 6 subtests passed in 2174.36s (0:36:14)。skipped 单列、不计 PASS；3 个 opt-in managed benchmark、6 个 PATH scanner 环境条件，真实 managed 引擎另走本地 SDK gate。

actual MCP + managed Scanner A/B：PASS / 69.9s；package wheel/sdist integrity + licenses/notices compliance：PASS / 4.09s / 108 Runtime source bytes checked。没有 clean install、standalone 重建、CI trigger、commit、push、活动 Runtime 替换或 Desktop E2E。

| Path | Episode | Runtime MCP | prepare | simulated Host steps | Context/Ticket bytes | cycle ms |
| --- | ---: | ---: | ---: | ---: | --- | ---: |
| before | 1 | 3 | 1 | 3 | 1699/0 | 13371.98 |
| before | 2 | 3 | 1 | 3 | 1699/0 | 13365.653 |
| after | 1 | 2 | 0 | 2 | 1700/2166 | 13616.619 |
| after | 2 | 2 | 0 | 2 | 1700/2166 | 13857.157 |

相同模拟 Host：1 target read、1 edit、0 search，两版本仅 prepare 步骤不同。独立 test Host edit RPC 每 cycle 1 次，另列、不隐藏。Runtime MCP 3→2、prepare 1→0、fixture步骤3→2；每 cycle 仍2 Hook SAST + 2 Gitleaks + 1 original-rule recheck，共5实际进程 invocation，不取消扫描。两个 Episode 均原 task/grant 对应 resolved receipt，旧 Episode refs 另在计时后拒绝。无 LLM/sleep/network，最终 driver 在离线回归结束后串行运行；此前并发报告另存 inline-ticket-core-concurrent.json，有限样本，不证明真实 Desktop/模型提速，不能拿用户的12次工具数作模拟 baseline。

新增 agent_fix_ticket.py、tests/test_agent_fix_ticket.py（当前37 cases）、scripts/inline_ticket_acceptance.py、inline-ticket-safety.md。修改 remediation.py（原 prepare 复用、签名 requirement、post gate、fallback lock）、mcp_server.py（标准 MCP 窄路径启用）、codex_mcp_hook.py（正式 Ticket / bounded text projection）、host_guidance.py（优先 Ticket 分支）、hook_timing.py（不重叠 inline 窗口）、MANIFEST.in（一行 script）和既有五份文档。旧测试原文未改；fast_fix.py/fix_context.py/TaskFix/Verification/scanner/cache/Functional/BOM 字节不变。11个 ref/receipt/Episode/guard/grant/security recheck 函数 AST、官方 Hook config/output filter AST 不变。_verify 只增 Ticket post gate；原安全校验仍执行。incoming 审计和 source freeze 见 .security-runtime/p06-scope-audit.json；PROJECT_CONTEXT 未读写。

初轮新增 fixture 把 Windows CRLF 改成 LF，精确字节保护拒绝（1passed/1failed）；修测试不放宽校验。其次错误使用不存在的 mode advisory（20passed/1failed）、期待旧 verify wrapper 输出内部 superseded 原因（22passed/1failed），均只修新测试；旧 API generic INCONCLUSIVE 保持。首次 SDK driver 错误要求所有 legacy MCP 工具均 structuredContent，尚未完成 A/B；修 driver，Hook Ticket 仍严格用原 structuredContent，旧 prepare text JSON envelope 按既有协议读取。一次带空格 pytest -k 的 Windows quote 失败/no tests，不计门禁。32case initial complete PASS/152.62s 后增加2 scanner failed/unavailable case；计时修正前兼容focused108passed/404.13s。MCP明细发现post policy误扣上一Hook preparation detail，仅扣当前inline span修正，另加1 accounting case；对应focused40passed/191.06s。其后发现P0-5 Host继续prepare+inline hint兼容问题，修为从当前事实重建informational hint，不放宽授权；定向5passed/18.65s。修正前全量347.05s主动停止return130，不计PASS。新增总37case；最终以final-focused/full为准。初轮MCP/package/fallback另存 before-timing-correction，计时后/兼容修正前报告另存 before-hint-correction，不覆盖错误/历史证据。

最后的 full-before-guidance-correction 实际完成为 1275 passed / 1 failed / 9 skipped / 6 subtests passed（1678.99s），唯一失败是旧 Host 指引契约要求的 `Immediately follow prepare → edit → verify` 大小写。保留原断言，仅修产品 conditional guidance 的句首；原测试单独重跑 1 passed / 0.34s。试图停止该已结束专用 wrapper 被 absent/ambiguous 安全保护拒绝，没有停止其它进程。最后审阅另发现 native Fast 分支不应带 Agent PREPARE_REQUIRED 诊断，仅将新的 offer 限定 AGENT_FIX、保留 Fast 原实现；新增兼容 case 使用 Host fixture edit + 原核查路径（单元测试 provider），1 passed / 6.73s。中止 release-full 专用子进程、保留日志，冻结最终源码后重跑 certified-focused/full；不把此前失败或中断记录改成 PASS。

Fresh Desktop P0-6自然续行/模型看到完整Ticket、p95/p99、三位真实试用仍 Pending；Ground Truth UNREVIEWED/null；Maven PENDING_ENVIRONMENT_PREREQUISITES；Fast Host atomic bridge PENDING_HOST_ATOMIC_EDIT_BRIDGE。其它阶段继续 Planned。当前无需继续压缩 Security Context；先验证本轮 Ticket 自然交接，不能把协议减少一次 RPC 宣称模型已少12次调用。

下次人工 Core E2E（本轮未执行）：用户自行安排加载本轮 Runtime 后，新建隔离 Java 项目与 fresh Codex chat；普通安全编辑建立 baseline，再只引入 standalone always-true hostname override。确认初次 Hook 的 INLINE_PREPARED、完整两个原 refs/attestation/context/target、prepare_required=false、工具调用计数0；Agent只read该target和删除该行、保留所有其它字节。不主动扫描/prepare/Deep/build。确认post Hook真实Scanner原规则proof、matched task/grant receipt、CLOSED/RETURN_TO_HOST、计数仍0和inline cycle窗口。再引入同family核对新Episode/Ticket/scan/grant、旧ref拒绝。遇到缺失/截断/stale字段停止，不从路径重建引用；记录实际Host工具数及wall-clock，若仍恢复summary则保留失败事实。



## Core P0-5: Agent Fix Context Compression

本轮实现和本地验收完成：focused 205 passed；full offline 1240 passed / 9 skipped / 6 subtests passed；实际MCP+managed Scanner A/B、Fast兼容、wheel/sdist integrity/compliance均PASS。Context实测1699 UTF-8 bytes / 47递归JSON keys（上限3072 bytes）；修复信息投影减少41.18%，未证明LLM或wall-clock提速。未执行Desktop E2E、未替换活动Runtime、未commit/push；本轮停止。

仅Core P0-5 Agent Fix Context Compression，继续feature/runtime-mvp/ee1bfd9c12493683cc313cb3628753a51ae124ac与前序全部dirty；162文件incoming快照，P0-4 wheel SHA85576795657bba49bd1380bc1471097630e8f57cb7ed80f1de976f14b712accc只读校验/提取为本地A/B baseline，无安装。Fast Fix文件原bytes保留，PENDING_HOST_ATOMIC_EDIT_BRIDGE；不扩第二条规则、不新增Scanner/daemon/Functional/BOM/CET/Sandbox/Plus/Pro。Runtime仍不写项目源码，Host编辑。

Security Fix Context v1只在POLICY_AUTO + SAFE_DETERMINISTIC_FIX + AGENT_FIX的单条TLS信号启用。共用原RULE/source_proof/_reference/TaskFixService及canonical proof；不新增修复语义。what为rule/CWE-295/当前severity/confidence/class；binding为workspace/Episode/grant/origin scan/finding/snapshot；target为唯一relative file与scanner起止行，可靠symbol未知null；why为固定API与三项既有scanner/本地JDK corroboration依据，不转发scanner message/dataflow/source。recommendation为受限删除override模式（not_a_patch），scope只该installation/1file/32KB且保留其它代码文件；success要求当前snapshot与原规则真实复扫、匹配receipt/CLOSED/RETURN_TO_HOST；context不是credential，生产可达性仍UNKNOWN。

初次Hook携带短context与informational security_fix_context_ref；prepare/verify/Stop handoff仍原两个task/remediation opaque values逐字保留，不改参数字典或重记continuation。仅保留context的Host可在prepare_task_fix调用额外传可选security_context_ref，其值为原context ref；不能让所有旧调用/verify/Deep继承未知参数。接口向后兼容：无hint（包括Stop fallback）返回INLINE compact context；匹配hint时在原ref/snapshot/source/preservation/budget门禁内重建并核对，REUSE_HOOK_CONTEXT仅回指事实，不重复整段信息；不匹配REFRESH_REQUIRED且无prepared attestation。hint单独不能授权，没有remediation grant时固定拒绝；context/ref不持久化，不成为新grant或缓存proof。所有generic selected-task以及USER_CONFIRMED preparation保留旧完整接口；legacy host_protocol.instructions保留短Core结束语，不重复guidance。POLICY_AUTO packet的旧报告/代码excerpts不再输出，bounded_evidence只保留UNTRUSTED_CODE locator兼容标记，不是source packet。

### Agent Handoff

新增test_fix_context.py 11functions/21cases；已有host orchestration及Code Mode契约测试只将smart_auto长prose断言替换为context/自动授权/不重复编辑/实扫等协议语义断言，ask_before_fix与其它旧tests保留。final focused PASS：205passed/822.16s（wrapper823.30s）；final full offline PASS：1240 passed, 9 skipped, 6 subtests passed in 1991.19s (0:33:11)（wrapper 1992.56s）；9 skipped单列BF，不计PASS。第二轮全量早期发现Code Mode旧测试要求stopReason重复完整guidance，单测1failed/4passed/21.99s；仅将该smart-auto文字断言改为精简协议语义，保留completed-edit/授权/两原refs/confirmed/Stop/ABI检查，产品代码未变。第二轮focused/full分别383.65/384.07s中止return130，不计PASS；修正后该模块5passed/19.71s。第三轮focused发现新增context把VALID AI review误判为Scanner过期，既有receipt单例1failed/3.76s；修正仅删除新增review-status条件，原grant/snapshot/source/ref与receipt校验未改。第三轮focused/full分别1139.69/1139.58s中止return130，不计PASS。随后context+receipt 47passed/1failed/316.60s为新fixture伪造VALID但缺ai_review时错误期待授权；已改为断言原TaskFix拒绝且不建立prepared，既有receipt测试原文保留。第四轮full200.13s中止return130，不计PASS。最终focused聚焦直接受影响7模块/205cases，先通过再跑full；新增仍21cases，完整1249收集/9skipped。final MCP A/B PASS/118.06s；原Fast/recurrence/fallback compatibility PASS/112.33s；package integrity/compliance PASS/7.28s，107Runtime文件bytes核对，dist/agent-context-final，无安装。初轮3failed/104passed为新测试过宽source子串及既有_fail无status断言错误，已修；诊断1failed/1passed，v2 context19passed/104.71s。后发现legacy instructions字段缺失、prepare arguments新增hint泄漏到旧verify/Deep/Stop消费者；已修正原两个args与短legacy字段。隔离诊断18passed/1failed/22.15s；失效门禁focused/full在631.58/631.65s中止return130，不计PASS；兼容复核129passed/457.00s。首轮MCP/package/Fast evidence另存initial；并行负载A/B另存concurrent，修正前串行证据另存；final与focused并行重测。产品/测试/脚本158文件冻结。

真实managed Scanner+actual stdio MCP；Host是SIMULATED_WINDOWS_NATIVE_EDIT_FIXTURE，无LLM、无sleep、offline。相同facts+guidance投影8203→4825bytes（减少41.18%），非整个Hook wire payload；final与focused并行负载，修正前串行报告另存agent-context-core-before-review-correction.json；1699bytes为新context本身，legacy不存在该schema故null。MCP主流程仍3=风险Hook/prepare执行前门禁/修复后Hook；额外Host fixture edit RPC单列1，不隐藏成0；Scanner每cycle仍3SAST+2Secret。before cycles23391.335/21004.801ms，after22553.257/22981.665ms。有限样本不证明wall改善，不声称reasoning加速或Host动作减少，固定Host双方同为1read/0search。recurrence旧ref拒绝在已测cycle结束后另作诊断，不混入比较。Runtime context构造有新增绑定/成员校验成本，Scanner/运行波动也存在；未测完整归因，不将全部差值归因模型或context CPU。初轮8203→4424byte报告早于兼容修正，不替代final；并行版119.93s只单列。

12个关键ref/receipt/Episode/guard/grant/_verify/_security_recheck函数AST与P0-4相同，Fast文件bytes及官方Hook config/output AST不变。全部前序未提交代码保留，PROJECT_CONTEXT未读取/修改。门禁/记录完成，本轮停止，无commit/push/活动Runtime替换/Desktop E2E；详见[BF](AI_TRIAGE_ACCEPTANCE.md#bf-core-p0-5-agent-fix-context-compression)。三位试用Pending、GroundTruth UNREVIEWED/null、Maven PENDING_ENVIRONMENT_PREREQUISITES、p95p99 NOT_MEASURED保持。

## Core P0-4: Deterministic Fast Fix Path

继续feature/runtime-mvp/ee1bfd9c12493683cc313cb3628753a51ae124ac，进入159个Python/五文档/manifest/pyproject文件快照.security-runtime/p04-review/incoming；全部前序dirty保留，P0-3的224文件基线审计，10个receipt/ref/Episode/grant函数AST保持。用户最新真实Desktop Episode7 cycle44281.864ms、initial6272.197、continuation18309.843、prepare773.952、Host修复12169.960、post-edit3614.465、recheck2986.286、finalize155.160，为USER_REPORTED_ACTUAL_DESKTOP，非本地SDK结果。近30.48秒为混合跨Host窗口，不能称模型CPU。

2026-10-05实际读取[OpenAI官方Hooks](https://learn.chatgpt.com/docs/hooks)：MCP Hook调用已连接server并遵循Hook输出协议，PostToolUse的additionalContext/continue:false提供模型可见反馈；PreToolUse updatedInput只能重写已排队工具。未发现PostToolUse响应能直接启动原生edit、检查当前Episode并原子CAS的官方契约。现有Codex Runtime integration也只输出反馈、四个metadata claims与Agent handoff，apply_patch无whole-file digest CAS参数。因此默认Codex严格保持AGENT_FIX/FAST_FIX_HOST_CAPABILITY_UNAVAILABLE；未实现、未宣称Codex machine-executable或无LLM apply。

Fast Fix仅支持POLICY_AUTO + SAFE_DETERMINISTIC_FIX + ai-security.java.trust-all-hostname + 一个<=32KB UTF-8 Java文件内、scanner坐标 corroborated 的唯一整行inline true lambda。复用原source_proof/preservation_proof和原grant，不扩规则、不新增scanner/policy。更窄REMOVE-only排除多安装、注释混行、多行lambda、非JDK receiver、类型遮蔽/重赋值/global TLS。Runtime只读取/规划/授权/核查，不写目标源码。Host执行编辑。

可信Host embedding声明ATOMIC_BOUND_EDIT_V1（排除写/rename、在该区域内校验当前授权、exact bytes CAS、 mismatch无写、正常PostToolUse）才可随风险响应取得连接内已授权Fast Fix Plan。无MCP/env capability opt-in，无新生产MCP工具。模拟Host为单独acceptance脚本的Windows kernel deny-write/delete fixture，不是Codex API或活动Runtime配置。

### Agent Handoff

新增test_fast_fix.py共44cases（18functions），最终focused PASS：392 passed in 1003.12s (0:16:43)（wrapper 1004.17s）；final full offline PASS：1219 passed, 9 skipped, 6 subtests passed in 1450.17s (0:24:10)（wrapper 1451.03s）；9 skipped单列如下BE，不计PASS。final local MCP + managed Scanner PASS/93.04s（无sleep，无model、network或Deep）；四个cycle均真实resolved/CLOSED，含Fast recurrence与篡改plan后的Agent fallback。final wheel/sdist/package integrity/compliance PASS/5.82s，106Runtime文件bytes一致，dist/fast-fix-final；未安装。首轮测试接线/文本拼接/CRLF断言修正、首次sdist缺脚本、为严格JSON防篡改中止的旧门禁均另列BE，不算PASS。 产品/测试/脚本155个Python文件冻结，详见[BE](AI_TRIAGE_ACCEPTANCE.md#be-core-p0-4-deterministic-fast-fix-path)。默认Agent prepare保持，Fast只在注册bridge的fixture不需二次prepare；仍post-edit scan+canonical原规则复扫。Fast不存在的prepare窗口为null，Host等待放入host_fast_apply_window，不隐藏。restart/reconnect丢Fast Plan/attestation/timing，历史budget不重置。门禁与记录已完成，本轮停止，不commit/push/替换活动Runtime，不自行Desktop E2E、不扩第二规则、PersistentScanner/Functional/BOM/CET/Sandbox/Plus/Pro。三位试用Pending、GroundTruth UNREVIEWED/null、Maven PENDING_ENVIRONMENT_PREREQUISITES、p95p99 NOT_MEASURED保留；PROJECT_CONTEXT未读取/修改。

## Core P0-3: AUTO_FIX Continuation Latency Observability

继续feature/runtime-mvp/ee1bfd9c12493683cc313cb3628753a51ae124ac，保留P0-2.1与所有前序dirty。用户真实Desktop风险Hook约3670/scanner2840/recheck2880ms、cycle约36170ms，为USER_REPORTED_ACTUAL_DESKTOP_TIMING；缺少那一轮内部端点，无法将余下时间归因模型/传输/编辑或相加旧窗口重建。六文件误操作已停止：当前231文件快照.security-runtime/p03-review/incoming与哈希验证过的上一轮wheel/sdist基线逐hunk比较，未reset/restore/clean。六文件合理的计时入口/输出/验收意图保留；修正跨workspace/session兜底、错误Host发送/编辑语义、跨instance/frozen标记、重复相加与未验证prepare影响观测等缺口。

新增cycle端点/互不重叠窗口、非加总scanner/policy/auth细节与边界分类。单调perf_counter，连接内<=32；当前Episode绑定，retry不重启，初次完成冻结，recurrence新起点；restart/reconnect未知。prepare只有原ref通过并READY才能归属该Episode。响应ready不声称sent，fix Hook entry不声称源码编辑结束；模型CPU/Host收到/MCP传输精确时间UNKNOWN。timing失败不影响原安全proof/状态。11个关键receipt/ref/episode/grant函数AST与P0-2.1一致；其余前序产品源码bytes一致。

### Agent Handoff

产品/测试/公开脚本已冻结；新增test_continuation_timing 21cases（保留误操作4项意图、扩展17）。初轮focused98passed/180.43s，后续补充项纳入final；最终focused 348passed/782.04s；full offline 1175passed/9skipped/6subtests passed/1206.43s；本地MCP simulated Host PASS/65.10s，两Episode（direct prepare/Stop fallback）分别cycle 14353.014/15369.367ms，均真实Scanner resolved/CLOSED/RETURN_TO_HOST，functional 0、build/test/sandbox false。final wheel/sdist/package integrity/compliance PASS/4.57s，105Runtime文件bytes核对一致，独立dist/continuation-latency-final；未安装。初轮MCP/package另存initial证据，不能替代final。v1三项诊断WAIT标签冲突及中止的full如实见BD，旧断言未改。 SDK初轮缩进错误已修正，错误启动不计PASS。真实结构/误操作审计/阶段边界见[BD](AI_TRIAGE_ACCEPTANCE.md#bd-core-p0-3-auto_fix-continuation-latency-observability)。不commit/push/替换活动Runtime。Deterministic Fast Fix Path仅分析，不实现；不进入PersistentScanner、Functional、BOM、CET、Sandbox、新scanner或Plus/Pro。fresh Desktop新分解、p95/p99、三位试用Pending；GroundTruth UNREVIEWED/null、Maven PENDING_ENVIRONMENT_PREREQUISITES保留。本轮门禁与记录完成，停止；HEAD/branch未变，工作区仍包含完整前序dirty，PROJECT_CONTEXT未读取/修改。


## Core P0-2.1: Cache Lifetime & Scanner Invocation Reduction

继续 feature/runtime-mvp / ee1bfd9c12493683cc313cb3628753a51ae124ac，保留 BB 与所有前序 dirty 实现。用户最新 Desktop：连续安全编辑 hook约3554/scanner2961ms、版本/config/pack HIT；后续TLS首次 scanner5325ms、全部MISS、Semgrep invocation2519ms、Gitleaks process_invocations5；resolved Hook7013/recheck3139ms。USER_REPORTED_ACTUAL_DESKTOP_TIMING。没有此前 Runtime instance/PID/raw target 记录，不能唯一判断 Host 自动重启还是对象重建，也不能猜五个文件名。

本轮复现对象级 cache 重建导致全部MISS，改为有界 process-local preparation buckets；每次仍做内容/workspace/config/version校验，新Scanner进程与 proof 必需。Hook及live Scan诊断新增 runtime_instance_id/cache_generation/cache_scope；工厂/registry重建保留，真实进程重启清空。Gitleaks原每文件一次 dir，改为多文件受控临时镜像一次 dir，保留完整scope、相对路径、脱敏与清理，不目录扫描用户仓库、不关闭Secret扫描。

remediation_cycle_wall_ms为首次风险Hook入口到已提交 scanner resolved/CLOSED/RETURN_TO_HOST决策的单调端点差；包含Host continuation，不累加六个既有timing阶段。同Episode冻结第一次完成，新Episode新起点。连接内32个观测，重连/重启缺少起点明确UNKNOWN，无时间/源码/Secret/refs持久化，不参与授权或安全判断。Core no Deep、Family/Episode/预算/opaque refs/receipt与setuprepair保持。

### Agent Handoff

实现和既定门禁已完成：最终focused485passed/774.14s；full1154passed/9skipped/6subtests passed/1558.46s，跳过单列。新增真实managed测试2passed/43.89s、既有managed兼容test1passed/13.89s；package/compliance PASS（105文件，6.46s）。本地MCP三次安全编辑及两Episode闭环PASS/56.68s，cycle12730.601/12721.181ms；driver模拟Host且含既有cooldown等待，不是Desktop模型体验。串行scanner对照：cold7835.689→8115.247ms未改善，warm2 4617.868→4528.311ms、warm3 4457.043→4425.323ms改善小；registry重建7592.651→4220.139ms，五目标Gitleaks5次→1次（invocation总2578.249→502.758ms）。初轮并发bucket引用问题已修正、坏初始数据保留，不当最终PASS。Semgrep固定invocation仍是主因：串行bench3.35–3.88s、独立SDK2.44–2.90s，不能混作CPU或延迟承诺。详见 [BC](AI_TRIAGE_ACCEPTANCE.md#bc-core-p0-21-cache-lifetime--scanner-invocation-reduction)。不commit/push/替换活动Runtime；无daemon/worker/新scanner/Functional/BOM/CET/Sandbox/Plus/Pro。Desktop新字段复测、真实项目p95/p99/三位试用Pending；Ground Truth UNREVIEWED/null，Maven环境PENDING_ENVIRONMENT_PREREQUISITES。完成本轮门禁与记录后停止，外部PROJECT_CONTEXT未读取/修改。


## Core P0-2: Scanner Hot Path Performance

继续 feature/runtime-mvp / ee1bfd9c12493683cc313cb3628753a51ae124ac，保留前序全部未提交实现。最新用户真实 Desktop timing：安全编辑 hook_total5777.198/scanner5009.189/policy146.845ms；AUTO_FIX resolved Hook9890.613，scanner4268.245/recheck4900.597/preparation788.943/policy323.543ms。此为 USER_REPORTED_ACTUAL_DESKTOP_TIMING；13045.887ms auto_remediation 是Host窗口，不能加进Runtime total或当Scanner CPU。本轮优化后 Desktop PENDING_ACTUAL_DESKTOP，不能用 SDK driver 覆盖。

实际 managed Semgrep1.178.0/Gitleaks8.30.0 baseline证明1 Java文件、21规则：重复Semgrep --version约1.7s、scan invocation约2.4s、规则验证约67ms。当前增加 scanner_diagnostics，缓存正向版本探测（仍每次校验artifact/content/env/workspace身份）、validated规则元数据/target-content-bound plan template/selected config文本；连接内有界，不缓存scanner结果或confirmed/scanned proof。Hook与Remediation共享准备registry；仍每次新scanner进程。复扫1文件、1原规则，保留checksum/版本兼容、覆盖/错误与原receipt/snapshot/episode校验。quick Hook不重复调用Git.changed_files；保留dirty+formerlydirty/candidate union用于Family收敛，不冒险缩减为仅最后一次编辑。

门禁结果与 before/after实际数据见 [BB](AI_TRIAGE_ACCEPTANCE.md#bb-core-p0-2-scanner-hot-path-performance)。初步176passed、新缓存/episode66passed；最终focused406passed/545.71s，full1137passed/7skipped/6subtests passed/1087.19s（skip单列），显式真实managed性能test1passed/14.31s。package/compliance PASS（104打包文件，3.84s），本地MCP两个episodePASS/46.34s/功能调用0。最终串行managed三样本medians：安全scan4672.122→3206.097ms、风险4545.742→2983.128ms、原风险recheck4319.427→2569.356ms；MCP safeHook5142.138→3533.367ms、resolvedHook10097.094→6868.439ms。并行负载较慢原始记录另存，不当Desktop收益或p95承诺。无常驻worker/daemon、新scanner、Functional/BOM/CET/Sandbox/entitlement扩展。

### Agent Handoff

保持Core原安全闭环与BA default no Deep；receipt binding、Family/Episode预算、refs、Hook/MCP名称/config/setuprepair不变。新时钟边界不能可靠区分Python启动与规则执行，actual_scanner_execution=null；engine_reported_*分列，不能拼出CPU耗时。state_persistence是提交后live诊断，DB中的该项为null，不额外重写scan或改变signed identity。当前工作不commit/push/替换活动Runtime，活动版本不变；优化后Desktop/真实项目p95p99/三位试用Pending，Ground Truth UNREVIEWED/null，Maven环境PENDING_ENVIRONMENT_PREREQUISITES。本轮必要门禁/记录已完成，停止。外部PROJECT_CONTEXT未读取/修改。版本0.3.1/contract不变；将来确认加载新实现须看scanner_diagnostics，不能凭版本号。

## Core P0-1: Hot Path Policy & Integration Hardening（2026-10-04）

继续 feature/runtime-mvp / ee1bfd9c12493683cc313cb3628753a51ae124ac；前序 episode/Host verifier/BOM/receipt 未提交实现全部保留。默认链路固定为编辑 → Hook quick 增量扫描 → Finding/Policy → 必要 AUTO_FIX/原引用 prepare → Host 最小修复 → 原风险安全复扫 → SCANNER_VERIFIED_RESOLVED/CLOSED → RETURN_TO_HOST。默认不自动进入 Functional Verification、build/test、Full Scan、Security Regression、Sandbox 或业务深审。Deep MCP/API 保留；只有本连接明确请求 prepare_functional_verification，后续 verify_task_fix 才合并功能结果。Security VERIFIED 独立成立，缺少 Deep 工具/能力不阻止 Core readiness。

新增六阶段 timing_ms，真实 monotonic 测量；null 表示未执行/未观测，不复用缓存旧耗时。auto_remediation 是本连接 prepare 完成到下一 Hook 入场的 Host continuation window，包含模型/传输/停顿/编辑，不是编辑 CPU 时间；各调用与阶段不能相加当端到端总计。无源码/Secret/模型内容持久化，原授权与状态机保留。支持 HOOK/MANUAL/STOP/PR/CI/SCHEDULED trigger vocabulary，未建设 entitlement 或调度器。

setup/repair 复现并修复旧版本 block、CRLF、重复已签名自有 MCP table 和精确旧 POC/command Hook 的迁移缺口。仅 signed manifest + block/server fingerprint，或已有 Git 管理标记 + 精确旧生成器构成归属证据；保留用户 MCP 原字节和自定义 Hook handler/event。健康 setup/repair 不重写，第二次 repair 稳定。无所有权证明或修改过的同名配置仍 fail closed。未取得用户失败时原始配置/manifest，不能声称已证明其唯一 Desktop 根因。

门禁及真实数据见 [BA](AI_TRIAGE_ACCEPTANCE.md#ba-core-p0-1-hot-path-policy--integration-hardening)。新增18项；最终focused **272 passed，413.00s**；full offline **1112 passed /6 skipped /6 subtests passed，1132.03s**，跳过另列，不计PASS。wheel/sdist/package integrity/compliance PASS（3.86s，103打包文件bytes一致）；实际本地 SDK/已有离线 Scanner 两个 episode PASS（67.72s），功能调用0、无 build/test/sandbox。安全编辑 Hook 5.726s，resolved Hook 11.709s，其中 scan 5.299s/recheck 5.546s。这是模拟 Host 驱动，不是 Desktop 自然模型续行；尚不能声称已满足常开不打断。

### Agent Handoff

当前本节/BA 优先于下方历史默认功能验证指导。实现、既定门禁及记录完成，停止本轮。不 commit/push/安装/替换活动 Runtime，无新 CI。0.3.1 版本号不足以证明加载本轮代码，需检查 runtime-info.execution_timing。fresh Core Desktop、实际项目延迟/p95/p99、三位试用 Pending；Ground Truth UNREVIEWED/null、质量 NOT_MEASURED；Maven A/B PENDING_ENVIRONMENT_PREREQUISITES。不安排 Functional Desktop E2E，不扩展 BOM/CET/verifier/sandbox/scanner/商业权限。外部 docs/PROJECT_CONTEXT.md 未读取/修改。

## Deep Verification protocol correctness fix（2026-10-04）

继续 `feature/runtime-mvp` / `ee1bfd9c12493683cc313cb3628753a51ae124ac` 的既有未提交工作，本轮仅修 `SECURITY_RECEIPT_REQUIRED_REFRESH` 生命周期。用户真实 Desktop 的 scanner resolved/CLOSED 后 refresh 为 **USER_REPORTED FAIL**。已复现旧实现把动态 AI review 的 UNTRIAGED 状态当作 resolved proof 的读取条件，以及不校验 resolution 的 scan/scope 绑定；缓存 Hook 还可能携带原风险 scan ID。失败调用的原始 opaque refs/具体 gate 未留存，因此不能声称已还原用户那次失败的唯一触发条件。只读实际 fixture 可确认历史/current episode 分离；未修改其源码或状态。

现在在安全关闭的原子提交中保存 signed resolved-security-v1 binding；functional prepare/run/finalize 校验当前 workspace/task/grant/episode/origin scan/目标 scope/resolved scan/snapshot。原始 ref 格式不变，不重建 Host 引用。动态审阅 freshness 不再否定已成立的 scanner proof；旧 episode、错误 scope、旧 scan 与 changed proof 均拒绝。prepare 与状态提交共享 workspace lock；重复安全复核保留同一有效 proof identity。失效给出固定具体 receipt reason，并保留独立 security resolved 事实。旧格式正向安全事实保留，但功能授权前必须用原引用实际 verify_task_fix 补齐 binding，不自动伪造 proof。

本轮定位为 **Deep Verification protocol correctness fix**。Core 产品默认方向为增量安全扫描 → Finding/Policy → 必要 AUTO_FIX → 安全复扫 → 返回开发者。Functional/Build/Test/Sandbox 保留未来 Plus/Pro/Manual/Stop/PR/CI Deep Verification 基础设施；本轮不迁移既有 Hook guidance、不新增或强化其功能验证路径，不删除现有计划能力，不扩展 verifier、BOM、CET 或 sandbox。测试最终结果见 [AZ](AI_TRIAGE_ACCEPTANCE.md#az-deep-verification-protocol-correctness-fix)。

### Agent Handoff

本轮新增27项；最终 focused **319 passed，864.01s**；full offline **1094 passed /6 skipped /6 subtests passed，1456.64s**，跳过单列于 AZ，不计 PASS。测试与记录完成，停止本轮。保留前序未提交实现；不 commit/push/替换活动 Runtime，不安排新的真实 Desktop BOM/Functional E2E。三位试用仍 Pending，独立 Ground Truth UNREVIEWED/null、质量 NOT_MEASURED；真实 Maven A/B PENDING_ENVIRONMENT_PREREQUISITES，不搭建/下载环境。下方 AY/AX 等为历史，当前范围以本节/AZ及最新用户产品定位为准。

## javac UTF-8 BOM compatibility（2026-10-04）

继续 feature/runtime-mvp / `ee1bfd9c12493683cc313cb3628753a51ae124ac`，保留前两轮未提交工作。最新用户真实 Desktop E2E：检测/AUTO_FIX/scanner resolved/Host javac 执行/结果回传/安全功能独立均 **USER_REPORTED PASS**；原文件 UTF-8 BOM 导致 exit1、最终 FUNCTIONAL_INCONCLUSIVE 为 **USER_REPORTED FAIL_BOM**。这是对 AX 的后续实机反馈；不能继续把所有 Host 编排视为未验证，也不能据此声称本次 BOM 修复已通过 Desktop。

本轮仅 FunctionalVerificationService 的 javac Host plan 处理 BOM：严格 UTF-8 检查，仅去除一份临时副本的开头 BOM；目标相对路径/package 保留，javac 只编译临时目标，产物仍在项目外。本轮 source_handling=ORIGINAL 或 TEMPORARY_BOM_NORMALIZATION、source_modified=false 可在 plan/functional 结果/缓存/final verify 区分；成功仍 COMPILE_ONLY，安全事实不变。未知编码/NUL/重复 BOM 为 INCONCLUSIVE，不修用户源码、不下载依赖、不改 CET/Hook/MCP 输入或新 sandbox。只使旧 javac 结果缓存失效，其他 provider 缓存不变。

新增13项 BOM 测试；最终 focused **107 passed，16.30s**。实际本地 MCP/离线 Scanner/已有 JDK 的 BOM A/B **PASS，102.79s**，仅 SIMULATED_NATIVE_HOST_DRIVER；A成功COMPILE_ONLY，B真实错误FAILED，安全均resolved。最终完整离线回归 **1067 passed /6 skipped /6 subtests passed，1244.51s**，六项真实扫描器 PATH 前提缺失单列于[AY](AI_TRIAGE_ACCEPTANCE.md#ay-javac-utf-8-bom-compatibility)。本轮未 commit/push/安装/替换活动 Runtime，外部 docs/PROJECT_CONTEXT.md 原样保留。

### Agent Handoff

下一次 Desktop 需明确加载此工作区实现后，在一次性有 BOM 的 Java fixture 用新 opaque refs 按 AY 验证完整链路；本轮 post-fix Desktop 为 PENDING_ACTUAL_DESKTOP。源码副本仅瞬时临时数据，不进状态/DB；结果提交/过期/正常退出沿既有安全清理，硬杀或拒绝清理仍可能遗留，不能写清理 PASS。三位试用/真实 Maven 环境仍 Pending、Ground Truth UNREVIEWED/null；其他阶段 Planned。完成必要测试与文档后停止。

## 功能验证器发现与宿主执行编排 v0.1（2026-10-04）

继续 feature/runtime-mvp / `ee1bfd9c12493683cc313cb3628753a51ae124ac`；起点含上一轮13个未提交episode交付文件，全部保留。用户真实E2E报告安全修复与SCANNER_VERIFIED_RESOLVED已正常，functional为NOT_AVAILABLE/NO_EXISTING_LOCAL_VERIFIER，但clean项目已有javac。本轮复用functional registry/service/cache及签名security receipt，新增Host计划和闭合结果回传。Runtime默认MCP不执行项目命令，不新增/修改CET或sandbox。Java优先Maven→Gradle→仅目标文件javac；Python已有pytest入口、Go已有test、Node固定scripts可发现。

首轮focused93 passed（36.77s）；扩展targeted171 passed（222.12s，早期26项新增）；最终focused99 passed（40.42s），新增宿主测试共32项；既有Hook receipt工具可用/缺失追加2 passed（14.18s）。最终完整离线回归 **1054 passed /6 skipped /6 subtests passed，1282.01s**，门禁及早期旧断言失败记录见[AX](AI_TRIAGE_ACCEPTANCE.md#ax-functional-verifier-discovery--host-execution-v01)。实际本地MCP/离线Scanner/已有JDK成功及失败A/B **PASS，93.90s**，仅SIMULATED_NATIVE_HOST_DRIVER，非Desktop自然执行。wheel/sdist/package/compliance **PASS，102打包文件，5.76s**，包含最终兼容测试。当前clean E2E项目仅只读检查发现javac，未使用旧引用、编译或修改该项目。

### Agent Handoff

未提交、未推送、未部署/替换活动MCP/native包。prepare返回FUNCTIONAL_VERIFICATION_READY与固定argv/scope/cwd/budget/functional_ref/plan_digest；Host原生执行并向run_functional_verification提交有界脱敏execution_result。verify_task_fix保留原status/verification_status，增加functional_status、双维度结果与overall；功能失败/不可用不否定安全事实。既有项目verifier走有界瞬时副本，javac仅外部产物目录；提交结果/过期重规划/正常退出时清理，硬杀可能遗留临时目录，不新增daemon。实际Desktop、三位试用仍Pending，Ground Truth UNREVIEWED/null、质量NOT_MEASURED；真实Maven环境验收Pending，不搭建/下载。完整门禁见AX，完成后停止；上一轮AW与其它历史节保留。

## Finding Family / Remediation Episode lifecycle（2026-10-04）

起点 `feature/runtime-mvp` / `ee1bfd9c12493683cc313cb3628753a51ae124ac`，干净工作区。用户隔离 E2E 确认：历史 TLS family 已 `SCANNER_VERIFIED_RESOLVED / CLOSED`，同文件重新引入却只返回 `FAMILY_CLOSED_OR_BUDGET_EXCEEDED`、无引用；全新文件同规则正常 AUTO_FIX。原缺陷 **USER_REPORTED FAIL**，本轮 Desktop 修复复验仍 Pending。

本轮仅改 family/episode/attempt 生命周期：稳定 eq-v1 family、随机 current episode identity、正向 scanner resolution receipt、有界历史；每 episode 最多两次，首次 AUTO 授权分配 attempt 1，确认前为 0。只有 scanner 已证明消失，之后新完整 scan 再次看到同 family，才按当前 policy 创建新 episode 和新引用。持续存在、失败/部分覆盖、换 session、重启不重置预算；exhausted 后人工最小修复需原 TaskFix verifier 成功才能关闭。

复用既有 workspace lock/HMAC/session envelope，无 SQLite schema migration；workspace 内查最新 episode，拒绝历史授权。旧记录只读兼容映射为 #1，预算保留；旧签名 scanner-resolved marker + 有效snapshot/guards保留正向证明，CLOSED alone不推断resolved。16 episodes/family、16 families/envelope、64 envelopes/workspace，耗尽 fail closed。新增34项episode测试；最终完整离线回归 **1021 passed /6 skipped /6 subtests passed，896.06s**。首次完整回归的既有并发setup间歇失败保留记录，未放宽断言，独立复跑及最终整轮通过。实际本地MCP/已有离线Scanner两轮recurrence **PASS，55.31s**（driver模拟宿主编辑，不是Desktop自然继续）；wheel/sdist/package/compliance **PASS，3.54s**，101打包文件bytes一致。clean install/native未在本轮重跑，活动包保留。完整门禁与真实Pending见 [AW](AI_TRIAGE_ACCEPTANCE.md#aw-finding-family--remediation-episode-lifecycle)。

### Agent Handoff

当前工作未提交、未推送、不发布/替换活动 MCP/native 包。只完成本轮验证与文档后停止，未经用户明确要求不 commit/push。手工 E2E 见 AW。Hook prompt/Code Mode feedback/automatic continuation、CET、functional credential 生命周期未修改，后者仍无干净 E2E 结论。三位试用 Pending、Ground Truth UNREVIEWED/null、质量 NOT_MEASURED、Maven A/B PENDING_ENVIRONMENT_PREREQUISITES、既有 CI PENDING_RERUN_AFTER_ACCOUNT_RECOVERY；其它阶段 Planned。下文为旧阶段历史，当前范围以本节/AW为准。

## AUTO_FIX PostToolUse Code Mode Contract Fix v0.1（2026-10-04）

干净起点 `feature/runtime-mvp` / `50f002deff33d0946ee99c338d700b08a739e394`。最新用户真实 Desktop：缺失首安全 Hook 后危险首有效 Hook 为 SETUP_SEED / baseline_available=true / SCANNED / NEW1 / AUTO_FIX，First-run Baseline Seed、归因、AUTO检测策略 **USER_REPORTED PASS**。之后 Script failed、未prepare/未secure edit、resolved0；Host重试危险编辑导致SESSION/NEW0/ESCALATE。**PostToolUse continuation USER_REPORTED FAIL（Code Mode decision:block contract）**；Stop未进入，Desktop **NOT TESTED**，不能写Stop FAIL。readiness/lifecycle已有真实PASS，不再调查。新transport的fresh Desktop自然继续/Stop闭环 **PENDING_ACTUAL_DESKTOP**。

[当前官方 Hooks 文档](https://learn.chatgpt.com/docs/hooks#tool-calls-from-code-mode)核对于2026-10-04：PostToolUse decision:block 在已执行工具后拒绝nested Code Mode promise；continue:false把反馈作为model-visible result而不拒绝promise。只改codex_mcp_hook.py的AUTO_FIX反馈为continue:false/stopReason，systemMessage原样；固定提示前一编辑已执行、不要retry/repeat、授权的是remediation、立即prepare_task_fix，然后附原bounded guidance。无新字段、无原AUTO decision/reason。CONFIRM_REQUIRED原continue:false/stopReason主动询问并WAIT；NONE无停止；Stop仍decision:block/reason生成continuation prompt，不能机械替换。

实现 `1033abfd5c467661a2a7110442bcc410851e9bb1` 已提交推送。focused **156 passed in 383.80s (0:06:23)**；targeted **534 passed in 1007.83s (0:16:47)**；final full offline **987 passed, 6 skipped, 6 subtests passed in 1142.05s (0:19:02)**。六项skipped单列于AV，不计PASS。wheel/sdist/package/compliance、101打包文件bytes integrity、其余全部Runtime源码不变、严格离线clean安装、actual source SDK、独立新目录Windows native均PASS。新四类CI **PENDING_RERUN_AFTER_ACCOUNT_RECOVERY**，实际jobs/annotations见AV；未运行的平台不写PASS。最终docs HEAD按本文件git log核对，其docs-only CI在最终交付回复单列。

AUTO_FIX action/interaction、原task_ref/remediation_ref/grant_id与prepare/verify handoff、policy/guards/verification/state machine保持。HookCoordinator/baseline/snapshot/cooldown/single-flight/family multiset/coverage gating、Raw/脱敏/UNTRUSTED_CODE/session/hash/evidence_refs/预算保持；command hook保留。SessionStart/PostToolUse/Stop的matcher/tool/input/timeout/statusMessage exact Hook定义与起点一致；canonical SHA256 cb407a5d3e175add5d51d90c86e5fd43cb74708b770dc585eab9eca92e82eb8b仅Runtime测试摘要，不猜Host私有hash、不写信任数据库。

SDK/clean/native真实Runtime/Scanner均SETUP_SEED/NEW1/AUTO_FIX，新feedback→driver消费原Stop handoff→prepare→模拟secure edit→resolved1/SCANNER_VERIFIED_RESOLVED/CLOSED，匹配receipt无需重复explicit verify；functional prepare NOT_AVAILABLE、无run。**SYNTHETIC_SDK_NOT_DESKTOP**，不证明自然模型继续。新原生包dist/standalone-code-mode由已提交实现HEAD构建；保留旧活动包/进程。fresh步骤见[Codex使用说明](CODEX_INTEGRATION.md)：全新disposable Git fixture→setup/Local Baseline READY→正常Review & Allow→退出/重开/新Chat→safe edit→danger edit→路径A自然PostToolUse或路径B原Stop兜底→同grant prepare/secure edit/resolved1，不得Script failed或重复危险编辑；不用旧ESCALATED baseline-seed-desktop-trial。

真实Maven A/B/Linux hardened execution PENDING_ENVIRONMENT_PREREQUISITES；不安装/下载/搭环境。三位试用PENDING，独立Ground Truth UNREVIEWED/null、质量NOT_MEASURED。未改Jeepay/用户实际fixture/冻结benchmark/人工标签；Runtime无模型/目标编辑/build/Secret rotation、Scanner离线，仅官方文档与授权GitHub交付联网。Capability/Entitlement、Plus/Pro、Enterprise Gate、Deep Audit、Skill/MCP Scan、Cursor、Installer、新Scanner/rule、baseline/Stop redesign及state relaxation/duplicate retry tolerance/AUTOrenewal均不进入。完成交付后停止。

完整门禁/CI/边界见[AV](AI_TRIAGE_ACCEPTANCE.md#av-auto_fix-posttooluse-code-mode-contract-fix-v01)和[结构化记录](code-mode-acceptance.json)。以下各旧节保留历史事实，当前状态以本节与AV为准。

### Agent Handoff

先读AV及结构化证据，核对Git。已证实seed归因与AUTO策略成功；旧transport导致Code Mode拒绝，Stop未测。只剩新fresh Desktop与外部CI/环境/人工验收，不改变authority/state/ABI，不进入下一阶段。

## First-run Baseline Seed + Trust UX v0.1（2026-10-04）

干净起点 feature/runtime-mvp / `50ecaf2f4451e4cc6854651c9987ae7167a8b11c`。本轮只修 setup→首有效 Hook 的归因缺口，暂停继续扩展 Stop Guard。最新用户 disposable Desktop 真实反馈：第一条安全编辑无 Hook 记录；第二条危险 TLS 编辑首次有效 Hook 返回 BASELINE_ESTABLISHED、baseline_available=false、scanner_run=true、FULL、NEW0/NONE。这是 **USER_REPORTED FIRST_RUN_TRUST_GAP**，本次没有 AUTO_FIX，不是 Stop Guard 失败。缺失首 Hook 的 Host 底层原因未证明，不能推断用户拒绝信任。旧 readiness/lifecycle PASS 保留历史。

实现 `4915354cd6e8bef139836cb760ae6fb601d8f76a` 已提交推送；final focused **90 passed in 219.07s (0:03:39)**；targeted **524 passed in 1037.62s (0:17:17)**（最后5项测试由 focused/full覆盖）；final full offline **982 passed, 6 skipped, 6 subtests passed in 1123.35s (0:18:43)**。wheel/sdist/package/compliance、五模块包/source字节一致、严格离线clean venv、实际SDK、独立目录Windows native均PASS。新四类CI **PENDING_RERUN_AFTER_ACCOUNT_RECOVERY**，具体jobs/annotations见AU；不能把未启动四平台写PASS。最终docs HEAD按本文件git log核对，docs-only新CI在最终回复单列。

setup配置提交成功后在项目外建立signed workspace seed，复用HookCoordinator._scan_scope的同一个quick Semgrep/Gitleaks observer、family_multiset与coverage proof。baseline只保存HookSnapshot safe projection与闭合HMAC wrapper，不写Finding DB/源码片段/Secret/prompt/transcript；PRE_EXISTING_BASELINE，无remediation/model/build/test/network/download。完整Git inventory≤1000 files/20MB/单文件1MB，扫描60秒cooperative deadline及既有Git/process/output限制。非空scope要求全部requested quick capabilities完成；空scope允许空比较点，SCOPED不是项目FULL安全声明。部分/失败/缺scanner/budget超限为INCONCLUSIVE、overall DEGRADED，Integration CONFIGURED仍独立保留。

setup/healthy repair有效seed为BASELINE_READY且不重扫，不因source变化刷新；首次/missing/stale/不兼容升级可建立，repair重建BASELINE_REESTABLISHED；status只读显示baseline READY/NOT_ESTABLISHED/STALE/INCONCLUSIVE、source SETUP_SEED及hook_trust HOST_MANAGED_UNKNOWN。remove只清自有seed/config metadata，保留源码/scanner DB/Finding DB/普通scan历史；re-setup新seed。CLI提示正常项目trust及Review & Allow Hooks一次，再重开正常编码，无info/scan/repair warm-up。

实际SDK/clean/native deliberately skip first safe Hook：SETUP_SEED、baseline_available=true、NEW1、AUTO_FIX；untracked新文件PASS；preexisting PERSISTING1/NEW0/NONE。driver消费原Stop handoff→prepare→模拟安全edit→resolved1/SCANNER_VERIFIED_RESOLVED→functional prepare NOT_AVAILABLE，无functional run。此为真实Runtime/Scanner、**SIMULATED_HOST_ONLY，不是Desktop模型证据**。fresh Desktop seed/trust/自然继续/Stop完整闭环 **PENDING_ACTUAL_DESKTOP**。步骤见[Codex使用说明](CODEX_INTEGRATION.md)，门禁和CI见[AU](AI_TRIAGE_ACCEPTANCE.md#au-first-run-baseline-seed--trust-ux-v01)。

真实Maven A/B/Linux hardened execution PENDING_ENVIRONMENT_PREREQUISITES；不安装/下载/搭环境。三位试用PENDING，独立Ground Truth UNREVIEWED/null，质量NOT_MEASURED。未改Jeepay/用户实际fixture/冻结benchmark/人工标签；Runtime无模型、目标编辑/build/Secret rotation，Scanner离线，仅官方文档与授权GitHub交付联网。Capability/Entitlement、Plus/Pro、Enterprise Gate、Deep Audit、Skill/MCP Scan、Cursor、其它Host、新AUTO_FIX rule、Functional sandbox扩展等继续Planned。完成本轮交付后停止。

当前架构/决策见ARCHITECTURE与DECISIONS首节；完整门禁/CI/实机边界见[AU](AI_TRIAGE_ACCEPTANCE.md#au-first-run-baseline-seed--trust-ux-v01)，[结构化记录](baseline-seed-acceptance.json)与[试用步骤](CODEX_INTEGRATION.md)。

### Agent Handoff

先核对Git与AU/结构化证据，保留上述最新USER_REPORTED失败与新实现PENDING的区别。不要把旧first-edit PASS覆盖本次缺失首次Hook场景，不为验收推断trust或制造warm-up。只剩fresh Desktop和外部CI/人工/环境验收，不进入新阶段。

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

### Agent Handoff

先读 AT、CODEX_INTEGRATION 与本轮 evidence，检查 Git。用户已经确认 readiness/lifecycle PASS，不回到 cold-start 调查。新的 Desktop Stop trial 尚无实际反馈，按 fresh disposable fixture 步骤验收；正常自然继续不需要 Stop，分别记录 natural continuation 与 fallback/count，不借扫描 zero findings 宣称闭环。只修本轮 PREPARE_REQUIRED；所有后续阶段 Planned。

以下章节为历史记录，最新状态以本节和 AT 为准。

## Codex Integration Productization v0.2 / Cold-start Readiness v0.3（2026-10-04）

Implementation e68cff74c97a0a7a45df2381015b5906b072a82f 已推送；本轮四类新 CI **PENDING_RERUN_AFTER_ACCOUNT_RECOVERY**，9 jobs 无 Runner/steps，实际 annotations 均为账户付款/支出限额阻止启动，不是代码 PASS 或已运行的代码失败。未改账户、workflow门槛或安全契约，四平台未执行。新 runs 见 AS.5。Windows native 已从该已提交 implementation HEAD 重建并完成实际本地 MCP/lifecycle验收，68.66s，version.json source_commit与实现HEAD一致。最终docs HEAD按PROJECT_STATE的git log核对，docs-only新CI在最终交付消息独立核实。

干净起点 feature/runtime-mvp / 022f402a7ade0ed0cf6bbfce50dccd04ed5920a1。最新用户真实 Desktop 回传：MCP Hook/equivalence、CONFIRM 主动询问/批准/拒绝、AUTO 无错误许可问题→prepare→宿主最小修复→Hook resolved1→Runtime 内部 TaskFixService.verify SCANNER_VERIFIED_RESOLVED→functional prepare 无 verifier NOT_AVAILABLE/SECURITY_VERIFIED_FUNCTION_UNKNOWN，均 **USER_REPORTED PASS**。未报告显式 verify_task_fix 或 functional run，不补写已执行。AR 的旧失败/Pending 保留历史语义，由本节最新回传覆盖当前判断。

本轮只交付 Codex 自有项目 setup/status/repair/remove、readiness/诊断及既有复核协议去重。Runtime 0.3.1 / developer-guidance-v0.3 保持，features 新增 codex_integration v0.2 / cold_start_readiness v0.3。新 **fresh Desktop cold-start PENDING_ACTUAL_DESKTOP**；未在当前聊天伪造真实启动派发。source SDK/clean/native 模拟宿主编辑不代替 Desktop。

新增 focused **59 passed**；定向 **438 passed /420.09s**，最后三项 readiness 状态/恢复由 focused 与 final full 覆盖。最终完整离线 **894 passed, 6 skipped, 6 subtests passed in 514.48s (0:08:34)**，六项 skipped 单列。wheel/sdist/七模块逐字节完整性/package/compliance/严格离线 clean（无 editable/system site，117 cached wheels）/Windows native **PASS**。实际本地 MCP + Semgrep/Gitleaks 合成冷启动不调用 get_runtime_info、不重复显式 verify，无 verifier 时不调用 functional run。门禁见 [AS 验收](AI_TRIAGE_ACCEPTANCE.md#as-codex-integration-productization-v02--cold-start-readiness-v03)、[证据](codex-product-acceptance.json)、[用户命令与 fresh trial](CODEX_INTEGRATION.md)。新 CI 推送后按实际 jobs/steps/annotations 核对，未预写通过。

### Agent Handoff

先读 AS、CODEX_INTEGRATION 和 evidence，检查 Git HEAD/状态。用户无需手改配置/了解 venv，setup 使用自己的环境、默认 MCP Hook。不要调用 get_runtime_info 热身后声称 cold-start PASS。官方支持 SessionStart MCP，但可能早于 server ready；采用自有 server required=true 初始化前提 + readiness 观察。新 Desktop required/start ordering 待真实试验；无可用机制记录 HOST_LIFECYCLE_PREREQUISITE_PENDING。

核心 HookCoordinator/snapshot/cooldown/single-flight/family multiset/equivalence、Scanner/规则、RemediationPolicy、TaskFix/Verification、Functional 三模块与 command fallback 未改。仅匹配原 task_ref/grant_id 的 Runtime CLOSED/SCANNER_VERIFIED_RESOLVED 回执可避免重复 verify；原签名/source/preservation/snapshot/policy/FULL/process/rule/path/absence 标准不降低。functional prepare 无 handoff 必须停止。

真实 Maven A/B/Linux hardened execution PENDING_ENVIRONMENT_PREREQUISITES；三位试用 PENDING、独立 Ground Truth UNREVIEWED/null、质量 NOT_MEASURED。未安装/下载 Maven/JDK/bubblewrap/容器/构建依赖。无 Scanner 网络、Runtime 模型、目标构建、Runtime 源码修复或 Secret rotation；宿主 edit 仅合成 fixture，未改 Jeepay/实际 Desktop fixture/冻结 benchmark/人工标签。后续 Enforcement/Enterprise Gate/其它 Host/第二类 AUTO/新 Scanner-policy/Joern/Deep Audit/watcher保持 Planned。完成本轮交付后停止。

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

### Agent Handoff

先核对本节 starting/implementation HEAD、git status、AN 的实际 CI；保留原 Hook/显式修复服务。读取 Smart Auto 文档的新确认 protocol/TTL/拒绝/失效边界。用户报告 smart_auto PASS 不证明本次主动确认 UX；请真实回传才更新新 Desktop PENDING。最终 docs HEAD 用 git log -1 --format=%H -- docs/PROJECT_STATE.md 获取。完成本轮后停止，其他阶段 Planned。


## Smart Auto Remediation v0.1 — 当前交接（2026-10-03）

本轮 implementation HEAD `462633e8b5d4dcc730dba868bd9ac66e8bc40b37` 已推送，Runtime tests、Package integrity、Compliance、Standalone artifacts 四类实际新CI全 success；后者四平台均执行新增离线自动修复 MCP 验收（宿主编辑仍模拟，Desktop trial Pending），具体链接见 AM.1。最终 docs HEAD 用 git log -1 --format=%H -- docs/PROJECT_STATE.md 核对。

本轮从 `feature/runtime-mvp` / `3d6611d7e94d80e9804ee526c6d35b809ca69c20`、干净工作区继续；现有 Hook/command/MCP 实现保留。上一轮 Codex Desktop MCP Hook POC 的自动触发、baseline/NEW/PERSISTING/multiset/RESOLVED 由用户在本轮明确报告真实 PASS，来源 **USER_REPORTED**；下方历史 POC Pending 是当时状态，不覆盖这项新反馈。本轮 **same-turn Smart Auto Remediation Desktop trial 仍 PENDING**，不得把 SDK 模拟宿主编辑当成新宿主 PASS。

独立 RemediationPolicy/Service 仅 allowlist `ai-security.java.trust-all-hostname` 的明确局部 JDK HTTPS inline installation。Runtime 发 AUTO_FIX grant，宿主沿现有 prepare_task_fix → edit → 自动 Hook/VerificationService → verify_task_fix；Runtime 不编辑源码、不调用宿主模型。用户级 smart_auto 默认，ask_before_fix/report_only 可选；两次尝试上限、HMAC/OS lock/有界 metadata、原 task_ref 和额外 grant 绑定、保留性证明防删除/抑制/移动/配置规避。已有 REVIEW/STALE/FAILED 与 Raw/risk/coverage 不提升或改写，本地 TLS 不变量的独立 ACTIONABLE repair policy 不证明生产可达性。

最终源码离线回归 **651 passed / 6 skipped / 6 subtests passed，260.36 秒**（新测试50项）；旧阶段已交付 baseline 601/6/6。六项 skipped 单列为 tests/test_e2e_real.py 的三引擎 PATH 前提，未计为通过。实际 SDK、严格 clean-wheel venv、Windows native MCP/离线 Semgrep/Gitleaks 修复验证通过；模拟宿主编辑、原引擎子进程实际执行。wheel/sdist/package integrity/licenses/notices 通过。本轮四类新 CI 需以 AM 的具体 run/结论为准，不能引用历史 CI 为当前通过。

包版本0.3.1、developer-guidance-v0.3 保持，新增 optional smart_auto_remediation v0.1。说明、真实 schema、模式命令、预算/连接中断/cooldown 限制、实机步骤见 [Smart Auto 文档](SMART_AUTO_REMEDIATION.md) 和 [AM 验收](AI_TRIAGE_ACCEPTANCE.md#am-smart-auto-remediation-v01)。现有 fixture 用户改动未覆盖；command hook 保留，不迁移 SessionStart/Stop 或其他 Host。

后续 Deep Audit、watcher/daemon、MCP/Skill Security、Joern、自动构建、自动依赖升级、Secret rotation、业务/IAM/IaC 自动修改未开始，继续 Planned。三位试用 Pending；独立 ground truth UNREVIEWED/null，质量 NOT_MEASURED；Jeepay、冻结 benchmark、人工标签原状。完成本轮提交/推送/验收记录后停止，不开始下一阶段。

### Agent Handoff

先核对 git status/branch/HEAD 和 AM 当前 run，保留全部工作区；不要重写 Hook/创建第二套 fix engine。查看 SMART_AUTO_REMEDIATION 的 narrow eligibility 与连接/cooldown/保留性限制。上一轮用户报告 POC PASS != 本轮自动修复 Desktop PASS；本轮仍需用户真实试用。最终 implementation/docs SHA 从 AM/交付记录及 `git log -1 --format=%H -- docs/PROJECT_STATE.md` 核对。


## Codex MCP Tool Hook POC — 当前交接（2026-10-03）

起点为干净的 `feature/runtime-mvp` / `7a38593fb795cec4d7d09291f33f389430df8dba`。新增可选 MCP 工具 `handle_hook_event` 与 `hooks generate-mcp-poc codex` JSON 生成入口；仅 PostToolUse → FILE_CHANGED → 原 HookCoordinator。MCP当前14工具，包版本0.3.1、developer-guidance-v0.3及原8个required guidance tools不变。command adapter/core/host-event/原项目配置保留，后续阶段仍Planned。

最终full offline **601 passed /6 skipped /6 subtests passed（174.14秒）**，新增25项POC cases均通过；6项旧real e2e因三引擎PATH未满足跳过，单列不算通过。wheel/sdist/POC模块入包/package integrity/compliance通过。实现和文档在同一POC提交；用`git log -1 --format=%H -- src/security_runtime/codex_mcp_hook.py`取得实际implementation HEAD。

真实本地SDK stdio工具调用完成离线Scanner检查（最终5012ms、当前quick scope coverage FULL），重复快照复用、越界声明拒绝。它是显式协议验收，**fresh Codex Desktop自动Hook dispatch、advisory UI/context消费仍PENDING**。用户报告既有Windows command Host runner `0x80131506`；本轮SDK路径未观察到该错误，不能据此宣布真实Host已修复。事实、配置、试用与回滚见[AL验收](AI_TRIAGE_ACCEPTANCE.md#al-codex-mcp-tool-hook-poc)和[协议证据](codex-mcp-hook-poc-evidence.json)。

## Host-agnostic Hook Integration v0.1 — 当前交接（2026-10-03）

本轮从干净且 ff-only 同步的 `feature/runtime-mvp` / `8a36b3884a7d25cfb7f75c3405df727909ed1c90` 开始，用户明确授权 Hook 实现；前置 Fix & Verify / eq-v1 已交付。HookCoordinator、本地快照/锁/冷却、多重集变化、中立 CLI、Codex 和 Cursor 适配已实现。本轮新的完整自动化、包和原生/CI 门禁以 AK 附录为准，后文“Hook 未开始”是旧阶段历史状态，不能作为当前结论。初次实现 `40d9905b1ddb8fbac93fd2a31ba2f3075f3cb6bd` 与跨平台验收修正后的实现 `c1d42552d63596790bfba6eaadf206bffae754f2` 已推送；最终576项离线回归、wheel/sdist、完全隔离clean venv、合规、本地Windows native和本轮四类新CI全部通过，详见AK.1/AK.2。文档最终HEAD用 `git log -1 --format=%H -- docs/PROJECT_STATE.md` 获取。

Hook 仅触发现有本地 quick SAST/Secret 检查，ADVISORY；MCP 继续负责核查/修复交接，Git pre-commit 保留 quick --staged 的原边界。没有 Runtime 调用模型、网络依赖解析、自动补丁、目标构建、后台 watcher/daemon、新 scanner/规则、Joern 或 Deep Audit。三位试用 Pending，独立人工 ground truth UNREVIEWED/null、质量 NOT_MEASURED；Jeepay 源码、冻结 benchmark、人工标签保持原状。

Coordinator首先取得workspace OS锁，再在锁内读取状态、计算snapshot、去重/判断冷却、执行检查并原子保存；相同snapshot直接复用。执行顺序详见ARCHITECTURE的Hook架构。

Codex/Cursor 的官方 schema 已核实，项目配置/适配与实际生成命令测试通过；**fresh Codex/Cursor host trial 仍 PENDING**，不得把 CLI/合成 fixture 当成宿主真实自动触发。WorkBuddy（桌面）/Kiro/Qoder 为 MANUAL_CONFIGURATION_REQUIRED，提供中立命令，不从 CodeBuddy CLI 或其他产品推测其 schema。详见 [AK 验收与试用步骤](AI_TRIAGE_ACCEPTANCE.md#ak-host-agnostic-hook-integration-v01)。

## 历史交接：Developer Fix & Verify v0.1（2026-10-02）

起始干净、ff-only 同步 HEAD `0f33d2624204794c84da6fa10cf43b8178cd5a56`，分支 feature/runtime-mvp。本轮明确授权 A→B，先完成 A 回归再实施 B。Stable Finding Equivalence 与任务修复/验证 v0.1 已实现；整体宿主产品 UX 尚待真实验收。Hook Integration 未开始，完成本轮推送后停止。

保留旧 occurrence ID/fingerprint 与历史 Raw/triage/task_ref；eq-v1 无行号，区分原 rule/provider/file，Dependency 复用稳定包/advisory身份，Secret 不含原值/匹配行/凭据摘要。旧 verify 只有完整原规则/文件复查证明缺席时才 RESOLVED + SCANNER_VERIFIED_RESOLVED，行号移动仍 STILL_PRESENT，缺文件/规则/引擎或 scope 无证明为 INCONCLUSIVE。

MCP 当前13工具，新增 prepare_task_fix（严格只读约束/受限证据交接）、verify_task_fix（本地 scanner/cache/temp 副作用，非 destructive）；能力契约 developer-guidance-v0.3，required subset。固定 task_ref 绑定 workspace/scan/精确成员，变化刷新，新 scan 不换对象。宿主响应明确“修复它/修第一项”后编辑选定本地代码并调用复查；Agent fixes. Runtime verifies。组内全部修复/全部仍在/混合为 SCANNER_VERIFIED_RESOLVED/STILL_PRESENT/PARTIALLY_RESOLVED，任一未知整体 INCONCLUSIVE，完全未复查 NOT_VERIFIED。

复查最多100成员/20原受影响文件/2MB，同 provider/file 复用，默认离线不下载或自动fallback，不构建/编辑目标、不调用模型。prepare 沿用 EvidenceBuilder 的20项/32KiB/120行/5相关文件预算，原 triage session/hash/evidence_refs 防护不变。宿主 patch/build/tests 声明为 UNTRUSTED_HOST_REPORT，不能改变 Runtime 观察或结论。Gitleaks/IaC 未提供原 detector/check 执行清单时缺席保守 INCONCLUSIVE；POM PARTIAL 不能证明完整图修复。

完整离线508 passed / 6 skipped / 6 subtests passed（120.12秒）。真实 Semgrep 1.178.0 合成100→110行仍存在、安全替换、分组只修一项及实际子进程失败均符合预期；包/合规/wheel/sdist 与本地全新 Runtime venv 安装通过（复用本地 SDK 依赖，无公网）。Windows native/实际 SDK及四平台新 CI 门禁均通过（实现 HEAD `1e10b53`），见 [AJ 验收](AI_TRIAGE_ACCEPTANCE.md) 和 [合成证据](fix-verify-synthetic-evidence.json)；结构/边界详见 [当前架构](ARCHITECTURE.md)。

没有修改 Jeepay、旧 scan/benchmark、ground truth、risk/coverage/policy；没有 scanner 公网查询、外部模型、目标构建或生产变更。三位真实开发者试用、真实宿主普通意图连续 UX 仍 Pending，独立人工 ground truth UNREVIEWED/null、质量指标 NOT_MEASURED。Hook 当前 Planned / NOT_STARTED，旧 PREREQUISITE_MISSING 留作历史门禁记录。


**新电脑 / 新 Codex Chat 的第一入口。** 更新：2026-10-02（Asia/Shanghai）。先读本文，再按文末 Agent Handoff 恢复；项目知识应从 Git 中取得，不能依赖上一段聊天或原电脑的缓存。

## 当前基线与 Milestone

| 项目 | 当前记录 |
| --- | --- |
| Branch | `feature/runtime-mvp` |
| Hook 最终实现 HEAD | `c1d42552d63596790bfba6eaadf206bffae754f2`；初次实现 `40d9905b1ddb8fbac93fd2a31ba2f3075f3cb6bd` |
| 本轮开发起始 HEAD | Hook Integration：`8a36b3884a7d25cfb7f75c3405df727909ed1c90`；旧 Fix & Verify 起始见 AJ |
| 开发者任务入口实现 HEAD | `00cbd721792ad14118f005ff1fcbb3996e5a8aa0`；第一轮 AG 验收附录 |
| Fix & Verify 实现 HEAD | `1e10b53aacf0dc0f69ad00c3126f8d8298e78989`；第三轮 AJ 验收附录 |
| 继续核查实现 HEAD | `f2cb534f27698881ead2b2f3452bc36598c6e957`；第二轮 AH 验收附录 |
| 代码及既有验收快照 | `3d773aaaa1b95b8c7596bf32c77c4bd5eabfd399` |
| Triage 最终实现 HEAD | `557052049c74c6d1ca4321c2d9559483a36f55d2` |
| 当前 milestone | **AI Finding Triage & Risk Validation v0.1 已完成实现和验收** |
| Runtime package version | `0.3.1`；不等于 Triage milestone 编号 |
| 下一阶段 | **AI Triage Quality Validation & Developer Guidance**；前两个产品迭代实现/自动化/分发 CI 通过；旧聊天实际宿主试用未通过，刷新后复验与独立开发者试用 Pending，整体质量 milestone 未完成 |
| 首个产品迭代 | **开发者任务入口 v0.1**；源码/CLI/MCP/wheel/Windows native/四组 CI 验收通过；三位真实开发者试用 Pending |
| 本轮范围 | **Host-agnostic Hook Integration v0.1 已实现并完成自动化/分发门禁**；实现 `c1d42552d63596790bfba6eaadf206bffae754f2`；fresh host trial Pending，见 AK |

此表分别记录本轮开发起始 HEAD 与既有 Triage 代码/验收快照；本轮实现提交及分发验收见 AI_TRIAGE_ACCEPTANCE 的开发者入口附录。恢复时用 `git rev-parse HEAD` 获取 checkout 的实际最终 HEAD，用 `git log -1 --format=%H -- docs/PROJECT_STATE.md` 获取最近状态文档提交，避免把无法包含自身 SHA 的文档快照当成永远最新。若有更晚代码提交，必须重新核对状态。

第一轮入口实现 `00cbd72`，验收文档 `50a01e6`。用户随后明确授权第二轮“继续核查 v0.1”，本轮从干净、已同步的 `50a01e6` 开始；不重跑 Jeepay 在线扫描、不替人工标注、不实现修复与验证。既有历史证据保留。

最近关键提交：

| Commit | 交付内容 |
| --- | --- |
| 1e10b53 | Stable equivalence / 原规则文件执行证据 / task_fix / 宿主执行声明分离 / 13工具 / 47项新增回归 |
| f2cb534 | 绑定任务继续核查、pending/cache推进、宿主普通意图指导/版本能力恢复、45项测试 |
| 00cbd72 | workspace 只读开发者任务入口、CLI summary / MCP get_security_summary、保守合并与 34 项入口测试 |
| 602a789 | NEXT_STAGE 产品与质量路线规划 |
| 7e19744 | Triage v0.1 架构、项目状态、决策与交接持久化 |
| 3d773aa | Triage/native 最终验收与证据 |
| 5570520 | offline 阻止外部模型调用 |
| f195020 | 完整 Finding range 的 120 行预算 |
| 93ef02f | 独立 Triage、EvidenceBuilder、MCP handoff、BYOK |
| 47c41f4 / 2538e1b / 26fe636 | OSV fallback、离线测试隔离与最终平台验收 |
| 51908b4 | Trivy vuln / misconfig 能力拆分 |
| 16d390b | Rule Coverage + Java Core Rules |
| 341e1e1 | 真实进度、heartbeat、可取消的引擎工作 |

## 已完成能力与代码入口

| 能力 | 实现入口 / 状态 |
| --- | --- |
| 共用本地 Runtime | CLI / MCP / pre-commit；quick、feature、release 与 Git/非 Git 边界 |
| 能力规划 | capabilities.py、planner.py；按 Capability 选适用 provider |
| 规则覆盖 | rule_catalog.py、rulepacks.py、rule_coverage.py、sast.py；计划与真实执行证据分离 |
| Scan providers | scanners.py、osv.py、dependency_fallback.py；四个 primary adapters + on-demand OSV |
| 原候选与风险 | models.py、findings.py、risk.py；normalization/dedupe 与原 release policy |
| 独立 Triage | triage_models.py、triage.py；prepare/submit/view/run、schema/ref/hash 校验、保守 policy |
| 受限证据 | triage_evidence.py；workspace 限定、脱敏、预算、UNTRUSTED_CODE、HMAC revision |
| 模型接入 | triage_providers.py；Agent-native 交接与显式授权的 OpenAI-compatible BYOK |
| 持久化 | storage.py；scans/findings + 加法新增 triage_records/cache index |
| 展示 | human.py、cli.py；候选语义、dependency grouping、独立 scan/triage coverage |
| 开发者任务入口 | security_summary.py、ReadOnlySQLiteStore；当前 workspace 最近扫描、只读 freshness、保守任务投影、最多三项推荐/完整详细视图 |
| 继续核查 | task_triage.py；版本化 task_ref、pending-only 选择、既有审阅复用、FAILED 显式重试、宿主受限 handoff |
| MCP | mcp_server.py；当前 13 工具，新增 prepare_task_triage；复用 submit_triage 和既有 session/hash/引用校验 |
| 进度/诊断 | progress.py、cli_progress.py、diagnostics.py、processes.py；stderr、heartbeat、限长脱敏错误 |
| 工具与分发 | toolchain.py、engines.py、licensing.py；wheel/sdist、PyInstaller onedir、四平台 CI |

具体行为与真实限制见 [ARCHITECTURE](ARCHITECTURE.md)，已确立决策见 [DECISIONS](DECISIONS.md)。

## 当前 Providers / Scanners

| Capability | Primary | Fallback / 说明 |
| --- | --- | --- |
| CODE_SAST | Semgrep 1.178.0 | 默认 first-party 规则；零规则为 NOT_COVERED |
| SECRET_SCAN | Gitleaks 8.30.0 | 独立成功；Trivy 失败不牵连 |
| DEPENDENCY_VULN | trivy-vuln / Trivy 0.74.0 | OSV-Scanner 2.6.0；仅白名单失败触发 |
| IAC_MISCONFIG | trivy-misconfig / Trivy 0.74.0 | 独立 scope/process，不准备 vuln DB |
| AI Triage | AgentNativeProvider；OpenAICompatibleProvider | 普通 scan 不调用；不是额外 Scanner |

`tools install --all` 仅准备三个主引擎，OSV 按需或显式安装。doctor 只读且 OSV 非强制就绪项。Dependency EXECUTED 要 SUCCESS + FULL coverage contract；SUCCESS/PARTIAL 仍 PARTIAL，不能只看进程状态。

MCP 当前十三个工具：`scan_diff`、`scan_project`、`get_findings`、`generate_fix`、`verify`、`prepare_triage`、`submit_triage`、`get_triage`、`get_security_summary`、`prepare_task_triage`、`get_runtime_info`、`prepare_task_fix`、`verify_task_fix`。新汇总在绑定/明确 workspace 内定位最近扫描，支持显式 scan_id 和 details；旧工具仍没有 `scan_id="latest"` 别名。`generate_fix` 是确定性任务，`verify` 是原 scanner 复查；Triage 是独立的风险审阅。

CLI：`security-check summary --path <project>`；加 `--details` 展开所有任务和逐 Finding/Advisory/AI 信息，加 `--json` 获取同一投影。未提供 path 时使用已绑定 workspace 或安全识别到的当前项目；MCP 未绑定且未明确 workspace 时拒绝取全局最近扫描。无记录仅返回 NEEDS_SCAN 和建议，不启动扫描。汇总经 SQLite mode=ro 读取，不创建 schema/state/HMAC key、不持久化 STALE、不调用 scanner/模型、不收集目标环境变量或凭据值。为核对已有审阅 freshness 可读取现有预算内的脱敏证据；继续核查使用任务引用进入已有受限证据流程，Runtime 不主动调用宿主模型。

## Java Rule Coverage

规则包 `ai-security-core 1.1.0`，checksum：

`52188177327841e4d0c8c517cbccd86f0503a1623c0cf6adf103fbbc2e9ec742`

Java 22 条（21 AST + 1 MyBatis XML），12 个类别，7 search / 15 taint；Python 2 条；全部默认规则 BETA。规则有 25 positive / 28 negative fixtures，质量门禁校验 catalog、metadata 与实际预期匹配。

Jeepay：650 个项目文件；Java 22/22/22 规则、548 Java/XML SAST 文件实际执行；JavaScript 10 文件、0 规则 NOT_COVERED；CODE_SAST=PARTIAL。有限 search/taint 不等价于 compiler-grade 跨文件 reachability。详情：[JAVA_RULES_ACCEPTANCE](JAVA_RULES_ACCEPTANCE.md)、[RULE_COVERAGE](RULE_COVERAGE.md)。

## Jeepay 已提交 Dogfood 基线与后续宿主报告

### 已提交的 native scan 与脚本化 MCP 回放

扫描时间：2026-10-01。保存的 scan ID：`f5224162-0624-416f-8472-0f0474e7fd58`。使用实际安装 CLI/scanners；公开 Jeepay 的依赖元数据在线解析/查询已获当次用户授权。本轮没有重新扫描、调用公网模型或修改证据。

| 原候选 | 数量 | 最新 scan capability |
| --- | ---: | --- |
| Semgrep code | 4 | CODE_SAST PARTIAL（Java 已执行，JS 未覆盖） |
| Gitleaks Secret | 9 | SECRET_SCAN EXECUTED |
| OSV dependency | 88 | DEPENDENCY_VULN PARTIAL |
| Trivy IaC | 14 | IAC_MISCONFIG EXECUTED |
| **Raw 总数** | **115** | **整体 scan coverage PARTIAL** |

Trivy vuln 为 FAILED / MAVEN_RATE_LIMITED，自动回退 OSV SUCCESS / PARTIAL。10/10 POM 有库存输出：177 package occurrences、135 个不同 ecosystem/name/version 组合，但有未知版本、内部模块解析不足及未证明完整 parent/property/传递/test 依赖图。成功返回 88 advisory 不是完整图证明，未提升 FULL。依赖显示为 28 个 package/version/ecosystem/manifest 组，原 88 项保留。

同一 native Raw Result 经真实 SDK stdio MCP prepare/submit/get，以及 Windows frozen Runtime 复验：

| Triage 状态 / 优先级 | 数量 |
| --- | ---: |
| 已 triaged | **26** |
| ACTIONABLE | **2** |
| REVIEW | **23** |
| LOWER_PRIORITY | **1** |
| SUPPRESSED | **0** |
| UNTRIAGED | **89** |
| FAILED / STALE | 0 / 0 |

101 项 eligible（code/secret/dependency）。26 项为 4 code + 9 Secret + 13 dependency（3 CRITICAL + 原序前 10 HIGH）；剩余 75 dependency + 14 IaC = 89 UNTRIAGED。IaC 独立分类为 5 HARDENING / 9 BEST_PRACTICE，不是 AI 判定。

Verdict：2 CONFIRMED（局部 TLS bypass 安装证据）、1 LIKELY（Java Secret 候选）、22 NEEDS_REVIEW（MD5/配置/依赖）、1 UNLIKELY（文档候选）、0 FALSE_POSITIVE。两条 TLS ACTIONABLE 保留生产调用/攻击位置未知；MD5 的支付签名用途及依赖利用条件尚需确认。没有删除或压制任何真实 Raw Finding。

**这些是 Coding Agent 审阅 artifact 的脚本化 MCP 回放，不是独立人工 ground truth，也不是公网模型质量测试。** `jeepay-human-ground-truth.json` 的 26 项 human_label/reviewer 均 null、status=UNREVIEWED；合成 fixture 标签也不能替代真实项目人工真值。invalid output rate=0 只说明此次结构/引用交接通过，不是准确率。第二次本地 MCP 回放 26 cache hits。

证据：[真实 native scan](jeepay-osv-online-evidence.json)、[MCP triage](jeepay-triage-evidence.json)、[frozen MCP triage](jeepay-frozen-triage-evidence.json)、[人工标注入口](jeepay-human-ground-truth.json)、[native BYOK loopback](triage-native-byok-evidence.json)。原 capture 含原电脑 workspace，只有 branch=master，**没有明确 Jeepay commit SHA**；跨设备复现必须补核对应源码版本，不能猜测一致。

### 用户提供的后续实际宿主 MCP 验收（与历史回放分开）

报告来源：2026-10-02 用户在当前聊天粘贴的 Jeepay 宿主 Codex 验收与随后只读核查回复。固定 scan ID：`99ca7566-4a6f-4818-b447-38646072457b`。**此段保留第一轮时点的用户报告。第二轮对同一已保存 scan 只读复用有效审阅的实际 SDK 验收见 AH；没有重跑原 scanner/宿主模型，也未补原源码 revision/独立 ground truth。**

| 状态 | 报告数量 |
| --- | ---: |
| Raw / eligible | 115 / 101 |
| VALID triaged | 26（4 code + 9 Secret + 13 dependency） |
| ACTIONABLE / REVIEW | **0 / 26** |
| LOWER_PRIORITY / SUPPRESSED | 0 / 0 |
| FAILED / STALE | 0 / 0 |
| UNTRIAGED | 89（75 eligible dependency + 14 不 eligible IaC） |

该宿主轮次追加处理 9 Secret + 13 dependency，报告 cache hits=0，保留先前 4 code。整体 scan、CODE_SAST、DEPENDENCY_VULN 为 PARTIAL；SECRET_SCAN、IAC_MISCONFIG 为 EXECUTED。Dependency 保留 Trivy MAVEN_RATE_LIMITED 失败与 OSV fallback 的部分覆盖；AI Triage 未提升 coverage。与历史的 2 ACTIONABLE / 23 REVIEW / 1 LOWER_PRIORITY 分布不同，不能为匹配旧输出调整新判断。

宿主随后额外读取 Jeepay 源码，报告 YsfHttpUtil 的校验绕过实现位于云闪付渠道下单、关单、退款和补单查询的请求链中；生产渠道、部署版本、信任配置和代理条件仍未知。这是**宿主补充只读核查**，没有在本轮作为新 evidence_refs/context_hash 提交 Runtime。它不是 Runtime 自动调用链分析、人工 ground truth、已执行补丁或修复验收。

产品反馈：用户需要多轮验收提示词才能取得可执行任务。将两条 TLS 候选合为一个跟进任务、Agent 先查仓库能够回答的问题、只询问必要业务事实，应成为后续产品流程；Secret 不询问原值，依赖信息缺失时不编造升级版本。当前优先级维持原结果，0 ACTIONABLE 不表示安全。

## 当前验收依据与文档导航

四份主文档各司其职：本文恢复项目状态；ARCHITECTURE 描述当前实现；DECISIONS 记录决策；NEXT_STAGE 规划未来工作。其它 acceptance 与 JSON/TXT 保留为阶段验收和证据，不要求每次恢复全部阅读，也不新增重复总结文件。

| 阅读目的 | 文档 |
| --- | --- |
| 最新 milestone 与完整验收 | [AI_TRIAGE_ACCEPTANCE](AI_TRIAGE_ACCEPTANCE.md) |
| 最新统计、测试/分发/CI 摘要 | [triage-delivery-evidence.json](triage-delivery-evidence.json) |
| Java 规则与执行覆盖 | [JAVA_RULES_ACCEPTANCE](JAVA_RULES_ACCEPTANCE.md)、[RULE_COVERAGE](RULE_COVERAGE.md) |
| Dependency fallback、在线/离线边界 | [OSV_DEPENDENCY_FALLBACK](OSV_DEPENDENCY_FALLBACK.md) |
| Trivy 独立能力 | [TRIVY_CAPABILITY_DECOUPLING](TRIVY_CAPABILITY_DECOUPLING.md) |
| 进度、失败语义与集成历史 | [CLI_PROGRESS_ACCEPTANCE](CLI_PROGRESS_ACCEPTANCE.md)、[REAL_PROJECT_DIAGNOSTICS](REAL_PROJECT_DIAGNOSTICS.md)、[DEVELOPER_ALPHA_ACCEPTANCE](DEVELOPER_ALPHA_ACCEPTANCE.md) |
| 扩展/分发/许可 | [EXTENDING](EXTENDING.md)、[distribution README](../distribution/README.md)、[LICENSING](../LICENSING.md) |

既有实现 `5570520` 的 382 passed / 6 skipped / 6 subtests（90.60 秒）、74 项 Triage 定向、native BYOK loopback 及 CI 属于历史验收。第一轮从同步后的干净工作区重跑基线：382 passed / 6 skipped / 6 subtests（125.57 秒）；新增 34 项开发者入口测试，最终全量离线 **416 passed、6 skipped、6 subtests passed**（93.83 秒）。wheel/sdist、新模块分发门禁、独立安装、licenses/notices 通过；已有 Jeepay 记录的真实 CLI/JSON/MCP 只读验收产生 54 个任务，保留全部 115 Raw，数据库/key 文件字节不变。没有新扫描或模型请求。第二轮基线416 passed（97.78秒），新增45项，最终461 passed / 6 skipped / 6 subtests（152.30秒）；新模块wheel/sdist/全新venv安装、Windows native/实际SDK交接通过。当前实现CI状态见 AH；实际宿主自然语言试用/旧聊天工具恢复/三位开发者均Pending，skipped不计通过。

## 已知限制与不可误读的状态

- `human.render_triage` 与任务入口现在使用“已完成 AI 审阅”；VALID 只表示记录通过 Runtime 校验，非人工验证、复现或线上可利用。建议跟进任务不修改 Runtime priority；0 ACTIONABLE 不表示安全。普通视图最多三项，完整详细列表和 Raw 入口仍可获得。
- 无 Joern、compiler-grade 跨文件 dataflow、完整 dependency reachability、主动 AI 全仓审计；版本命中、有限词法搜索与文件位置不能证明可利用性或误报。
- 实际公网 BYOK 模型效果/兼容性、不同模型一致性、triage precision 与 suppression risk 未测；独立人工标注未完成，不能宣布“99% 准确率”或“零漏报”。
- Raw 始终保留；SUPPRESSED 仅影响独立显示优先级。原 RiskEngine 不随 triage 自动解禁。
- Secret 匹配行、相邻字面量与回显有脱敏，但任意未知 Secret 不能获得完整检测保证。宿主模型可能联网，Agent-native 不代表全程本地推理；外部 BYOK 每次显式授权，原在线依赖授权不能推定为模型源码上传授权。
- Evidence 依赖对应 workspace/文件仍存在；失效或不可读取变 STALE。跨设备绝对根路径和本地 HMAC key 不同，ID/cache 不保证可复用；provider 的 host-managed 标签也不是精确模型版本证明。
- prepare 不再先截断后查缓存；最多检查 1000 个候选，缓存不占新分析名额，packet/证据错误合计最多 20。任务入口保留当前 VALID，优先 UNTRIAGED、其次 STALE；FAILED 默认单列，retry_failed=true 才重试。115 候选不意味着一次 triage 全覆盖。
- 新 verify 可选 primary/fallback origins；位置移动按 eq-v1 仍存在，缺文件 INCONCLUSIVE，离线依赖图不足不判 resolved。Gitleaks/IaC 原 detector 执行清单不足时缺席 INCONCLUSIVE；扫描复查不等于生产安全。
- scans/findings 不是数据库级 immutable audit log；Triage 先批次校验，再逐记录提交，没有整批事务、retention 或多租户隔离。旧 MCP 工具未绑定时不提供 workspace 隔离；新汇总即使未绑定也必须明确 workspace，不能读取全局最近记录。
- 程序未自动执行目标项目构建。scanner plugins 是受信任 Python 代码；进程 timeout/快照不是 OS sandbox。原 WorkBuddy 版本的 UI 路径与真实连接限制见历史验收，不因 SDK 测试而宣称全部客户端自动可用。
- `privacy.py` 的旧 LocalContextProvider/AIProvider.generate_fix 没有接入新 Triage。State 与 managed tool DATA_DIR 分开，不静默搬移数据库。

## 下一阶段

用户已分别授权第一轮入口及第二轮 **继续核查 v0.1**。详细边界见 [NEXT_STAGE](NEXT_STAGE.md)。独立人工质量工作仍未实施，修复与验证 v0.1 已实现；原 ground truth 仍 UNREVIEWED/null。

产品迭代顺序：

1. **开发者任务入口 v0.1 — Implemented，自动化及分发/四组 CI 验收通过 / 人工易用性 Pending**：新增 get_security_summary，当前共十三个工具；来源与完整列表保留。用户明确目前无法安排三位未参与开发的试用者，因此不声称这一验收已通过。
2. **继续核查 v0.1 — Implemented / 自动化/原生/四组 CI 通过 / 旧聊天实际试用未通过，刷新后复验 Pending**：summary 任务自带 task_ref/continuation；宿主使用本次显示项的引用，不按 T01 重新索引。prepare_task_triage → 宿主受限分析 → submit_triage；有效审阅保留，过期重建，失败显式重试，必要业务问题仅为候选提示。用户实际两句试用的调用记录仅有 get_triage，继续轮没有工具调用；不能把聊天中的修复草案计为任务交接成功。同一配置程序的新离线 SDK 连接确认能力存在，疑似旧连接/工具列表，具体原因及宿主刷新未验证。见 [试用记录](jeepay-host-task-trial.json) 与 AH。
3. **Developer Fix & Verify v0.1 — Implemented / 宿主 UX Pending**：结构化只读交接、宿主编辑、bounded 原规则等价复查；见本文当前状态。

独立人工质量工作协同推进：冻结 Jeepay benchmark 身份、人工盲审与 ground truth schema、五类 verdict 标准、Agent-native/BYOK 模型比较、suppression risk、precision/agreement 与 prompt/model regression。没有人工审阅者时保持 UNREVIEWED；模型不得自填人工真值。易用性用三位未参与开发的开发者试用观察，不能换算为安全准确率。

前两个产品迭代已获授权并实现；首个未开展的质量任务仍是固定源码身份与独立人工试标。Raw、TriagePolicy、RiskEngine、覆盖契约和上传/执行授权边界保持完整。任务入口交付不表示整体质量 milestone 完成；Joern Java PoC 仍后置。

## Hook Integration 前置检查历史（2026-10-02，已由本轮前置交付更新）

该旧任务假设 Developer Fix & Verify v0.1 已完成，要求复用其不依赖 occurrence 行号的 Finding identity；若缺少则停止正式 Hook delta 实现。当时干净工作区执行 ff-only 同步后，远端/本机仍为 `787aace817bd607efd22bc70a7bd613a5f313faa`，没有新的 Fix & Verify 提交。该时点文档将修复与验证标为 Planned，findings.py 的代码指纹含 line，runtime.py 的旧 verify 按 fingerprint 判消失。本轮已修正该缺陷并交付前置，但未开始 Hook。

隔离合成 scanner 复现：同一规则/文件/代码仅从100行移到110行，fingerprint 改变，旧 verify 返回 RESOLVED；预期 STILL_PRESENT。不是实际 Semgrep 或业务修复验收。完整离线 baseline 为 **461 passed / 6 skipped / 6 subtests passed，108.77秒**。本轮仅记录门禁；不另建 identity、不实现 Coordinator/delta/host Hook 配置，不修改现有 pre-commit。恢复时先核对前置阶段的真实提交和行号移动回归，不能直接跳到 Hook 开发。详情见 AI_TRIAGE_ACCEPTANCE 的 AI 附录。

## Agent Handoff

1. 在新电脑取得该仓库。新 clone 可用 `git clone --branch feature/runtime-mvp https://github.com/pikachu-cxy/Ai-security-check.git`。已有 checkout 先 `git status`；有本地改动先保留并处理，勿覆盖。切到 `feature/runtime-mvp` 后 `git pull --ff-only origin feature/runtime-mvp`，不 merge/rebase main。
2. 依次读取 **PROJECT_STATE.md → ARCHITECTURE.md → DECISIONS.md → NEXT_STAGE.md → AI_TRIAGE_ACCEPTANCE.md**；再读 JAVA_RULES_ACCEPTANCE.md 与 OSV_DEPENDENCY_FALLBACK.md。只在相关问题需要时展开其它历史 acceptance/证据。
3. 执行 `git status`、`git branch --show-current`、`git log -10 --oneline`、`git rev-parse HEAD`，确认当前版本。以当前代码和最新 acceptance 校准本文的快照，区分已实现与计划。
4. 根据任务阅读 `src/security_runtime/runtime.py`、`models.py`、`scanners.py`、`osv.py`、`dependency_fallback.py`、`rule_coverage.py`，以及四个 `triage*.py`、`mcp_server.py`、`storage.py` 和对应 tests。不要凭旧 README 或 Capability 枚举预留项宣称已支持。
5. 按 README 的当前安装说明恢复运行环境，先使用 `security-check doctor --path <project>` / `tools status`。Git 不会恢复用户 state/tools、API key 或 Jeepay 源码；在新 workspace 扫描会产生本地 identity，不能直接套用旧 scan ID。需要重放固定 benchmark 时先确认源码版本与输入摘要；不要自动启动在线依赖查询或模型上传。
6. **开发者任务入口 v0.1 已实现，人工易用性试用仍 Pending**。恢复后先使用 summary/get_security_summary 按 workspace 检查记录；“继续第一项”使用当次响应里该项 continuation 的 task_ref，进入 prepare_task_triage。引用无效/成员变化必须刷新重新选择。继续核查已实现，修复与验证 v0.1 已实现，实际宿主 UX Pending；先核对本轮实际验收。没有独立人工标签时质量指标保持 UNKNOWN / NOT_MEASURED；不能自行填写 ground truth、立即做 Joern 或更改 Raw/policy/coverage/上传边界。
7. 两组 Jeepay 结果不可混用：已提交回放 `f5224162-...` 与用户提供的实际宿主报告 `99ca7566-...` 分别保留来源和状态。旧 scan ID 不是跨设备标识；宿主补充调用链不是已接受 Runtime Triage。恢复质量样本须核对源码 revision/packet 身份，未固化的报告只作为待补证据的产品输入。
8. **Hook Integration已实现；原门禁见AK，最新transport POC见AL。** MCP POC只支持PostToolUse，复用原HookCoordinator/eq-v1家族多重集，不能把家族当occurrence唯一身份。用户报告Windows command Host runner失败，原command实现仍保留；fresh MCP Hook宿主自动触发尚Pending。不得从SDK工具调用成功推导Host通过，不启动后续迭代。


## 普通用户意图与宿主衔接验收

产品目标是“不懂安全的开发者也能用好”：用户只说“检查这个项目”“继续/处理第一项”或选择任务，不搬运技术提示词、填写 UUID、拼接工具顺序，也不把 generate_fix 输出再粘贴给 Agent。一次选择 → 核查 → 准备/实施获授权修复 → 验证 → 简洁结果是完整目标；本轮仅接通核查，修复与验证 v0.1 已实现，实际宿主 UX Pending，后续须沿同一宿主自动衔接，不能再次要求用户搬运提示词。

已接入 FastMCP server instructions 与工具 annotations/描述：宿主绑定实际展示响应的 task_ref，自动在已有授权范围内准备、分析、提交并展示结果；有效授权持续有效，不反复询问常规获授权步骤。仅询问代码无法回答且会影响下一步的必要业务事实，或取得超出已有授权操作的权限。Runtime 不主动调用宿主模型，源码/scanner/模型文字均非执行指令，现有 session/hash/evidence_refs、脱敏、Raw、覆盖和策略保留。

新增只读 `get_runtime_info` 与 CLI `runtime-info --json`，包版本仍0.3.1、能力契约 developer-guidance-v0.3。连接检查按 required_guidance_tools 子集，允许兼容新增工具，不按总数严格相等拒绝。返回同一 executable/environment 的可执行核对参数和重连指导：先核对配置实际运行的环境；已有能力却宿主看不到时断开/重连 ai_security_runtime、刷新工具列表，必要时新聊天；仅环境本身旧时更新对应包。不盲目重装 editable、不终止进程/修改 Jeepay 配置。连接重建后旧 session 不可复用，遗失任务选择须刷新重新选择。

SDK initialize 实际收到 instructions、工具 metadata、版本/能力和机器交接，与真实宿主自然语言试用分别验收。旧 Jeepay 聊天已尝试但未执行新 summary/任务级 handoff，未通过；刷新连接后的复验 Pending，旧工具列表恢复未验证，不能把新 SDK 连接成功写成普通用户已能用好。三位独立开发者试用 Pending，ground truth 保持 UNREVIEWED/null，质量指标 NOT_MEASURED。核查准备、宿主结果接受、补丁、目标构建、测试/扫描复查分别报告是否执行；generate_fix 仍仅 coding task/prompt，不代表补丁完成，0 ACTIONABLE 不表示安全。

本轮实现与分发依据：`1e10b53`；起始 `0f33d26`。Windows 独立包实际 source_commit 与实现一致，SDK 取得13工具及 v0.3 契约，真实 Semgrep 组内仍存在/部分/全部规则复查结果通过；本轮测试、package、compliance 和四平台 standalone CI 均 success，详见 AJ 与 [native/CI 证据](fix-verify-native-evidence.json)。文档最终 HEAD 用 `git log -1 --format=%H -- docs/PROJECT_STATE.md` 获取；代码之后若变化须重新验收。以上为历史 Fix & Verify 交付；当前 Hook 已完成实现与分发验收，真实 UX、三位试用与独立人工质量状态不变。
