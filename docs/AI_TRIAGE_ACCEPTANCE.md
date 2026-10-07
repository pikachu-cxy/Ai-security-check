# AI Finding Triage & Risk Validation v0.1 验收

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

P0-10.1 local targeted/native/installed/package checks passed; final focused/full regression PASS (LOCAL VERIFIED; actual visible Cursor UI Pending); actual visible Cursor UI Pending. Existing triage/ground truth status is unchanged.

See [acceptance](cursor-visible-feedback-acceptance.md) for binding, bounds, privacy, native race evidence and manual UI trial.


## P0-9.6 — Advisory remediation acceptance

Final focused: **397 passed in 1074.60s (0:17:54)**. Full offline: **1730 passed, 9 skipped, 6 subtests passed in 2361.35s (0:39:21)**. Package/integrity/compliance/candidate install PASS; actual Desktop NOT_RUN, Cursor continuation Pending.

18 个新增 cases：Cursor NEW TLS attribution → AUTO policy → OFFERED；真实用户 report_only 偏好；manual/confirmation policy；缺失/错误 workspace/session/host context；generic advisory transport；禁止源码写入/任意 Scanner prose/Secret/Host ID 泄漏；无 execution capability、stale task、malformed policy fail closed；无假 config.path；确认 revision 保留；capability claims 不授权；旧 Agent Episode 不被 advisory 继续或修改；跨进程 closed recent diagnostics。

真实 managed offline Scanner / 独立 Cursor command fixture、本地实际 MCP stdio + managed Scanner Codex 两轮 recurrence 已验收；完整回归、包结果和 skipped 单列见 [本轮验收](cursor-advisory-remediation-acceptance.md)。全部为本地模拟 Host，真实 Desktop 未执行，Cursor post-edit schema 未新增 context，OFFERED 不是自动修改/verified/CLOSED。

无 commit/push、活动 Runtime 替换或真实 .cursor/.codex 修改。冻结代码/旧文档历史通过 incoming byte/AST audit 保留。


## P0-9.5 — First-scan mutation attribution acceptance

新增 25 deterministic cases：新风险、已有风险/行移动、同 rule 第二实例、旧 bytes 不可恢复、snapshot 缺失、版本/引擎/rule 变化、pre scanner failure/incomplete coverage、moving source、safe edit 无额外 scan、LF/CRLF/BOM、临时目录清理、单文件风险 scope、reload、staged recovery、retry、workspace/HMAC/closed diagnostics、shared legacy entry、旧 blob 读取超时。模拟 Scanner 结果只用于语义测试，不作为真实性能证据。

另有 actual managed offline Scanner / independent Cursor command processes、跨进程 CLI recent、本地 Codex MCP simulated Host 两轮 INLINE_PREPARED/Envelope/真实 scanner proof/CLOSED、wheel/sdist/integrity/compliance 与隔离候选安装。实际 Cursor policy 独立接线阻塞按 PARTIAL 报告，不把泛化 ADVISE 误报为 Remediation Offered。具体最终结果和 skipped 单列见 [本轮验收](first-scan-attribution-acceptance.md) 及关联 JSON。

未执行真实 Desktop E2E、不替换活动 Runtime、不改真实 .cursor/.codex、不调用模型/build/Deep、不 commit/push；前序未提交内容保留。


## P0-9.4 — Cursor Event Lifecycle + Baseline Ordering

首轮 targeted 208 passed / 1 failed（旧 Stop assertion），按本轮明确 finalization 状态修正；focused最终343 passed。新增 lifecycle test + pipe-controlled独立进程 fixture；成功 publication overlap 仅一轮Scanner且delta=1；捕获前已有修改则 attribution unavailable，无伪造pre-edit；timeout pending跨进程可见且retry；same bytes/read-only/Stop无扫描。

package首轮发现fixture未进sdist，增加MANIFEST精确include后通过。独立CLI recent、actual managed offline Scanner候选安装与Codex actual local MCP回归均有artifacts。本地进程fixture不等于真实Desktop新生命周期通过，Cursor自动 continuation/人工ground truth不伪造。

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

## Core P0-7.3.2 — Workspace binding failure attribution

只读真实 active launcher/Project C 复现：canonical cwd→Git root 正常、无 related project layer；失败源于 configuration_status 的 INSTALLED_RUNTIME_REQUIRED，旧 catch 误标 workspace mismatch。修复限定于已有 COMMITTED signed enrollment 的只读 exact fingerprint 检查，未降低新安装 DEV opt-in、workspace/session/ref/replay/link 校验。28 new cases，最终 focused 180 passed / 263.29s；完整回归 1498 passed / 9 skipped / 6 subtests passed / 2034.91s，零失败。[回归及 skipped 原因](workspace-binding-regression.json)。候选包 integrity/compliance PASS / 7.78s。用户 .codex/Project C 只读，无源码修改或实际扫描，无新 remediation/opaque ref；真实 Desktop 后续一次普通编辑待用户复测。[详细证据](workspace-binding-acceptance.md)。

## P0-7.2 Codex Tool Coverage

Global Codex edits through Bash now reach PostToolUse. Read-only Bash is explicitly observable and skipped; mutation/UNKNOWN uses real snapshot and scanner logic. Missing SessionStart readiness is recoverable through bounded lazy bootstrap without granting first-scan AUTO_FIX. Desktop trial remains pending.

## Core P0-7.1 — Codex host-owned Hook state compatibility

仅修复配置兼容性，feature/runtime-mvp / ee1bfd9c12493683cc313cb3628753a51ae124ac 不变。不 commit/push、不替换活动 Runtime、不读写真实用户 CODEX_HOME；前序 dirty 保留，PROJECT_CONTEXT 未读写，P0-8 未开始。

已确认根因：_config 将 TOML hooks.state dict 当 event list；base/global 后续重复 Hook 检查也直接遍历所有 hooks 值。按当前官方 HooksToml / HookStateToml schema，仅对 TOML 的 state 建立明确 metadata 分支；每条 state 是 object，enabled 为 bool、trusted_hash 为 string。官方未封闭 state object 的扩展字段，保留其值；未知其它 hooks dict 不获得豁免。独立 hooks.json 保持 event-only 校验。真正 event groups/handlers、command/server/tool/input/timeout/statusMessage 校验与签名 ownership 冲突检查仍 fail closed。Runtime 不使用这些 host trust values 决定自有 ownership 或修改 trust。

只建立 event-only view，不改变原 parsed document；现有 signed managed block/CAS 合并保留 TOML 原字节，uninstall 恢复原 user bytes。state 与 node_repl、用户 inline/JSON Hook、未知 top-level 设置共存；setup/repair 两次稳定且无无意义重写。两种实际定义来源仍按既有 duplicate 检查处理；state 不算 event source。[详细验收及官方来源](codex-hook-state-acceptance.md)。

新增 25 cases；focused 160 passed / 121.85s；最终 full offline：1414 passed, 9 skipped, 6 subtests passed in 1853.57s (0:30:53)（runner 1854.15s），9 skipped 单列不计 PASS。[回归](codex-hook-state-regression.json)。wheel/sdist integrity + licenses/notices compliance PASS，[package](codex-hook-state-package.json)。temporary venv 强制安装本轮 wheel，确认 module origin 在其 site-packages，借用已有依赖、无网络下载；实际 CLI setup→setup→repair→repair→status→doctor→uninstall 全 PASS，实际 Codex CLI 0.159.2 正常解析脱敏 state 且同时发现 node_repl/ai_security_runtime。[安装验收](codex-hook-state-installed-trial.json)。修复前隔离结构 fixture 为 CONFIG_INVALID，修复后 MCP/Hook CONFIGURED；不是实际 Desktop Hook trial。

现有两份产品模块仅 narrow compatibility hunks；新增 test/fixture + MANIFEST fixture include。router/remediation/Ticket/Scanner/Deep/CET 与 incoming 字节相同；[前序工作区保留审计](codex-hook-state-workspace-audit.json)。真实 Desktop 验收仍 Pending，三位试用待验收、独立 Ground Truth 未执行，未扩大本轮范围。


## Core P0-7 temporary CODEX_HOME / actual MCP / Desktop Pending

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



## BH. Core P0-6.1: Post-edit Exact Target Verification

本地既定门禁完成，停止本轮；Desktop 重试未执行。

仅 Core P0-6.1 Post-edit Exact Target Verification correctness bugfix。继续 feature/runtime-mvp / ee1bfd9c12493683cc313cb3628753a51ae124ac，168 incoming 文件已保存快照，P0-1…P0-6 前序 dirty 完整保留；不 commit/push/install/替换活动 Runtime，不运行新 Desktop E2E。

根因：原 FastFix.removal 从 raw UTF-8 bytes 计算整行 range/segment/preimage/canonical postimage SHA，但 Agent Ticket 只保留整文件 preimage 和唯一 postimage SHA。post_failure 只接受“删除风险整行、保留后续空行”的唯一结果；真实 Desktop patch 删除风险整行及其后一个空行，所以 Scanner 已观察风险消失仍无法授权 canonical proof。只读读取已有试验记录：新增/删除均 8-space statement + 1 empty line，记录无其它 changed lines；当前文件 UTF-8 BOM / MIXED EOL。完整旧 Ticket/raw preimage 未捕获，[forensic](inline-exactness-forensic.json) 中 preimage/expected SHA 与 offset **明确为重建假设**，不冒充原凭据。未发消息、未使用旧 opaque refs、未编辑或持久化真实目标源码。这是历史取证，不是新 Desktop E2E。

没有证据表明原 raw-byte helper 存在 decode→newline normalize→encode、BOM 删除、字符/byte offset、pre/postimage 混用或错误 snapshot 来源。具体 mismatch 是 following-empty-line cleanup；设计过窄而不是取消 whole-file hash 本身。构造现在复核 original file/segment/canonical result SHA 来保证同一 preimage。

新 signed edit_envelope = 原 risk physical line + 至多一个已存在的、真正空的紧邻 LF/CRLF line。不含业务代码/注释/indented blank/第二空行。预枚举 ≤3 exact byte variants：REMOVE_LINE（旧结果）、REMOVE_STATEMENT（只移除 statement，原缩进/尾部/EOL/后空行精确保留）、REMOVE_LINE_AND_EMPTY_LINE（只在原已有该空行时）。签入 range、statement range、原 segment/statement SHA、原字节总长、prefix/suffix SHA、EOL/BOM、variant segment length/SHA/whole-result SHA。所有结果从原 bytes 得到；无 post-edit normalize/fuzzy/diff/formatter tolerance/语义等价推断。新缩进/空格、whole-file EOL/BOM 改动均拒绝。

Post-edit 比较原长度定位的 prefix 与右锚定 suffix SHA，验证 envelope 内长度/segment SHA 为预枚举结果，再验证该 variant whole-file SHA；外部 byte-for-byte preservation 保持。原 HMAC、workspace/task/remediation/Episode/grant/scan/snapshot、policy/TTL/attempt、source/preservation/scope guards 原样执行。成功后仍走原当前 snapshot + TaskFix/Verification **真实原规则 Scanner recheck**，签名 receipt 才能 CLOSED；Ticket MATCHED + scanner FAILED/UNAVAILABLE 仍 INCONCLUSIVE。原 Fast Fix 单结果 contract 不变、legacy 无 envelope Ticket 保留旧严格 SHA 分支。已有旧客户端 prepare/Context hint/fallback 不变；正常 inline prepare RPC 仍 0。

非敏感 exact_target_verification diagnostics：MATCHED/REJECTED、subreason、expected preimage/current/canonical SHA、expected envelope length/actual result length/deleted bytes、prefix/suffix/outside changed、expected/actual EOL/BOM/encoding、accepted variant、preservation guard bool。无源码、Secret、byte diff、模型内容。顶层兼容 TICKET_TARGET_NOT_EXACT，子原因 TARGET_PREIMAGE_NOT_REMOVED / TARGET_RESULT_MISMATCH / OUTSIDE_EDIT_ENVELOPE_CHANGED / LINE_ENDING_IDENTITY_MISMATCH / ENCODING_IDENTITY_MISMATCH / TARGET_RANGE_DRIFT / RESULT_HASH_MISMATCH；原 ticket-binding/scope/clock/expiry reason 不改。

产品 hunk 仅 agent_fix_ticket.py + 新 agent_fix_envelope.py；新增 tests/test_agent_fix_envelope.py（48 cases）、scripts/inline_exactness_acceptance.py，MANIFEST 加一行及文档/安全报告。Security Context、Fast Fix、Hook schema/MCP names/4 claims、remediation/receipt/Family/Episode、timing、scanner/cache、Deep/Functional/BOM/CET 文件与 incoming **字节相同**。不增加 prepare RPC、新规则、daemon/bridge/build/Deep。普通 Agent 编辑仍是 post-validation，未观测 edit-and-restore ABA 不可证明，没有原子编辑承诺。

### BH.1 Gates and evidence

focused：PASS: 138 passed in 811.85s (0:13:31)。

full offline：PASS: 1325 passed, 9 skipped, 6 subtests passed in 2131.43s (0:35:31)。skipped 单列不计 PASS；此前 9 skips 的 PATH/opt-in managed 条件保留，真实 Scanner 另走 SDK gate。

MCP / managed Scanner：PASS / 341.96s。[core](inline-exactness-core.json)、[legacy fallback](inline-exactness-fallback.json)、[legacy client](inline-exactness-legacy-client.json)。实际 stdio MCP + 离线 managed Semgrep/Gitleaks；Host 编辑是一次性 native fixture simulation，**不是 Desktop**。旧 P0-6 hash-verified wheel source 重现 risk absent 仍 TICKET_TARGET_NOT_EXACT/ESCALATED；新 LF/CRLF × BOM/no BOM、mixed+BOM、statement/old canonical、recurrence 取得当前 original-rule proof；邻接业务编辑在 Scanner risk absent 时仍拒绝且无 resolution。旧 refs 在 recurrence 计时后拒绝，不序列化/重建引用。正常每 cycle 2 Runtime Hook MCP、0 prepare、1独立 test Host RPC；额外状态检查 RPC 在计时后单列。每成功 cycle 仍 2 Hook SAST + 2 Hook Secret + 1 canonical rule recheck，共5真实进程 invocation；失败 envelope 在4次增量进程后拒绝、不会伪造第5次 proof。并发 focused 测试期间样本仅证明 correctness，不作性能提升结论。

wheel/sdist package integrity / licenses+notices compliance：PASS / 7.81s，[package](inline-exactness-package.json)。没有 clean install、standalone、CI 或活动替换，未请求新增这些 gate。

[design review](inline-exactness-design.md)、[regression](inline-exactness-regression.json)。

### BH.2 Pending

初轮新增 direct cases 32 passed / 1 failed：mixed EOL 改动且尺寸缩短时，诊断优先给 TARGET_RANGE_DRIFT；只修诊断分类优先级，不放宽 acceptance。下一轮 35 passed / 13 setup errors：新 module 导入 fixture 时缺少 repo fixture，补显式 fixture import，旧测试未改。修正后 48 passed（46新+2旧 inline契约）；最后再加2个合法 statement variant + scanner FAILED/UNAVAILABLE 不能关闭的 case。历史日志均保留，最终以 focused/full 为准。

Fresh Desktop 本轮 NOT_RUN，下一次仅用户自行安排加载本轮 Runtime 后，隔离 fresh chat：safe baseline → 引入唯一独立 TLS 风险及一个紧邻真空行 → Hook INLINE_PREPARED → Agent read一次并按 envelope删除风险行及该空行 → post-edit Scanner + canonical proof → CLOSED/RETURN_TO_HOST；核对 accepted_variant、outside_changed=false、原 refs逐字、prepare count0和原timing。另验证 statement-only、CRLF/BOM 原样保持，以及风险移除同时改邻接业务行仍拒绝。缺字段/stale立即停，不恢复或重建 opaque refs，不主动 build/Functional/独立扫描。

三位真实试用 Pending；Ground Truth UNREVIEWED/null；Maven PENDING_ENVIRONMENT_PREREQUISITES；Fast Host atomic bridge PENDING_HOST_ATOMIC_EDIT_BRIDGE；其它阶段 Planned。PROJECT_CONTEXT 未读写。完成既定门禁即停止。



## BG. Core P0-6: Inline Prepared Agent Fix Ticket / Reliable Handoff

本地实现及既定门禁完成，停止本轮。

仅 Core P0-6 Inline Prepared Agent Fix Ticket / Reliable Handoff。继续 `feature/runtime-mvp` / `ee1bfd9c12493683cc313cb3628753a51ae124ac`，165 个 incoming 文件已快照；前序 P0-1…P0-5 dirty 保留。P0-5 wheel SHA `fa1a1e90ab5df6b9d2a46a2ef8b66cceb53922a07d2c1286d36a7cbc4658ef3e` 校验后仅提取源码作 A/B，不安装。用户提供 Episode 8 的 cycle 90854.049ms、continuation wait 61355.587ms、prepare 1133.092ms、约 12 次编辑前 Agent calls / 1 read / 0 search / 1693 context bytes，标 `USER_REPORTED_ACTUAL_DESKTOP`；本轮未自行复现 Desktop。

先完成 [prepare A/B 安全职责分析](inline-ticket-safety.md)：所有 POLICY_AUTO TLS **preparation** 必需项可在原 workspace 锁内完成，包括 workspace/Episode/grant/授权/预算/成员/origin scan/snapshot/source/scope、TaskFix bounded evidence、prepared attestation 与提交依赖。B 是 USER_CONFIRMED 的用户选择及实际编辑/后续 scanner receipt，不从 initial Hook 推断。原 `_prepare` 完整执行，不删检查。P0-5 历史将 prepare 保守保留为独立 RPC；本轮在此窄 eligibility 内复用同一函数到 Hook 事务，不改变 generic/confirmed prepare 或安全 proof。

只在 connected MCP Hook（可信 embedding 可显式 opt in）、POLICY_AUTO / SAFE_DETERMINISTIC_FIX / AGENT_FIX / Fast Host capability unavailable / 唯一 `ai-security.java.trust-all-hostname`、attempt 1、当前 scan/Episode/grant/snapshot/target 且唯一整行可精确删除时签发 Ticket。命令 adapter 默认保留原 prepare。正常窄路径为 Hook → 原 prepare 检查在 Hook 内完成 → structured Ticket + Context → Host read/edit → post-edit incremental scanner + 原规则 targeted real recheck → 签名 receipt / CLOSED / RETURN_TO_HOST；无额外 prepare MCP。没有 Runtime source writer、模型调用、原子编辑桥、Scanner worker、新规则、Deep/Functional/build/test/Sandbox/CET/Plus/Pro。

`agent-fix-ticket-v1` 正式字段位于 `structuredContent.remediation.agent_fix_ticket`：version/mode/fix_path、workspace_id、episode_id、grant_id、原 task_ref/remediation_ref、finding_id/origin_scan_id、security_context_ref、snapshot_digest/scope_hash、allowed_target_paths/rule_id、authorization_kind、attempt_count/max_attempts、prepared_attestation、connection-scoped 900s expiry、精确 removal operation、原文件/预期结果 SHA、ordinary Agent post-validation edit contract、real-scanner success/CLOSED/RETURN_TO_HOST 及 production UNKNOWN / no Deep。上限 4096 canonical bytes；Context 仍独立解释 What/Where/Why/建议/范围/成功条件，不成为 credential。inline Context 的 `prepare_required=false` 仅描述已签发 Ticket；原 refs 不解析重建、不改字，informational context ref 对当前小对象重新计算，不是 bearer grant。

原 authorization、2-attempt budget、membership、source/preservation、receipt binding、真实 scanner proof 保留。inline 额外要求 whole-file expected result bytes，连接内 ≤32 Ticket + 单调 TTL + policy revision binding。磁盘仅存签名 attestation HMAC/状态/固定原因，绝不恢复 live authorization；重启丢 Ticket/prepared，不伪造延续。unexpected target、额外文件、expiry、wrong binding、lost attestation 不能 CLOSED；观察到 stale 后持久拒绝，不被后续 manual-recovery Hook 漂白。未编辑且原 freshness 仍有效时，可用**原两个 refs**走 legacy prepare 重新检查并替换未消费/过期 preparation；可不传 hint，旧 Host 也可传当前 inline Context ref，Runtime 在完整原检查内从当前事实重建这个 informational 对象（只差 prepared flag），不是从 hint 接受授权。已 drift/escalated 要刷新当前任务，不盲目重试旧授权。已签发 CLOSED security proof 不被 Ticket expiry/重连或 Deep unavailable 降级。

没有 Host 原子编辑锁，未观测的 edit-and-restore ABA 无法证明，旧 prepare 同样无法检测；不声称阻止每次外部写入或证明模型读了哪份 Ticket。可观测的异常编辑被当前字节/snapshot/其它文件 preservation 和编辑后 scanner 阶段拒绝。完整 machine Ticket 不依赖 prose：测试删除或截断文本后仍从原 structuredContent 完成闭环。官方 [Codex Hooks](https://learn.chatgpt.com/docs/hooks) 于 2026-10-05 实际读取，说明 MCP 与 command Hook 输出契约一致、大输出可 spill/truncate；没有 arbitrary structuredContent 独立向模型展示的官方保证。保留正式 SDK 字段，同时 documented additionalContext 只投影完整同一 Ticket/Context 与短固定说明，去掉重复 refs/报告/scanner diagnostics。**SDK 完整性 PASS 不等于 Desktop 模型一定见到完整对象**，其 gate 仍 Pending；不改 config/schema/四个输入 claims，不猜官方字段。

observability：agent_fix_ticket_version/mode、prepare_task_fix_required、Runtime 工具函数入口计数（当前 grant/当前连接）、handoff_recovery_required、structured_handoff_complete、inline_prepare_reason、ticket_stale_reason/ticket_status；Host retry/read/search/model CPU 未观测仍 null。P0-3 timing 保留：inline_prepare_started/finished 在 initial runtime 内；独立 inline_host_edit_window 为 response-ready→post-edit Hook，混合 Host/Agent/transport，不叫模型 CPU。正常 inline 不制造 prepare MCP/Host received 端点；旧 prepare windows 为 null，不重复相加。recurrence 独立新 Episode/grant/scan/Ticket；相同字节的 snapshot digest 可以相等，隔离靠新身份，绝不伪造 hash。

### BG.1 Tests and gates

focused：PASS: 112 passed in 823.71s (0:13:43)。

full offline：PASS: 1277 passed, 9 skipped, 6 subtests passed in 2174.36s (0:36:14)。skipped 单列、不计 PASS；3 个 opt-in managed benchmark、6 个 PATH scanner 环境条件，真实 managed 引擎另走本地 SDK gate。

actual MCP + managed Scanner A/B：PASS / 69.9s；package wheel/sdist integrity + licenses/notices compliance：PASS / 4.09s / 108 Runtime source bytes checked。没有 clean install、standalone 重建、CI trigger、commit、push、活动 Runtime 替换或 Desktop E2E。

新增 agent_fix_ticket.py、tests/test_agent_fix_ticket.py（当前37 cases）、scripts/inline_ticket_acceptance.py、inline-ticket-safety.md。修改 remediation.py（原 prepare 复用、签名 requirement、post gate、fallback lock）、mcp_server.py（标准 MCP 窄路径启用）、codex_mcp_hook.py（正式 Ticket / bounded text projection）、host_guidance.py（优先 Ticket 分支）、hook_timing.py（不重叠 inline 窗口）、MANIFEST.in（一行 script）和既有五份文档。旧测试原文未改；fast_fix.py/fix_context.py/TaskFix/Verification/scanner/cache/Functional/BOM 字节不变。11个 ref/receipt/Episode/guard/grant/security recheck 函数 AST、官方 Hook config/output filter AST 不变。_verify 只增 Ticket post gate；原安全校验仍执行。incoming 审计和 source freeze 见 .security-runtime/p06-scope-audit.json；PROJECT_CONTEXT 未读写。

初轮新增 fixture 把 Windows CRLF 改成 LF，精确字节保护拒绝（1passed/1failed）；修测试不放宽校验。其次错误使用不存在的 mode advisory（20passed/1failed）、期待旧 verify wrapper 输出内部 superseded 原因（22passed/1failed），均只修新测试；旧 API generic INCONCLUSIVE 保持。首次 SDK driver 错误要求所有 legacy MCP 工具均 structuredContent，尚未完成 A/B；修 driver，Hook Ticket 仍严格用原 structuredContent，旧 prepare text JSON envelope 按既有协议读取。一次带空格 pytest -k 的 Windows quote 失败/no tests，不计门禁。32case initial complete PASS/152.62s 后增加2 scanner failed/unavailable case；计时修正前兼容focused108passed/404.13s。MCP明细发现post policy误扣上一Hook preparation detail，仅扣当前inline span修正，另加1 accounting case；对应focused40passed/191.06s。其后发现P0-5 Host继续prepare+inline hint兼容问题，修为从当前事实重建informational hint，不放宽授权；定向5passed/18.65s。修正前全量347.05s主动停止return130，不计PASS。新增总37case；最终以final-focused/full为准。初轮MCP/package/fallback另存 before-timing-correction，计时后/兼容修正前报告另存 before-hint-correction，不覆盖错误/历史证据。

最后的 full-before-guidance-correction 实际完成为 1275 passed / 1 failed / 9 skipped / 6 subtests passed（1678.99s），唯一失败是旧 Host 指引契约要求的 `Immediately follow prepare → edit → verify` 大小写。保留原断言，仅修产品 conditional guidance 的句首；原测试单独重跑 1 passed / 0.34s。试图停止该已结束专用 wrapper 被 absent/ambiguous 安全保护拒绝，没有停止其它进程。最后审阅另发现 native Fast 分支不应带 Agent PREPARE_REQUIRED 诊断，仅将新的 offer 限定 AGENT_FIX、保留 Fast 原实现；新增兼容 case 使用 Host fixture edit + 原核查路径（单元测试 provider），1 passed / 6.73s。中止 release-full 专用子进程、保留日志，冻结最终源码后重跑 certified-focused/full；不把此前失败或中断记录改成 PASS。

### BG.2 Actual MCP / managed Scanner A/B

| Path | Episode | Runtime MCP | prepare | simulated Host steps | Context/Ticket bytes | cycle ms |
| --- | ---: | ---: | ---: | ---: | --- | ---: |
| before | 1 | 3 | 1 | 3 | 1699/0 | 13371.98 |
| before | 2 | 3 | 1 | 3 | 1699/0 | 13365.653 |
| after | 1 | 2 | 0 | 2 | 1700/2166 | 13616.619 |
| after | 2 | 2 | 0 | 2 | 1700/2166 | 13857.157 |

相同模拟 Host：1 target read、1 edit、0 search，两版本仅 prepare 步骤不同。独立 test Host edit RPC 每 cycle 1 次，另列、不隐藏。Runtime MCP 3→2、prepare 1→0、fixture步骤3→2；每 cycle 仍2 Hook SAST + 2 Gitleaks + 1 original-rule recheck，共5实际进程 invocation，不取消扫描。两个 Episode 均原 task/grant 对应 resolved receipt，旧 Episode refs 另在计时后拒绝。无 LLM/sleep/network，最终 driver 在离线回归结束后串行运行；此前并发报告另存 inline-ticket-core-concurrent.json，有限样本，不证明真实 Desktop/模型提速，不能拿用户的12次工具数作模拟 baseline。

[core evidence](inline-ticket-core.json)、[legacy fallback](inline-ticket-fallback.json)、[old Host prepare compatibility](inline-ticket-legacy-client.json)、[package](inline-ticket-package.json)、[regression](inline-ticket-regression.json)、[safety responsibilities](inline-ticket-safety.md)。

### BG.3 Pending and next manual Core trial

Fresh Desktop P0-6自然续行/模型看到完整Ticket、p95/p99、三位真实试用仍 Pending；Ground Truth UNREVIEWED/null；Maven PENDING_ENVIRONMENT_PREREQUISITES；Fast Host atomic bridge PENDING_HOST_ATOMIC_EDIT_BRIDGE。其它阶段继续 Planned。当前无需继续压缩 Security Context；先验证本轮 Ticket 自然交接，不能把协议减少一次 RPC 宣称模型已少12次调用。

下次人工 Core E2E（本轮未执行）：用户自行安排加载本轮 Runtime 后，新建隔离 Java 项目与 fresh Codex chat；普通安全编辑建立 baseline，再只引入 standalone always-true hostname override。确认初次 Hook 的 INLINE_PREPARED、完整两个原 refs/attestation/context/target、prepare_required=false、工具调用计数0；Agent只read该target和删除该行、保留所有其它字节。不主动扫描/prepare/Deep/build。确认post Hook真实Scanner原规则proof、matched task/grant receipt、CLOSED/RETURN_TO_HOST、计数仍0和inline cycle窗口。再引入同family核对新Episode/Ticket/scan/grant、旧ref拒绝。遇到缺失/截断/stale字段停止，不从路径重建引用；记录实际Host工具数及wall-clock，若仍恢复summary则保留失败事实。



## BF. Core P0-5: Agent Fix Context Compression

### BF.1 范围与事实来源

仅Core P0-5 Agent Fix Context Compression，继续feature/runtime-mvp/ee1bfd9c12493683cc313cb3628753a51ae124ac与前序全部dirty；162文件incoming快照，P0-4 wheel SHA85576795657bba49bd1380bc1471097630e8f57cb7ed80f1de976f14b712accc只读校验/提取为本地A/B baseline，无安装。Fast Fix文件原bytes保留，PENDING_HOST_ATOMIC_EDIT_BRIDGE；不扩第二条规则、不新增Scanner/daemon/Functional/BOM/CET/Sandbox/Plus/Pro。Runtime仍不写项目源码，Host编辑。

Security Fix Context v1只在POLICY_AUTO + SAFE_DETERMINISTIC_FIX + AGENT_FIX的单条TLS信号启用。共用原RULE/source_proof/_reference/TaskFixService及canonical proof；不新增修复语义。what为rule/CWE-295/当前severity/confidence/class；binding为workspace/Episode/grant/origin scan/finding/snapshot；target为唯一relative file与scanner起止行，可靠symbol未知null；why为固定API与三项既有scanner/本地JDK corroboration依据，不转发scanner message/dataflow/source。recommendation为受限删除override模式（not_a_patch），scope只该installation/1file/32KB且保留其它代码文件；success要求当前snapshot与原规则真实复扫、匹配receipt/CLOSED/RETURN_TO_HOST；context不是credential，生产可达性仍UNKNOWN。

Context固定schema版本security-fix-context-v1，MAX_BYTES3072 canonical UTF-8预算。API/证据项/约束用固定词表；source/comments、scanner description/fix_advice/dataflow/symbol/CWE自由metadata、AI reviews、完整调用树不复制。原scanner finding identity与起止行基于当前可信origin scan、TaskFix resolve与source_proof位置corroboration；workspace、当前Episode/target/snapshot/grant须与_reference读出的签名record相符。symbol/dataflow null，绝不猜compiler-grade事实。完整源码仅由Host在现有workspace按需读取。

### BF.2 协议、压缩和授权

初次Hook携带短context与informational security_fix_context_ref；prepare/verify/Stop handoff仍原两个task/remediation opaque values逐字保留，不改参数字典或重记continuation。仅保留context的Host可在prepare_task_fix调用额外传可选security_context_ref，其值为原context ref；不能让所有旧调用/verify/Deep继承未知参数。接口向后兼容：无hint（包括Stop fallback）返回INLINE compact context；匹配hint时在原ref/snapshot/source/preservation/budget门禁内重建并核对，REUSE_HOOK_CONTEXT仅回指事实，不重复整段信息；不匹配REFRESH_REQUIRED且无prepared attestation。hint单独不能授权，没有remediation grant时固定拒绝；context/ref不持久化，不成为新grant或缓存proof。所有generic selected-task以及USER_CONFIRMED preparation保留旧完整接口；legacy host_protocol.instructions保留短Core结束语，不重复guidance。POLICY_AUTO packet的旧报告/代码excerpts不再输出，bounded_evidence只保留UNTRUSTED_CODE locator兼容标记，不是source packet。

Security context各section：version；binding(workspace_id/episode_id/grant_id/origin_scan_id/finding_id/snapshot_digest)；what(rule_id/cwe/severity/confidence/remediation_class)；target(file/line_start/line_end/symbol/symbol_status)；why(dangerous_api/evidence/source_to_sink)；required_security_property；recommendation(kind/operation/not_a_patch)；allowed_scope(target_ref/max_modified_files/pattern/preserve/source_budget_bytes)；success(original_rule/current_target_snapshot_required/real_scanner_recheck_required/receipt_match_required/final_stage/next_action)；authorization(via/prepare_required/context_is_not_credential)；production_reachability。target位置不重复进scope，opaque refs仍原envelope/handoff，不重构、不放入context；context_ref仅元数据identity，不代替refs。

短GUIDANCE实际678bytes：立即按原prepare handoff、只读目标、按约束编辑、无需重复已corroborated事实；UNTRUSTED_CODE、无审批重复、匹配真实receipt才返回Host、无其它权限。Hook两个feedback字段只短指向context/prepare，不重复这段guidance。prepare仅保留status、原ref/workspace/scan、remediation_authorization、verification_plan、执行声明、host protocol pointer及旧UNTRUSTED_CODE locator。Generic task/USER_CONFIRMED字段和说明不删。legacy POLICY_AUTO报告字段有意替换，调用方应使用新context或ref；旧调用无hint仍INLINE，不是取不到事实。

安全拒绝：SECURITY_FIX_CONTEXT_BINDING_MISMATCH、STALE_FINDING、TARGET_MISMATCH、LOCATION_UNAVAILABLE、STALE_SOURCE、BUDGET_EXCEEDED由metadata构造固定拒绝；Hook不足时UNAVAILABLE_REFRESH_REQUIRED（不增新权限）；prepare错误hint SECURITY_FIX_CONTEXT_REFRESH_REQUIRED，无grant hint SECURITY_FIX_CONTEXT_REQUIRES_REMEDIATION_GRANT，仍原prepare fail-closed。旧Episode/grant refs被原_reference拒绝，任何context不能替代它们；成功上下文也不能替代真实Scanner。

### BF.3 可观测性与实际A/B

diagnostics包含fix_path/version、canonical UTF-8 security_context_size_bytes/chars、递归JSON object key field_count（不是token）、target/scope/evidence counts、agent_prepare_required与duplicated_guidance_removed。Host read/search、model token和MCP transport次数Runtime无法可靠知道，返回null/UNKNOWN。独立SDK fixture能观测自己的3个Runtime MCP及1个Host编辑、1次target read/0search，但不代表LLM工具行为。保留P0-3 timing/cycle与UNKNOWN边界。

| Path | Episode | Context bytes | Facts+guidance bytes | Runtime MCP | Host fixture reads/search | Cycle wall ms |
| --- | ---: | ---: | ---: | ---: | --- | ---: |
| before | 1 | null (no v1) | 8203 | 3 | 1/0 | 23391.335 |
| before | 2 | null (no v1) | 8203 | 3 | 1/0 | 21004.801 |
| after | 1 | 1699 | 4825 | 3 | 1/0 | 22553.257 |
| after | 2 | 1699 | 4825 | 3 | 1/0 | 22981.665 |


真实managed Scanner+actual stdio MCP；Host是SIMULATED_WINDOWS_NATIVE_EDIT_FIXTURE，无LLM、无sleep、offline。相同facts+guidance投影8203→4825bytes（减少41.18%），非整个Hook wire payload；final与focused并行负载，修正前串行报告另存agent-context-core-before-review-correction.json；1699bytes为新context本身，legacy不存在该schema故null。MCP主流程仍3=风险Hook/prepare执行前门禁/修复后Hook；额外Host fixture edit RPC单列1，不隐藏成0；Scanner每cycle仍3SAST+2Secret。before cycles23391.335/21004.801ms，after22553.257/22981.665ms。有限样本不证明wall改善，不声称reasoning加速或Host动作减少，固定Host双方同为1read/0search。recurrence旧ref拒绝在已测cycle结束后另作诊断，不混入比较。Runtime context构造有新增绑定/成员校验成本，Scanner/运行波动也存在；未测完整归因，不将全部差值归因模型或context CPU。初轮8203→4424byte报告早于兼容修正，不替代final；并行版119.93s只单列。

两条路径均2风险/修复Hook SAST+2Secret+1original-rule recheck，真实process ledger计数。每条两个Episode、正常receipt的task_ref/grant逐字匹配；after旧ref另测拒绝。MCP主流程不变：1 handle_hook_event检测/政策/上下文；2 prepare_task_fix当前授权/范围/snapshot/source检查+prepared attestation；3 handle_hook_event观察Host改动、post-edit scanner+canonical原规则proof并CLOSED。第一与第二均非纯信息往返，不能安全合并。prepare复用已发送context，但仍重新验证绑定和事实；未拿旧scan result冒新proof。

[regression](agent-context-regression.json)、[core A/B](agent-context-core.json)、[Fast compatibility](agent-context-fast-compat.json)、[package](agent-context-package.json)、[initial core](agent-context-core-initial.json)、[concurrent core](agent-context-core-concurrent.json)、[initial package](agent-context-package-initial.json)、[initial Fast](agent-context-fast-compat-initial.json)。Host工具是单独test fixture，WINDOWS_KERNEL_DENY_WRITE_DELETE与P0-4同实现，不是Codex官方edit API；双方编辑动作完全相同，无人为多读/多search制造收益。模型推理时间与实际LLM工具数UNKNOWN。

### BF.4 测试、门禁与保留

新增test_fix_context.py 11functions/21cases；已有host orchestration及Code Mode契约测试只将smart_auto长prose断言替换为context/自动授权/不重复编辑/实扫等协议语义断言，ask_before_fix与其它旧tests保留。final focused PASS：205passed/822.16s（wrapper823.30s）；final full offline PASS：1240 passed, 9 skipped, 6 subtests passed in 1991.19s (0:33:11)（wrapper 1992.56s）；9 skipped单列BF，不计PASS。第二轮全量早期发现Code Mode旧测试要求stopReason重复完整guidance，单测1failed/4passed/21.99s；仅将该smart-auto文字断言改为精简协议语义，保留completed-edit/授权/两原refs/confirmed/Stop/ABI检查，产品代码未变。第二轮focused/full分别383.65/384.07s中止return130，不计PASS；修正后该模块5passed/19.71s。第三轮focused发现新增context把VALID AI review误判为Scanner过期，既有receipt单例1failed/3.76s；修正仅删除新增review-status条件，原grant/snapshot/source/ref与receipt校验未改。第三轮focused/full分别1139.69/1139.58s中止return130，不计PASS。随后context+receipt 47passed/1failed/316.60s为新fixture伪造VALID但缺ai_review时错误期待授权；已改为断言原TaskFix拒绝且不建立prepared，既有receipt测试原文保留。第四轮full200.13s中止return130，不计PASS。最终focused聚焦直接受影响7模块/205cases，先通过再跑full；新增仍21cases，完整1249收集/9skipped。final MCP A/B PASS/118.06s；原Fast/recurrence/fallback compatibility PASS/112.33s；package integrity/compliance PASS/7.28s，107Runtime文件bytes核对，dist/agent-context-final，无安装。初轮3failed/104passed为新测试过宽source子串及既有_fail无status断言错误，已修；诊断1failed/1passed，v2 context19passed/104.71s。后发现legacy instructions字段缺失、prepare arguments新增hint泄漏到旧verify/Deep/Stop消费者；已修正原两个args与短legacy字段。隔离诊断18passed/1failed/22.15s；失效门禁focused/full在631.58/631.65s中止return130，不计PASS；兼容复核129passed/457.00s。首轮MCP/package/Fast evidence另存initial；并行负载A/B另存concurrent，修正前串行证据另存；final与focused并行重测。产品/测试/脚本158文件冻结。

21cases覆盖context小预算与真实bytes/key统计、workspace/Episode/remediation/origin/target/snapshot binding、篡改hint、stale source/AI review annotation、recurrence旧ctx/ref、新ctx、污染scanner自由字段/Secret/source排除、原真实verify入口、失败Scanner不得close、无Deep。旧host prose断言仅smart-auto语义更新；确认相关测试原文保留。129passed兼容复核与修正前中止门禁详见上文，不计作final full通过。

| Gate | Result |
| --- | --- |
| initial focused | FAIL：104passed/3failed，351.95s（wrapper353.26）；新增测试误把continuation_source当source泄露，及原_fail无status键；修正断言，不算PASS |
| diagnostic | FAIL：1passed/1failed，9.09s；上述source子串；不算PASS |
| context v2 | 19passed/104.71s；随后增加canonical record Episode/snapshot对比+2cases，不能代替final |
| final focused | PASS：205passed/822.16s；wrapper823.30s |
| final full offline | PASS：1240 passed, 9 skipped, 6 subtests passed in 1991.19s (0:33:11)；wrapper 1992.56s；9 skipped不计PASS |
| local MCP A/B | PASS/118.06s；真实managed Scanner，模拟Host，noLLM/sleep/network |
| Fast/fallback/recurrence compatibility | PASS/112.33s；Fast原文件未改、原两扫描窗口保留 |
| wheel/sdist integrity/compliance | PASS/7.28s；107 Runtime文件bytes一致，licenses/check-wheel/notices |
| actual Desktop/clean install/standalone/CI | NOT_RUN_USER_REQUEST / NOT_RUN_THIS_SCOPE / NOT_REBUILT / NOT_TRIGGERED_NO_PUSH |

Wheel SHAfa1a1e90ab5df6b9d2a46a2ef8b66cceb53922a07d2c1286d36a7cbc4658ef3e；sdist SHA3d1c33dea71a4b5a458cf550b8731025a294959afdaed88b1baa02c2f03df016。代码/测试/公开脚本158文件冻结；162文件incoming范围核对；12个_security/references/grant函数AST unchanged、Fast字节不变、official config/output AST unchanged，TaskFix/Verification/scanner/cache/Functional/BOM/CET/旧fixtures与前序其它未提交bytes保留。修改仅fix_context.py新增、remediation/codex_mcp_hook/mcp_server/host_guidance、tests/test_fix_context新增、host_orchestration及Code Mode smart-auto文字断言、script新增、MANIFEST一行、五文档与evidence。PROJECT_CONTEXT未读写；没有reset/restore/clean。

完整回归skipped（6个PATH Scanner前提、3个opt-in performance；真实managed Scanner另行通过上述本地MCP验收）：

- SKIPPED [1] tests\performance\test_managed_cache_lifetime.py:14: Explicit managed real Scanner benchmark environment required
- SKIPPED [1] tests\performance\test_managed_cache_lifetime.py:38: Explicit managed real Scanner benchmark environment required
- SKIPPED [1] tests\performance\test_managed_hot_path.py:10: Explicit managed real Scanner benchmark environment required
- SKIPPED [1] tests\test_e2e_real.py:58: real scanner binaries required
- SKIPPED [1] tests\test_e2e_real.py:80: real scanner binaries required
- SKIPPED [1] tests\test_e2e_real.py:120: real scanner binaries required
- SKIPPED [1] tests\test_e2e_real.py:154: real scanner binaries required
- SKIPPED [1] tests\test_e2e_real.py:68: real scanner binaries required
- SKIPPED [1] tests\test_e2e_real.py:38: real scanner binaries required

### BF.5 后续人工A/B与停止边界

当前Codex仍AGENT_FIX，Fast PENDING_HOST_ATOMIC_EDIT_BRIDGE。后续用户选择隔离baseline/new版本与fresh Chat、相同安全fixture/模型/提示、只对当前Chat原refs推进，不跨Chat转交；确认B context/REUSE及target最小edit、matched真实resolved/CLOSED、无Deep。手工工具轨迹统计read/search/MCP，记录risk→return wall与跨Host窗，至少一对并重复以排除LLM/Scanner波动，真实token数需Host tokenizer数据；本轮没有执行Desktop/没有替换Runtime。无真实LLM证据、不建议扩SQLi/SSRF；它们仍需要上下文/业务条件，不把TLS确定性事实方案泛化。

既定门禁和真实记录已完成，本轮停止，无commit/push/活动安装/系统更新/生产操作/Secret rotation/用户项目编辑/目标build/test/新阶段。三位试用Pending、GroundTruth UNREVIEWED/null、真实Maven PENDING_ENVIRONMENT_PREREQUISITES、p95p99 NOT_MEASURED保留。

## BE. Core P0-4: Deterministic Fast Fix Path

### BE.1 Host能力与范围

2026-10-05实际读取[OpenAI官方Hooks](https://learn.chatgpt.com/docs/hooks)：MCP Hook调用已连接server并遵循Hook输出协议，PostToolUse的additionalContext/continue:false提供模型可见反馈；PreToolUse updatedInput只能重写已排队工具。未发现PostToolUse响应能直接启动原生edit、检查当前Episode并原子CAS的官方契约。现有Codex Runtime integration也只输出反馈、四个metadata claims与Agent handoff，apply_patch无whole-file digest CAS参数。因此默认Codex严格保持AGENT_FIX/FAST_FIX_HOST_CAPABILITY_UNAVAILABLE；未实现、未宣称Codex machine-executable或无LLM apply。

Fast Fix仅支持POLICY_AUTO + SAFE_DETERMINISTIC_FIX + ai-security.java.trust-all-hostname + 一个<=32KB UTF-8 Java文件内、scanner坐标 corroborated 的唯一整行inline true lambda。复用原source_proof/preservation_proof和原grant，不扩规则、不新增scanner/policy。更窄REMOVE-only排除多安装、注释混行、多行lambda、非JDK receiver、类型遮蔽/重赋值/global TLS。Runtime只读取/规划/授权/核查，不写目标源码。Host执行编辑。

用户Episode7 44281.864ms及跨Host30.479803s作为真实Desktop前提，但具体model/transport/queue子项UNKNOWN，不改写旧BD报告。当前Native Codex fast apply未找到、未伪造；这里成功的是可信embedding+disposable Windows Host fixture。标准MCP server没有fixture_host_edit，没有fast config/env opt-in，新constructor DI不是官方Host API，不能由远程claims变为trusted。

### BE.2 Plan与执行契约

| 字段 | 语义 |
| --- | --- |
| schema_version / fix_path | hostname-remove-v1 / DETERMINISTIC_FAST_FIX |
| workspace_id / episode_id / grant_id | 当前workspace、Episode、原grant绑定 |
| task_ref / remediation_ref / plan_ref | 原opaque values及新连接内plan reference，不重建 |
| origin_scan_id / finding_id / rule_id | 当前scanner原始对象，allowlist只有trust-all-hostname |
| target_path | 唯一受控relative Java path |
| expected_snapshot_digest | 原授权Hook snapshot |
| expected_file_sha256 / expected_segment_sha256 / expected_result_sha256 | 原字节、精确删除段、仅REMOVE后全文件身份 |
| byte_range | UTF8_BYTES_END_EXCLUSIVE，zero-based start/end |
| operation / replacement | DETERMINISTIC_REMOVE / 空字串；无任意replacement |
| expires_in_seconds / host_edit_contract | 900 / ATOMIC_BOUND_EDIT_V1，Runtime以connection monotonic deadline执行 |
| result_contract | PostToolUse真实Scanner proof、CLOSED/RETURN_TO_HOST，production correctness UNKNOWN，Deep false |

Runtime source_proof/preservation_proof沿原实现；plan只元数据/Hash，不含target源码或模型prompt。连接内<=32/8KB plan，source<=32KB；严格canonical JSON对比拒绝类型改写及字段篡改，opaque字串保持原值。validate_and_claim不是远程MCP工具，必须由trusted Host bridge在目标写/rename排他内调用，然后Host自己CAS与commit。bridge不可用不发plan、不跳prepare；任何不满足条件都未授权Fast edit。当前Host fixture中WINDOWS_KERNEL_DENY_WRITE_DELETE是真实句柄能力，但不是已经接入Codex的能力。只有测试工具执行Host写；产品模块没有source writer。

校验当前root/Episode/original remediation token、policy mode/revision、member/rule/file、monotonic expiry、snapshot、expected bytes、preservation，无放宽receipt。Fast claim仅建立原prepared连接内attestation，attempt=原1（或原retry）；成功prepare Agent fallback会放弃unused Fast plan，不重置计时/budget。recurrence新Episode/newgrant/newplan，旧plan/旧authorization不能复用；restart/reconnect未知Fast ref不恢复。

新增固定reason codes：FAST_FIX_UNSUPPORTED_RULE、FAST_FIX_POLICY_NOT_ELIGIBLE、FAST_FIX_AMBIGUOUS_TARGET、FAST_FIX_FINDING_IDENTITY_MISMATCH、FAST_FIX_WORKSPACE_MISMATCH、FAST_FIX_EPISODE_MISMATCH、FAST_FIX_REMEDIATION_MISMATCH、FAST_FIX_AUTHORIZATION_UNKNOWN_OR_RECONNECTED、FAST_FIX_AUTHORIZATION_EXPIRED_OR_CONSUMED、FAST_FIX_AUTHORIZATION_INVALID、FAST_FIX_HOST_CAPABILITY_UNAVAILABLE、FAST_FIX_PLAN_INVALID、FAST_FIX_PLAN_TAMPERED、FAST_FIX_PLAN_BUDGET_EXCEEDED、FAST_FIX_STALE_SNAPSHOT、FAST_FIX_EXPECTED_BYTES_MISMATCH、FAST_FIX_CONCURRENT_MODIFICATION、FAST_FIX_PREPARATION_BUDGET_EXCEEDED、FAST_FIX_POST_EDIT_NOT_EXACT。读/编码异常fail closed，固定消息不反射claims/source。STALE之后REFRESH_HOOK_OR_AGENT_FIX；不能强套patch或降低旧prepare snapshot校验。

### BE.3 Scanner proof与timing

精确删除仍要求原source/preservation、当前post-edit snapshot及原TaskFixService/VerificationService真实执行，confirmed原rule、file、catalog/version/checksum/engine/coverage完整。plan/Host applied不能CLOSED。post-edit scan与original-rule security recheck均保留。只因编辑确定不能跳过ledger；Hook delta projection没有当前canonical verification所需全部live plan/provider ledger，不能直接复用它或旧DB result。本轮没有更换/新增Scanner或取消Secret扫描。未来合并需single-use live proof进入canonical verifier、失效隔离和额外协议验证，不在本轮冒险走absence-only旁路。

新增fix_path、fast_fix eligibility/fallback/plan_ready/host_fast_edit_observed/scanner_verification和P0-3 fast点。Fast真实Host窗放host_fast_apply_window，不存在prepare_task_fix/continuation_to_prepare/旧host_fix_window为null；不是0或完全删除Host等待。分区仍互不重叠，scanner/policy/auth为嵌套非additive，unknownHost CPU/网络sent等全null，restart/reconnect不重建wall。Agent fallback分区按真实prepare返回旧形态，budget和cycle不中断。explicit verify入口仍保留real scanner门禁（SDK未额外调用重复verify），完结timing冻结，不改变receipt身份。

### BE.4 实际本地MCP/managed Scanner与性能

final PASS/93.04s，ACTUAL_LOCAL_MCP_STDIO/ACTUAL_MANAGED_OFFLINE，Host是SIMULATED_WINDOWS_NATIVE_EDIT_FIXTURE，不是Desktop。两个server使用同一managed环境，先真实baseline暖cache，再计risk→close；已有cooldown在两条fixture路径均设0，未注入sleep或假model时间。风险编辑与应用只在disposable project，standard runtime source_modified=false；Host工具如实source_modified=true。

| Path | Runtime MCP calls | Host fixture edit calls | prepare calls | cycle wall ms | Scanner invocations |
| --- | ---: | ---: | ---: | ---: | --- |
| AGENT_FIX / 1 | 3 | 1 | 1 | 18546.754 | 2 Hook SAST + 2 Secret + 1 original-rule recheck |
| DETERMINISTIC_FAST_FIX / 1 | 2 | 1 | 0 | 16805.614 | 2 Hook SAST + 2 Secret + 1 original-rule recheck |
| DETERMINISTIC_FAST_FIX / 2 | 2 | 1 | 0 | 16813.190 | 2 Hook SAST + 2 Secret + 1 original-rule recheck |
| AGENT_FIX / 3 | 3 | 1 | 1 | 17874.430 | 2 Hook SAST + 2 Secret + 1 original-rule recheck |

Runtime MCP counts只计risk/PostToolUse与prepare；另1次fixture Host native编辑操作单列（同一测试stdio传输，生产server没有该工具）。所以总fixture transport Agent4、Fast3，不把test Host编辑RPC隐藏成0。scanners计真实进程invocations，不含baseline version probes；两条路同为3 SAST/2 Secret，不声称削减Scanner数量。两Fast cycles真实resolved/CLOSED/RETURN_TO_HOST；第二Episode recurrence、旧plan被拒绝；第三Episode篡改plan拒绝后原prepare fallback正常完成。原ref逐字传递，artifact不保存任何raw refs/source/secret。

final Fast1：initial6335.903/Host混合577.047/post-edit5269.274/original recheck4376.197/finalize247.193ms；Fast2：6238.865/539.332/5340.963/4427.416/266.614ms。不存在prepare为null，Host窗口仍真实可见。有限样本不能把cycle差归因全部Fast本身：首轮Agent16676.449/Fast16775.460ms不更快，final一轮Agent18546.754/Fast16805.614ms，且有Scanner波动。可靠收益仅少一次prepare Runtime往返与无需重新推导删除操作；真实Desktop仍有未知LLM/queue/transport延迟，当前Codex未启用Fast，不声称消除了用户约30秒窗口。没有足够证据扩第二规则，优先真实Host bridge。

[final core](fast-fix-core.json)、[initial core](fast-fix-core-initial.json)、[final package](fast-fix-package.json)、[initial package](fast-fix-package-initial.json)、[final regression](fast-fix-regression.json)。

### BE.5 测试、打包与前序保留

test_fast_fix.py 18functions/44cases：成功精确REMOVE/不调用prepare/两scanner阶段/receipt闭环；workspace/Episode/remediation/rule/ref/path/range/operation/replacement/expiry/file hash/result contract type tamper；target/其他tracked/ignored变化；claim后Host CAS拒绝；多匹配/多行/注释/混行不eligible；deadline/mode/replay；recurrence旧plan、restart/unknown wall；Agent fallback；非精确修改不得Hook或explicit verify绕过；失败Scanner及原rule/file/confirmation/catalog checksum/engine缺失不close；UTF8/CRLF原字节保留；无源码/bearer持久化。旧tests一字未改。

| Gate | Result |
| --- | --- |
| 初轮focused | FAIL：44passed/59errors，176.84s；新增测试repo fixture接线及Hook字符串缺连接符；已修正，不计PASS |
| 单独fixture诊断 | FAIL：1error/0.49s；缺repo注册；不计PASS |
| fast v2 | FAIL：3errors/9.84s，字符串连接缺陷；已修正 |
| fast v3 | 31passed/1failed，102.75s；测试错把保留CRLF要求成LF，改成原bytes删除段等式，不改变产品换行 |
| 旧focused/full门禁 | INTERRUPTED_FOR_STRICT_JSON_FIX：396.95/394.86s、return130；仅精确识别自有test后代停止，不动活动Runtime，不计PASS |
| final focused v2 | PASS：392 passed in 1003.12s (0:16:43)；wrapper 1004.17s |
| final full offline v2 | PASS：1219 passed, 9 skipped, 6 subtests passed in 1450.17s (0:24:10)；wrapper 1451.03s；9 skipped不计PASS |
| final MCP+managed Scanner+Fast/fallback/recurrence | PASS/93.04s，no sleep/model/network/Deep/target build |
| 首次sdist integrity | FAIL：缺fast_fix_acceptance.py；仅追加一行MANIFEST，旧行完整保留；重建通过 |
| final wheel/sdist/integrity/compliance | PASS/5.82s，106Runtime文件bytes一致；dist/fast-fix-final；无安装 |
| actual Desktop / clean install / standalone / CI | NOT_RUN_USER_REQUEST / NOT_RUN_THIS_SCOPE / NOT_REBUILT / NOT_TRIGGERED_NO_PUSH |

final wheel 85576795657bba49bd1380bc1471097630e8f57cb7ed80f1de976f14b712accc、sdist 7e3c96ab2709d8306e5d6d8703ea1436cbc593909b0cbe92c820595250b0a52a；初轮包另保留dist/fast-fix与initial JSON，不替代final。最终Python155文件冻结核对和原P0-3 224文件范围审计；_reference/_close/_new_episode/_validate_episode/_receipt_scope/_resolved_scan_hash/functional_receipt_diagnostics/_allowed/_guard/_grant AST保持，official Hook config/output AST不变。新增fast_fix.py/test_fast_fix.py/fast_fix_acceptance.py，修改remediation.py/codex_mcp_hook.py/hook_timing.py/mcp_server.py和MANIFEST一行、五文档；其他前序source/tests/scripts/config/Functional/BOM/scanner/cache/CET全部保留。ignored SOURCES.txt为build metadata，非产品修改。外部PROJECT_CONTEXT未读写，无reset/restore/clean。

完整回归skipped（6个PATH scanner前提、3个opt-in performance，真实managed Scanner验收另见BE.4）：

- SKIPPED [1] tests\performance\test_managed_cache_lifetime.py:14: Explicit managed real Scanner benchmark environment required
- SKIPPED [1] tests\performance\test_managed_cache_lifetime.py:38: Explicit managed real Scanner benchmark environment required
- SKIPPED [1] tests\performance\test_managed_hot_path.py:10: Explicit managed real Scanner benchmark environment required
- SKIPPED [1] tests\test_e2e_real.py:58: real scanner binaries required
- SKIPPED [1] tests\test_e2e_real.py:80: real scanner binaries required
- SKIPPED [1] tests\test_e2e_real.py:120: real scanner binaries required
- SKIPPED [1] tests\test_e2e_real.py:154: real scanner binaries required
- SKIPPED [1] tests\test_e2e_real.py:68: real scanner binaries required
- SKIPPED [1] tests\test_e2e_real.py:38: real scanner binaries required

### BE.6 下一次Desktop与停止边界

本轮不自行Desktop试用，不替换活动Runtime。后续明确加载源码后，standard Codex仍应报告AGENT_FIX/FAST_FIX_HOST_CAPABILITY_UNAVAILABLE→原prepare→Host最小修复→real Scanner/CLOSED/RETURN_TO_HOST；不要期待未存在的native自动apply。真正Fast Desktop需先获得supported/trusted Host bridge，能在目标排他/CAS内校验当前authority，不能通过Runtime写文件或模型声称capability绕过。届时再核对plan原ref、prepare调用0、未知Host窗真实显示、原rule proof、recurrence新plan/旧plan拒绝、无Deep；当前保留PENDING_HOST_ATOMIC_EDIT_BRIDGE。

门禁/记录完成，停止，无commit/push/install/系统更新/用户项目编辑/Secret rotation/目标构建/新阶段；只disposable Host fixture编辑和既有回归。三位试用Pending、GroundTruth UNREVIEWED/null、Maven PENDING_ENVIRONMENT_PREREQUISITES、p95p99 NOT_MEASURED不补PASS。

## BD. Core P0-3: AUTO_FIX Continuation Latency Observability

### BD.1 起点、误操作证据与逐文件处理

feature/runtime-mvp/ee1bfd9c12493683cc313cb3628753a51ae124ac未提交工作继续；用户Desktop风险Hook约3670/scanner2840/recheck2880/cycle36170ms，USER_REPORTED_ACTUAL_DESKTOP_TIMING。没有该cycle内部点，不能推断剩余均为Host模型耗时。P0-2.1 wheel SHA a1d59fc3f497142660d04b5d0cb6637197104767fe30a6a447603c2ccbd48b6c、sdist b22cd832c2c7128cebf24ec4d2466854b0b29b0a19deb264ebb481bc342db61e验证后只读提取.security-runtime/p03-review/p021-baseline；进入时231个source/tests/scripts/必要文档与哈希保存incoming。未reset/checkout/restore/clean，六文件incoming相对真实P0-2.1 diff保存，不能以HEAD总diff删除前序工作。原新增diff行数175/60/134/10/79/29。

| 六文件 | 保留的P0-3意图 | 局部修正 |
| --- | --- | --- |
| hook_timing.py | 原bounded cycle内增加point/breakdown/边界 | 删除重复常量、跨scope wildcard、弱instance/结束mark；严格有限单调时钟、freeze、重叠拒绝、detail非加总、重试residual |
| codex_mcp_hook.py | 真实Hook入口/scan结束点及MCP新增输出 | 不预先猜fix对象；response ready代替sent；输出当前points，官方config/feedback不变 |
| remediation.py | on_hook/prepare/recheck/verify测量入口 | 移除shared pending与singleton/prepared兜底，prepare仅READY归属当前episode；还原_close原体、在实际持久提交后观察关闭；观测fail-soft |
| host_continuation.py | 原Stop fallback中的一次观察 | 当前已验证root/hash+STOP_GUARD source、观测异常隔离，不改guard/预算/authority |
| test_continuation_timing.py | 原4项复现/分解/未知/重启意图 | 修正错误Host标签与相加断言，扩展至21cases |
| remediation_episode_acceptance.py | episode验收输出cycle与分解 | ready命名、未知Host/sent断言、浮点误差容限；原流程与refs不改 |

额外扩展已有core_hot_path_acceptance SDK脚本记录新字段、验分区/未知/重复verify冻结、第二Episode现有Stop fallback；不引入新工具/Scanner或Deep。除四个上述产品模块，前序全部其他产品源码与P0-2.1 bytes相同；11函数_reference/_close/_new_episode/_validate_episode/_receipt_scope/_resolved_scan_hash/functional_receipt_diagnostics/_allowed/_guard/_grant/_prepare AST相同；official Hook config/output AST相同。审计.security-runtime/p03-scope-audit.json PASS；原外部PROJECT_CONTEXT未读取/修改。错误Chat有不符合架构的观测关联和归因，但未发现其改变receipt/opaque ref授权、引入Deep或新安全执行路径。

### BD.2 协议与计时边界

兼容原remediation_cycle_wall_ms/measurement与timing_ms六字段，增加remediation_cycle_timepoints_ms、breakdown_ms、detail_ms、boundary、breakdown_measurement。point是相对当前风险入口的ms，不持久化绝对时间/Host claims/refs/source/Secret。<=32连接内Entry，绑定canonical workspace/Episode/runtime_instance；new episode新start；validated retry不重启；end冻结；restart/reconnect/evict/clock无效UNKNOWN/null。timing wrapper异常不否定原SCANNER_VERIFIED_RESOLVED/CLOSED；必要安全动作错误仍原fail closed。

| breakdown字段 | 可信观测边界与限制 |
| --- | --- |
| initial_runtime | risk Hook入口→adapter advisory数据就绪（新增additionalContext编码前），含scanner/policy/adapter；不是network sent |
| runtime_to_host_continuation_wait | response ready→首次有效Stop或成功prepare请求入口，混合Host/transport/queue；子项UNKNOWN |
| continuation_to_prepare | Stop观察→prepare入口；direct prepare两个点相同，真实0 |
| prepare_fix | 原工具函数入口→READY准备完成，Runtime处理，不含MCP传输 |
| host_fix_window | prepare完成→相关fix Hook入口，Host-Agent/transport混合窗，不是编辑CPU |
| post_edit_hook | fix Hook入口→原风险独立recheck开始，包含post-edit增量Scanner/guard/policy |
| security_rescan | 原TaskFix verify调用边界，真实Scanner proof、未删复扫 |
| close/finalization | recheck完成→proof检查/DB持久CLOSED/返回决策；多retry不能这样归因，改null/residual |
| unaccounted | wall减去已知互不重叠端点分区的残余，不猜CPU/模型/业务活动 |

initial_scanner、initial_finding_policy、auto_fix_authorization（原grant准备+持久到可返回的真实窗口）、post_edit_scanner为嵌套detail，不能再次加到breakdown。timepoints包括risk/scanner/policy/auth/response-ready/continuation/prepare/fix-Hook/snapshot观察/recheck/closed/return；actualHost收到、源码edit start/end、response sent全null。host_edit_observed只是Runtime已检查到相关post-edit snapshot，不是磁盘写入时刻。overlap/reverse使breakdown UNKNOWN，不能max(0)隐藏重复计时；正常分区有0.01ms rounding容限。缺点不补造，已知wall仍可保留安全事实独立。

### BD.3 测试与门禁

test_continuation_timing 16functions/21cases，误操作原4意图保留、补充17：workspace/连接与进程变化、完成冻结、bool/NaN/Inf/未来/负值/回退时钟、overlap不伪分区、detail非加总、retry同episode不重启/旧token不再标记、非法task ref prepare不写point、观测异常仍scanner resolved、Stop与prepare点分开、manual verify不猜edit、原opaque ref/persistent状态不变。原缓存/Scanner失效、Family/Episode/receipt/预算/确认/Core no Deep/command Hook兼容focused/full回归，不削弱原断言。

| Gate | Result |
| --- | --- |
| P0-2.1历史full | 1154passed/9skipped/6subtests，1558.46s |
| 首轮focused | 98passed/180.43s（wrapper180.94）；后补四项前，不替代final |
| SDK初轮启动 | FAIL：新增断言缩进错误，修正脚本后再跑；不算Runtime PASS |
| 首轮实际MCP simulated Host | PASS/56.69s；detail rounding及第二Episode Stop分支补充前；[initial](continuation-latency-core-initial.json)，不替代final |
| final focused v1 | FAIL：345passed/3failed，769.79s（wrapper770.40）；新的CROSS_BOUNDARY_WAIT标签撞上既有AUTO_FIX禁用WAIT控制词断言；旧断言未修改，已修正两个诊断标签 |
| full v1 | INTERRUPTED_CONFIRMED_FAILURE：约72%后已有同三项F，returncode130/1036.76s；只中止唯一匹配的本轮自有测试后代，不触及活动Runtime或文件；不计PASS |
| final focused v2 | PASS：348passed/782.04s；.security-runtime/episode-p03-final-focused-v2.log/.json，旧断言未改 |
| final full offline v2 | PASS：1175passed/9skipped/6subtests passed，1206.43s（wrapper1207.08），returncode0；.security-runtime/episode-p03-final-full-v2.log/.json |
| final本地MCP simulated Host | PASS/65.10s；两个Episode均SCANNER_VERIFIED_RESOLVED/CLOSED/RETURN_TO_HOST；direct prepare与现有Stop fallback分支；[final](continuation-latency-core.json) |
| wheel/sdist/package integrity/compliance | final PASS/4.57s，105Runtime文件bytes一致、LICENSE/NOTICE/合规内容核对；[final package](continuation-latency-package.json)；初轮4.48s另存initial |
| actualDesktop/cleaninstall/standalone/CI | PENDING_P03_HOST_TIMELINE / NOT_RUN_THIS_SCOPE / NOT_REBUILT / NOT_TRIGGERED_NO_PUSH |

final wheel 007d295dacb3622274f790d7c65b1381996a6a50301b049dde0ab66f170ffb7b、sdist 1fb4a891ef07507796c7cdb1f131c8c05bbb238f956484398815aeb8406bb76a，dist/continuation-latency-final独立目录，未安装或替换活动Runtime。224 source/test/script最终冻结核对PASS；scope audit与git diff --check PASS。9 skipped实际单列：tests/test_e2e_real.py:38/58/68/80/120/154六项要求PATH真实binaries；tests/performance/test_managed_cache_lifetime.py:14/38两项与test_managed_hot_path.py:10一项要求显式managed performance环境，当前full未设置。P0-2.1显式性能PASS仅历史，本轮未重跑这三项；本轮真实managed Scanner由final MCP SDK实际运行，不把skip算PASS。

### BD.4 本地MCP latency与rule-plan诊断

最终串行本地MCP PASS/65.10s，真实Runtime+已有managed Scanner，driver模拟Host编辑、无模型。第一Episode direct prepare，第二Episode走现有Stop fallback；两Episode为同family recurrence的新生命周期。SDK两次独立driver墙钟14355.451/15371.788ms，与Runtime周期相差约2.44/2.42ms（driver与Runtime端点不同）。全部单位ms：

| 不重叠分区 | Episode 1 / PREPARE_REQUEST | Episode 2 / STOP_GUARD |
| --- | ---: | ---: |
| initial_runtime | 4403.185 | 4411.985 |
| runtime_to_host_continuation_wait | 69.298 | 977.325 |
| continuation_to_prepare | 0.000 | 75.316 |
| prepare_fix | 904.655 | 903.459 |
| host_fix_window | 1107.790 | 1104.029 |
| post_edit_hook | 4126.822 | 4155.059 |
| security_rescan | 3557.769 | 3550.940 |
| close/finalization | 183.495 | 191.252 |
| unaccounted | 0.000 | 0.002 |
| remediation_cycle_wall_ms | 14353.014 | 15369.367 |

嵌套detail：initial_scanner 3402.975/3414.382、initial_finding_policy 505.308/516.286、AUTO授权6.369/5.428、post_edit_scanner3446.193/3439.059ms；不得加到上述分区。安全编辑有真实Scanner，危险Hook和post-edit增量均单Java target/21规则，原风险独立security recheck单target/1原规则；没有删除任一次必要复核，P0-3未修改Scanner执行/缓存。已有1.1s cooldown等待包含在模拟host_fix_window，不当优化benchmark。Host received、response sent、真实edit start/end始终null；0.002ms residual为显示舍入量，不声称所有内部CPU已归因。两新Episode原refs逐字传递、旧refs拒绝，最终scanner resolved/CLOSED/RETURN_TO_HOST；explicit verify仍新Scanner且旧cycle/points/分区冻结；默认functional 0、build/test/sandbox false。不能用driver cycle对比Desktop36170ms宣称提升，Desktop必须采新端点才可归因。

rule-plan保守key为workspace/pack位置+checksum/文件集合/目标bytesSHA。普通safe comment、危险编辑或修复都会改变byte signature，因此MISS正确；同内容同scope可HIT，缓存的是计划而非Scanner proof。首次冷plan 99.123ms（pack MISS）；其后changed bytes的MISS 10.416–10.989ms（pack HIT）；同bytes/scope HIT 10.595–12.295ms，原规则recheck计划9.696/11.404ms。原rule复扫从21→1也改变首次规划/selected config，但不是跨进程丢staticcache。真实量级约10ms，不能解释约36秒cycle；本轮未修改Scanner/缓存键，也未为HIT比例降低proof。

证据：[final core](continuation-latency-core.json)、[initial core](continuation-latency-core-initial.json)、[final package](continuation-latency-package.json)、[initial package](continuation-latency-package-initial.json)。final serial采用冻结的V2源码，所有四份新JSON无raw refs/source/Secret/model prompt。

### BD.5 Deterministic Fast Fix Path分析与停止边界

只分析、不实现。现有source_proof/preservation_proof有单inlineJDK hostname verifier/32KB/类型与唯一receiver/位置校对/注释字符串mask/no alternate/globalTLS mutation/完整scope guard，能作为狭窄确定性diff候选。未来若Host能应用精确expected-bytes patch，可减少自由模型编辑窗口，但必须遵循已有AUTO授权、opaque refs/current workspace/episode/snapshot、单文件范围、并发修改拒绝、原preservation/source guard与freshScanner。自定义对象/多安装/歧义/能力缺失回原Host路径；不把scanner安全消除当业务或生产正确。当前Runtime不写目标源码，FastFix API/patch writer/Host执行协议全未实现；没有依据量化省多少秒，也不能在本轮新增命令/build/sandbox。

下一次明确加载本轮源码后的fresh Desktop，一次性Git Java项目/同Chat：普通安全编辑→TLS风险AUTO→原refs prepare→Host最小修复→完整post-edit与原rule复扫→closed；保存breakdown/detail/boundary，不持久化rawref/source/secret。检查长cycle主要落哪个跨边界窗，model/transport子项仍unknown；第二Episode独立；重连unknown、旧ref拒绝、无Deep。仅新字段支持本轮代码身份辨别，版本0.3.1未升，不替换活动Runtime。本轮门禁/记录完成并停止，不commit/push/部署/新阶段；无联网/依赖安装/模型调用/用户目标编辑或构建/Secret rotation，仅disposablefixture与既有回归。三位试用Pending、GroundTruth UNREVIEWED/null、p95p99 NOT_MEASURED、Maven PENDING_ENVIRONMENT_PREREQUISITES保持。

initial_hook_response_ready具体为adapter advisory数据已就绪、尚未将新增additionalContext编码或发送；后续编码、MCP传输、队列和Host工作只能落在混合窗口，不据此单独归因。RETURN_TO_HOST端点表示Runtime返回决策，不能声称Host已经收到。

## BC. Core P0-2.1: Cache Lifetime & Scanner Invocation Reduction

### BC.1 Desktop事实、复现与边界

起点feature/runtime-mvp/ee1bfd9c12493683cc313cb3628753a51ae124ac，前序dirty全部保留。用户实机 USER_REPORTED_ACTUAL_DESKTOP_TIMING：连续安全编辑第二次hook3554/scanner2961ms、Semgrep/Gitleaks版本及config/pack HIT；随后风险scanner5325ms全部MISS、Semgrep invocation2519ms、Gitleaks扫描调用5、recheck3139ms、resolved Hook7013ms。没有历史进程identity/原targetlist，不能证明唯一的Desktop重启或对象重建原因，也不猜五个文件名。

源码明确原ToolManager/RulePackManager/adapter caches属于对象，MCP server工厂、HookCoordinator或registry重建会丢失；本轮保存的源码快照.security-runtime/cache-lifetime-baseline（213文件）实际复现同进程registry重建后版本/pack/config全部MISS。原Gitleaks _scan_targets对每target一次dir，process_invocations不含--version；五文件fixture实际5次SECRET_SCAN+1次Semgrep，不是对一个文件重复5次。不缩dirty/retained Family收敛范围，而是batch全部有效target。

### BC.2 实现及安全合同

新增scanner_cache process owner：runtime_instance_id随机32hex，不是ref/credential、不输出PID或主机信息；cache_generation初始1，当前进程内factory重建不变，新进程新identity/空cache；scope PROCESS_LOCAL_CONTENT_VALIDATED。最大64namespace，保留BB version/pack/plan/config数量与资源边界。process buckets共享锁，版本函数本地持有自己的engine bucket，不使用会被另一engine改写的实例属性读写。首轮新实现实际复扫MISS暴露此竞态，已修正并加入双engine并行→单engine复核测试，初始after保留[cache-lifetime-after-initial.json](cache-lifetime-after-initial.json)，未当最终PASS。

workspace/源bytes/规则catalog/LICENSE/NOTICE/config/helper/expectedversion/env变化仍按BB每次验证；workspace也加入共享pack/config key，重启清空。只cache准备信息，不cache扫描结果/confirmed/scanned/errors，failure/incomplete不能污染新proof。_close/_reference/_new_episode/receipt diagnostics、verification.py、policy、Deep/BOM/CET、官方Hook定义与setuprepair保持不变。

Gitleaks单文件仍一次dir；多文件去重/边界验证后在项目外temporary mirror保留相对目录，唯一dir读取完整scope并映射回原路径。原始用户源码不改；源码副本仅临时且成功/失败都清理，不进入持久状态/日志/验收JSON。--redact=100、原timeout/报告output预算保持，报告缺失/失败/超限不得成功。invocations为VERSION_PROBE/SECRET_SCAN/SAST_SCAN类型+target_count；invocation_count只计scan，version另计；列表64条有truncated且总数准确。rule/file scope仍可见，不增加repository scan。

remediation_cycle_wall_ms = 第一次风险Hook adapter入口至原scanner proof已提交CLOSED并决定RETURN_TO_HOST的perf_counter端点差，包含首次Hook、prepare、Host continuation/等待/编辑、下一Hook/安全复扫，不累加分项。端点在Runtime内，不声称Host接收延迟或编辑CPU。最多32个连接内(workspace,episode)观测；首次grant成功才记录起点，retry不重置，第一完成冻结，显式重复verify仍新Scanner但不延长旧cycle，recurrence新起点。无起点/重连/重启/不连续clock为UNKNOWN/null，不能由DB时间或旧阶段重建。既有timing_ms六字段不变，metadata不参与安全策略/授权，不持久化times/refs/source/Secret。

### BC.3 测试与门禁

新增17项test_cache_lifetime合同测试：3请求MISS/HIT/HIT、重建manager/registry保留、workspace隔离/新proof、真实Python重启新identity冷MISS、MCP工厂identity、两engine并发bucket、单文件去重、完整batch/坐标/脱敏/清理/源码不变、failure/missingreport→下一次fresh、越界拒绝、cycle端点/冻结/新episode/未知/进程identity/预算/元数据截断、真实Core AUTO及reconnect保留安全事实。旧BB rule/source/version/env/cache失败失效测试保留；旧2项把new object等同restart的期望改成retains，真正进程重启独立覆盖。新增tests/performance/test_managed_cache_lifetime.py 2项真实managed：连续3编辑+重建+5文件+原rulefresh recheck；真实Gitleaks逐文件与batch对照（两个syntheticSecret，完整坐标一致、脱敏、无原文件变化、unrelated文件未进入scope）。无假Scanner性能数据、无sleep基准。

| Gate | Result |
| --- | --- |
| BB baseline历史 | 1137passed/7skipped/6subtests，1087.19s |
| 初轮focused | 46passed/1failed，59.10s；新增测试误用不存在evidence_snippet属性，改为现有evidence；未放宽实现断言 |
| contract v2 | 185passed，76.06s；并发补充前，不代替final |
| 修正后真实managed早期 | 2passed，44.96s；最后metadata计数补充前，不代替final |
| final focused | PASS：485passed，774.14s（wrapper775.23s）；.security-runtime/episode-cache-final-focused.log/.json |
| final full offline | PASS：1154passed /9skipped /6subtests passed，1558.46s（wrapper1559.57s）；.security-runtime/episode-cache-final-full.log/.json |
| final managed benchmark/tests | PASS：新2passed/43.89s（wrapper44.63s），.security-runtime/episode-cache-real-final.log/.json；既有managed test1passed/13.89s（wrapper14.28s），episode-cache-managed-compat；最终串行before/after原始JSON见BC.4 |
| 本地MCP Core E2E | PASS：56.68s，3 safe edits/2 episodes；两cycle OBSERVED/frozen，functionalcalls0；driver非Desktop模型 |
| wheel/sdist/package/compliance | PASS，6.46s，105 Runtime文件bytes一致；[cache-lifetime-package.json](cache-lifetime-package.json) |
| Desktop/cleaninstall/standalone/CI | PENDING_ACTUAL_DESKTOP / NOT_RUN_THIS_SCOPE / NOT_REBUILT / NOT_TRIGGERED_NO_PUSH |

full九项skip单列且不计PASS：tests/test_e2e_real.py:38/58/68/80/120/154均real scanner binaries required（本套PATH前提不满足）；tests/performance/test_managed_hot_path.py:10与test_managed_cache_lifetime.py:14/38均显式managed性能环境门槛，已独立全部3项实际运行PASS，与full skip分开。最终full之后产品/测试/公开脚本不再修改；补充的ignored runner只用于显式门禁与文档。

包dist/cache-lifetime，wheel a1d59fc3f497142660d04b5d0cb6637197104767fe30a6a447603c2ccbd48b6c，sdist b22cd832c2c7128cebf24ec4d2466854b0b29b0a19deb264ebb481bc342db61e。source审计.security-runtime/cache-scope-audit.json PASS。改9产品模块、新scanner_cache；改旧scanner_hot_path两个生命周期期望、新2测试文件（19项）、扩展core_hot_path_acceptance、新cache_lifetime_benchmark、MANIFEST补脚本、更新五现有文档。产品/测试已冻结，后续仅文档/证据。命令Hook保留，Deep没有接入Core。

### BC.4 真实before/after与cycle

串行对照在full结束后进行，固定已有managed Semgrep1.178.0/Gitleaks8.30.0与同协议一次性Git fixture，不安装/下载；before使用保存的修改前源码，不reset工作区。每列是实际单次wall，不是p95/中位数/速度承诺。保留初始before与并发bucket Bug的初始after：[cache-lifetime-before-initial.json](cache-lifetime-before-initial.json)、[cache-lifetime-after-initial.json](cache-lifetime-after-initial.json)，不以坏实现数据当验收成功。最终原始：[cache-lifetime-before.json](cache-lifetime-before.json)、[cache-lifetime-after.json](cache-lifetime-after.json)。

| 真实managed Scanner wall | before ms | after ms |
| --- | ---: | ---: |
| cold safe | 7835.689 | 8115.247 |
| warm safe 2 | 4617.868 | 4528.311 |
| warm safe 3 | 4457.043 | 4425.323 |
| 同进程重建manager/registry后safe | 7592.651 | 4220.139 |
| 5目标safe | 4536.041 | 4314.213 |
| 5目标risk | 4603.556 | 4216.019 |
| 原rule/file fresh security recheck | 3978.953 | 3793.712 |

cold没有变快、正常热路径改善小，不能宣传普遍大幅提速。最明确收益为registry重建保留HIT（约44%减少wall）及Gitleaks批次。cold version/pack/config MISS，随后warm/rebuilt静态HIT；rule_plan在文件bytes变化时MISS正确，不跳过scanner。Java SAST实际21适用rules/1文件（不是全catalog22），5target仅Gitleaks完整scope；recheck1原rule/1原文件、真实新invocation，未复用结果。before五目标对应notes/one.txt、notes/two.txt、README.md、settings.properties、Java文件各一次SECRET_SCAN，after一次SECRET_SCAN/target_count5；这些是本轮fixture，用户Desktop那五个真实文件未知。version probe另计。单文件scan一次，不在同Hook重复扫描相同target。

Gitleaks五目标safe过程边界：before invocation总2578.249ms/scanner2645.778ms→after一次invocation502.758ms/scanner585.886ms；镜像准备6.169ms。5risk invocation2617.787→520.686ms、临时复制6.276ms。Semgrep并行主导，所以五目标总体wall只小幅下降，不能把Secret分项节省直接加到Hook收益。重建后的Semgrep content identity459.176ms、config12.633ms、invocation3549.863ms、Popen3.554ms、自报config465.875/core245.763/total792.662ms。复扫invocation3348.256ms/Popen3.738ms、自报total532.794ms，actual_scanner_execution=null。热路径排序：固定CLI invocation > retained内容身份校验 > 小量配置/target准备/解析；真正冷路径另有版本probe约2.8s，旧对象丢cache造成的重复冷路径已减少。CLI boundary与自报total区间不等，剩余初始化解释是推断，不是独立CPU测量。

最终串行Scanner bench的Semgrep invocation约3.35–3.88s；随后独立本地MCP run约2.44–2.90s，与用户Desktop旧2519ms分开记录，说明短样本仍有运行差异，不选择最小值作为承诺。足以说明固定CLI invocation值得后续设计评估，不足以证明persistent实现的收益、支持的reuse接口或隔离/失效模型；不进入新PoC。

本地stdio MCP原始：[cache-lifetime-core-after.json](cache-lifetime-core-after.json)，PASS/56.68s，实际Runtime+managed Scanner，Host编辑SIMULATED_BY_ACCEPTANCE_DRIVER；不持久化opaque refs。baseline冷MISS后同连接3次安全编辑static HIT，同runtime_instance_id/cache_generation1，安全facts未因cache改变。只调用handle_hook_event/prepare_task_fix/verify_task_fix，功能调用0、build/test/sandbox=false。既有1.1s cooldown等待会进入cycle，不是Scanner性能bench，也不是Desktop模型体验；before没有可信cycle，不从旧timing加和补造baseline。

| 本地MCP真实端点/阶段 | ms |
| --- | ---: |
| 冷baseline Hook/scanner | 6644.142 / 5996.754 |
| 安全edit 1 Hook/scanner | 4035.341 / 3418.919 |
| 安全edit 2 Hook/scanner | 3543.028 / 2916.997 |
| 安全edit 3 Hook/scanner | 3609.727 / 3015.996 |
| episode1风险Hook/scanner | 3836.817 / 2953.232 |
| episode1已resolved Hook/scanner/recheck | 6912.693 / 3065.012 / 3070.030 |
| episode1 cycle Runtime/driver | 12730.601 / 12732.456 |
| episode2风险Hook/scanner | 3860.358 / 2956.756 |
| episode2已resolved Hook/scanner/recheck | 6819.306 / 3001.200 / 3027.444 |
| episode2 cycle Runtime/driver | 12721.181 / 12723.556 |

两episode最终SCANNER_VERIFIED_RESOLVED/CLOSED/RETURN_TO_HOST；旧ref被拒绝，新原值逐字传递。risk开始IN_PROGRESS，resolved OBSERVED；显式重复verify实际重新Scanner但cycle12730.601/12721.181ms保持，不累加。六原timing窗口不能机械相加，也不能将driver cycle宣称自然模型耗时。新实现实际Desktop/真实项目p95p99与长期常开仍Pending。

### BC.5 下一次Desktop及停止边界

本轮不替换活动Runtime。将来加载本轮实现后，全新一次性Git Java项目/Chat，确认runtime_instance_id/cache_generation可见（0.3.1alone不足）。连续3次普通Java编辑：同identity/generation，cold MISS→HIT→HIT，rule_plan可因源码bytes变化MISS而static config/pack/version保持HIT，每次真实scan。然后同连接TLS fixture→AUTO_FIX原refs prepare→最小删除风险行→原Scanner证明resolved/CLOSED/RETURN_TO_HOST；记录cycle OBSERVED与双Scanner分项，不加Host窗口。record所有Gitleaks scope/scan count/type/target_count，5 dirty files预期1次SECRET_SCAN，不把version算scan。recurrence新episode新cycle，新ref原样；旧ref拒绝。重连/重启cycle UNKNOWN，实际重启instance变化/coldMISS是正确，不要求跨进程缓存。无Functional/build/test/sandbox调用。

未实施persistent Scanner/worker。低复杂度正确性与诊断门禁通过后才可据稳定热连接invocation占比评估下一轮设计；不能把当前粗测当worker收益或安全隔离已证明。既定门禁、串行性能与记录已完成，停止，不commit/push/替换活动Runtime，不进入新阶段。HEAD仍ee1bfd9c12493683cc313cb3628753a51ae124ac，工作区保留前序及本轮dirty，不声称clean；无新的CI/standalone/活动部署。六份新真实JSON为两个initial、final before/after、package、MCP。无联网/依赖下载/系统安装/模型调用/用户目标源码编辑或构建/Secret rotation；只编辑disposable fixture并执行既有回归测试。三位试用Pending、GroundTruth UNREVIEWED/null、quality/p95/p99 NOT_MEASURED、Maven环境PENDING_ENVIRONMENT_PREREQUISITES保持。


## BB. Core P0-2: Scanner Hot Path Performance

### BB.1 实机baseline与实际范围

起点feature/runtime-mvp/ee1bfd9c12493683cc313cb3628753a51ae124ac，BA及前序dirty实现全部保留。用户Desktop事实 USER_REPORTED_ACTUAL_DESKTOP_TIMING：安全hook5777.198/scanner5009.189/policy146.845ms；AUTO_FIX hook9890.613/scanner4268.245/recheck4900.597/preparation788.943/policy323.543ms。两次scanner9170ms。auto_remediation13045.887ms是Host模型/传输/等待/编辑窗口，不能加进Hook或当CPU。未获得用户这组scope的原始Scanner JSON，不能猜Desktop文件数；以下1文件数据仅本轮controlledfixture。

真实managed（显式选本机已有cache，不允许SYSTEM/EXPLICIT冒充MANAGED）Semgrep1.178.0/Gitleaks8.30.0，离线Git Java fixture目标src/main/java/demo/CodeModeTlsService.java。initial适用21条Java规则/1文件（catalog Java22，其中mapperXML规则不适用于这一个.java）；无repository target递归，无辅助source context。Semgrep实际time.rules=21、paths.scanned=1。baseline recheck也21规则/1文件；优化后original-rule recheck=1规则/1文件。正常Edit保留dirty/current+formerlydirty/candidate范围，可能包含上次dirty文件，保证revert/Family收敛；没有冒险实现只取最后编辑的旧proof cache。Runtime在hook_scope已给定时跳过重复Git.changed_files，path/link/size/profile校验保持。

### BB.2 成本拆解与诊断

修改前真实三样本medians：safe4672.122/risk4545.742/recheck4319.427ms。代表risk调用：Semgrep版本probe1741.148ms、scan invocation2430.743ms、规则验证68.624ms；Gitleaks probe265.436/invocation374.866ms，与Semgrep并行，不可全部相加。第一次safe6079.319ms，cold/暖连接须区分。根因排序：Semgrep重复版本探测是确定可消除成本；scan CLI边界固定成本为剩余主要项；规则解析约67ms/重复discovery为次级；parsing/DB是小项。未可靠区分CLI Python初始化与core执行，不能给伪造CPU数字。

scanner_diagnostics返回Runtime orchestration/workspace/target/ruleplanning/resultnormalization/statepersistence/total；provider给capability/identityvalidation/versionprobe、selectedconfig、processinvocation/Popencreation、parsing、scanner_total和cache/count。actual_scanner_execution=null，Semgrep自身profiling(config/core/total/rules_parse)仅engine_reported_*，不同计时边界不直接相减当精确启动时间。最终暖调用观测invocation2724.378ms/Popen2.419ms/engine_reportedtotal685.195ms/config350.046ms/core270.800ms；约2.0秒在engine自报区间外是初始化等开销的推断，不是独立测量。版本identity内容hash318.905ms，ruleplanning8.464ms，rule_config_preparation6.924ms（包含再次校验规则包与临时config写入）；statepersistence6.664ms。上述单次观察非延迟承诺。benchmark operations.version_probe包装的是整个版本解析函数，HIT时包含identity hash/cache lookup，不能当成启动--version；实际子进程计数以scanner_diagnostics.counts.version_probe_invocations为准。

scope字段含文件/规则数、language/profile、repository_discovery=false、context count、至多20条脱敏relative target（每条300字符，truncated可见）、scanner_results_reused=false。无source/secret/stdout/model prompt/原始refs进入performance证据。Base观测ContextVar隔离并发，已知边界perf_counter调用开销不含昂贵额外进程。persistence仅提交后live metadata；保存DB中该项及total是null，不为计时第二次改写signedscan identity。HookSnapshot持久格式不变，cachedHook不冒充新scanner duration。

### BB.3 优化与缓存安全模型

ToolManager每次resolve仍验证原managedmetadata/license/executablechecksum，成功且版本匹配才缓存probe；key包括canonicalpath/expectedversion/contentidentity/env/workspace，nativebytes、Semgrep package/helpers/core/distmetadata/Pythonruntime文件都会纳入。<=16，knownPython布局且<=2000files/512MB才cache；未知/超限正常probe。identity前后不稳定/failed/versionmismatch不cache，restart清空；相同engine锁single-flight，不影响实际扫描并发。配置/路径选择每次重新resolve，不缓存PATH命中对象。

RulePack<=8（每pack<=1000records/4MB YAML）只复用validatedmetadata，每次读取YAML/catalog/LICENSE/NOTICE内容fingerprint；ruleplan<=16绑定workspace/files/源bytesdigest/packchecksum，每次proof集合为空，目标<=1000/20MB才cache；selectedconfig<=16×1MB绑定packpath/checksum/IDs，只缓存规则文本，临时config仍每次独立创建/清理。source内容/文件集合/语言变化、rule/catalog/license变化、engine/helper/version/env/config/workspace变化按各自key失效；超预算绕过cache，不放宽原scanner限制。_scan再次读当前pack拒绝stale已准备plan。全部仅内存；不缓存findings、scanned/confirmed/error集合或旧proof。

HookCoordinator与Remediation复用连接内registry/ToolManager/adapter。VerificationService仍按当前workspace/originalfindingprovider/file/同episode现行授权与snapshot实际执行；一次verify_many按file/provider合并原rule union，catalogchecksum/原rule版本/engine兼容、confirmedrules/scannedfiles/errors/unscopederror和process_observed均保留。旧rule不存在/错配/失败/partial不能resolved。新episode旧refs拒绝、attempt预算/receipt binding不变；重复verify也会新进程，不把上次结果当新proof。基础规则与CET/BOM/Deep/default no Deep/API/config/setuprepair不改。

### BB.4 自动化、性能和package门禁

新增test_scanner_hot_path.py 25项：plan fresh证据、同文件字节变且恢复mtime仍MISS、workspace/语言隔离、YAML/catalog/LICENSE失效、invalid规则/staleplan、failed/incomplete后重扫、原rule/1file fresh recheck、缺rule拒绝、cache上限/restart、versionhit/miss/nativecontent/env/expectedversion/workspace/restart/失败或错版本/Pythonhelper变化、诊断无source。既有Core AUTO/recurrence/no Deep及receipt/预算/opaque refs/commandHook/setuprepair完整回归，不降低旧断言。另tests/performance/test_managed_hot_path.py显式选真实managed执行；无sleep、fakeprocess或伪造性能成功断言。默认full不主动启动此重benchmark，单列skip，独立已运行。

| 门禁 | 实际结果 |
| --- | --- |
| BA saved baseline（历史） | 1112passed/6skipped/6subtests，1132.03s |
| 初步兼容focused | 176passed，74.23s |
| 新cache+Core+episode | 66passed，180.10s |
| 真实managed performance test | 早期1passed/16.03s；最终冻结源码独立1passed/14.31s（wrapper14.66s），.security-runtime/episode-perf-managed-final.log |
| 早期final focused/full | INTERRUPTED：固定缓存资源上限及timing前重启，未完成不计通过 |
| 最终focused | PASS：406passed，545.71s（wrapper546.25s）；.security-runtime/episode-perf-final-focused-v2.log/.json |
| 最终full offline | PASS：1137passed /7skipped /6subtests passed，1087.19s（wrapper1087.77s）；.security-runtime/episode-perf-final-full-v2.log/.json |
| wheel/sdist/package/compliance | PASS，3.84s，104 Runtime文件bytes一致；修复sdist未包含新performance子目录/脚本后重跑，不把首轮失败写PASS |
| 本地MCP before/after Core E2E | 两者PASS（60.14s→46.34s）；2episodes/原refs/旧refs拒绝/freshscannerresolved/CLOSED/RETURN_TO_HOST，functionalcalls0/buildtestsandbox=false |
| fresh Desktop / cleaninstall / standalone / CI | PENDING_ACTUAL_DESKTOP / NOT_RUN_THIS_SCOPE / NOT_REBUILT / NOT_TRIGGERED_NO_PUSH |

包证据[scanner-perf-package.json](scanner-perf-package.json)，dist/scanner-performance；source scope审计.security-runtime/perf-scope-audit.json确认receipt _close/_reference/diagnostics与Hook config AST、已有tests/Deep/BOM/CET/policy/rulepack bytes不变。新增scanner_observation；改12个产品模块、2验收脚本、MANIFEST仅补必要新test/scripts、2测试文件、5现有文档与7真实JSON证据（含两份并行负载after原始记录）。构建生成egg-info为ignored元数据，不是产品重构。产品/测试最终冻结后只更新文档/基准证据。七项skip：tests/test_e2e_real.py:38/58/68/80/120/154均为real scanner binaries required（当前PATH不满足，独立managed验收另列）；tests/performance/test_managed_hot_path.py:10为Explicit managed real Scanner benchmark environment required，已独立显式运行PASS，不把skip改写PASS。

### BB.5 Before/after真实数据与剩余瓶颈

修改前源码快照保存在.security-runtime/perf-baseline，只用于对照，不reset当前workspace。两组明确选同一managedcache/version、同一fixture、scope/命令预算，基准真实测量无sleep；MCP driver既有1.1s cooldown等待只属于Host窗口，不是性能优化。before[scanner-perf-before.json](scanner-perf-before.json)，最终after[scanner-perf-after.json](scanner-perf-after.json)；完整回归结束后串行重测，safe/risk/recheck medians为3206.097/2983.128/2569.356ms，对照4672.122/4545.742/4319.427ms。cold first safe6079.319→5185.810ms，不把冷连接当暖命中。并行regression+SDK时after为3606.425/3559.008/2996.583ms，原记录保存在[scanner-perf-after-concurrent.json](scanner-perf-after-concurrent.json)，不丢弃不利数据，不用三样本声称p95或Desktop收益。

| 同fixture真实managed中位数 | before ms | after ms |
| --- | ---: | ---: |
| 安全Edit扫描 | 4672.122 | 3206.097 |
| 风险Edit扫描 | 4545.742 | 2983.128 |
| 原规则/文件安全复扫 | 4319.427 | 2569.356 |

最终串行MCP一次实际safe：before hook5142.138/scanner4516.186ms，after hook3533.367/scanner2957.053ms。风险Hook5453.212→3885.327ms（scanner4566.301→3013.363ms）。episode1resolved：beforehook10097.094/scanner4575.642/recheck4769.232/prep805.249ms；afterhook6868.439/scanner3013.320/recheck3048.215/prep801.506ms。policy321.868→343.811ms未优化；双scanner9344.874→6061.535ms，独立必要recheck仍存在。episode2最终hook7000.503/scanner3000.108/recheck3214.298ms，CLOSED/RETURN_TO_HOST。数据[scanner-perf-core-before.json](scanner-perf-core-before.json)/[scanner-perf-core-after.json](scanner-perf-core-after.json)；driver模拟Hostedit、无模型，不是Desktop自然执行。autoRem1107.975/1108.348ms不可加入total，prep也是不同MCP调用；不把各阶段机械相加作端到端。此前并行负载safe4136.377/resolved7571.741ms保留于[scanner-perf-core-after-concurrent.json](scanner-perf-core-after-concurrent.json)，不冒充最终串行数据。

未引入worker：确定的PriorityA收益已获得，剩余CLI初始化/配置加载/engine过程约2秒以上和身份hash约0.3秒仍是瓶颈，先用真实Desktop与大项目scope测量，未来worker必须先设计隔离/失效再实现。本轮不优化BOM/Deep/CET、不新scanner/Plus/Pro/Sandbox/Dashboard。三位试用Pending、GroundTruth UNREVIEWED/null、p95p99/常开体验NOT_MEASURED、真实Maven环境Pending保留。

### BB.6 下一次 Desktop 最小复测

当前未替换活动Runtime。将来明确加载本轮实现后，同一一次性Javafixture全新Chat，核对Hook响应存在scanner_diagnostics（0.3.1版本alone不足以辨别源码）；先cold普通Edit，再同会话数次safeedit观察version_probe cache/count和planning，有实际process_invocations=1、21rule/1file而非旧结果reuse。显式TLSfixture风险→原opaque grant prepare→只删风险行→完整Hookscan+原rulefreshrecheck，期待1rule/1file、新process/confirmedrule/filecoverage和resolved/CLOSED/RETURN_TO_HOST。再次引入同family应新episode/新refs；旧refs拒绝。记录至少cold/warm各3次，保留两scanner分项，不加Host等待窗，确认无Functional/build/test。可在临时环境改rule/helper/config再验MISS/failclosed，不能修改活动scanner/rules。此为Pending步骤，未实际执行，不写DesktopPASS。本轮既定门禁与记录已完成，停止，不commit/push/部署，不进入新阶段。HEAD仍ee1bfd9c12493683cc313cb3628753a51ae124ac，保留前序与本轮dirty实现。修改产品文件：codex_mcp_hook、hook_runtime、mcp_server、models、processes、remediation、rule_coverage、rulepacks、runtime、scanners、toolchain、verification；新增scanner_observation。新增test_scanner_hot_path及performance/test_managed_hot_path，新增scanner_hot_path_benchmark、扩展core_hot_path_acceptance，MANIFEST补包内验收文件。Hook/Git snapshot仓库状态采集仍保留；repository_discovery=false仅表达Scanner显式target/profile范围，没有声称Hook无需采集仓库状态。

## BA. Core P0-1: Hot Path Policy & Integration Hardening

### BA.1 范围与默认链路

起点 feature/runtime-mvp / ee1bfd9c12493683cc313cb3628753a51ae124ac，保留前序未提交实现。编辑 → 原 HookCoordinator bounded quick incremental scan → 原 Finding/Policy → 必要 AUTO_FIX/原 opaque refs prepare_task_fix → Host 最小修复 → 原 TaskFix scanner proof recheck → SCANNER_VERIFIED_RESOLVED/CLOSED/RETURN_TO_HOST。GUIDANCE/HOST_INSTRUCTIONS 默认结束 Core；不调用 prepare/run_functional_verification、javac/Maven/Gradle/pytest/go/npm、Full Scan、Security Regression、Sandbox/业务深审。Core 必需动作失败不能伪装resolved；可选 Deep 不可用不阻止Core。

MCP verify_task_fix 默认只走安全路径；仅本连接明确 prepare_functional_verification 的原 ref pair 进入 bounded intent，后续才合并原 functional.finalize。重连须再次显式 prepare；未请求时不附虚构功能结果。Deep工具/API兼容保留，Functional/BOM/CET/执行安全源码本轮 bytes不变；resolved receipt _close/_reference/diagnostics AST、official product_hooks/codex_mcp_hook_config AST不变。scope审计：.security-runtime/core-scope-audit.json；不猜Host schema或信任hash。

### BA.2 timing 与真实本地证据

timing_ms 六项：hook_total、scanner、finding_policy、remediation_preparation、auto_remediation、security_rescan。均本机 perf_counter 真实测量；未执行/未观测null、cached scanner不复用旧耗时。scanner包含规划/检测，policy扣除其内部recheck；total包括adapter/policy/recheck。auto_remediation是prepare完成到下一Hook入场的连接内窗口，含模型/传输/停顿/编辑，不是编辑CPU时间；本driver刻意等1.1s，不能当实际模型性能。准备/Host窗口和下一Hook total跨调用，不可相加为精确端到端延迟。六trigger HOOK/MANUAL/STOP/PR/CI/SCHEDULED仅元数据，不授予权限，不建设entitlement。

实际 stdio MCP + 已有 managed Semgrep/Gitleaks、offline disposable Git Java fixture：PASS，67.72s；两轮新episode、旧ref拒绝、原ref逐字传递、matchedreceipt resolved/CLOSED/RETURN_TO_HOST。只调用handle_hook_event/prepare_task_fix/verify_task_fix，功能调用0、build/test/sandbox=false；无class产物。Host edits SIMULATED_BY_ACCEPTANCE_DRIVER，非Desktop自然模型执行；不持久化raw refs/source/model/Secret。证据 [core-hot-path-sdk-evidence.json](core-hot-path-sdk-evidence.json)，复跑脚本 scripts/core_hot_path_acceptance.py。

| 本轮实际阶段 | ms |
| --- | ---: |
| 安全编辑 Hook total / scanner / policy | 5726.325 / 5060.716 / 175.159 |
| episode1 risk Hook total / scanner / policy | 6261.351 / 5295.354 / 480.262 |
| episode1 preparation | 912.101 |
| episode1 resolved Hook total / scanner / policy | 11708.565 / 5299.139 / 353.763 |
| episode1 Host continuation window / security recheck | 1103.561 / 5545.736 |
| episode2 preparation / resolved Hook total / recheck | 855.594 / 11505.213 / 5480.792 |

Scanner及原风险recheck占主要时间。仅合成小项目单次观测、并行测试期间，不是性能benchmark；真实项目/p95/p99及常开不打断仍NOT_MEASURED/PENDING，不删必要安全复扫。

### BA.3 setup/repair 根因与修复

旧实现把单块/current-version/原字节fingerprint当唯一管理形式，重复同名MCP table在ownership repair之前TOML parse即冲突，CRLF迁移可能被误判，旧精确POC Hook不在迁移集合且mixedhandler迁移受限。用户真实Desktop升级后MCP_CONFIGURATION_CONFLICT/POTENTIAL_DUPLICATE_HOOK为USER_REPORTED FAIL；未取得当时rawconfig/manifest，不能证明其唯一触发组合。本轮fixture复现上述具体缺口。

signedmanifest v0.1/v0.2→原精确marker+CRLF归一化blockhash+serverfingerprint共同attest；重复自有block在parse前只读合并，mutation删除全部已证明自有block后追加单个当前格式。旧MCP POC仅signedinstallation锚点+精确生成器，旧command仅Git managed marker+精确生成器；只移除ownedhandler，保留parent自定义handler/其他event。保留customMCP原字节。healthy bytes/mtime不改、第二repair ALREADY_CONFIGURED。现有锁/journal/原始fingerprint/并发编辑检查/rollback保留；未知ownership、tamperedmanifest、修改同名MCP或近似Hook继续failclosed，不能擅自repair用户对象。未修改活动项目配置/Hook trust。

### BA.4 自动化与包门禁

新增18项（test_core_hot_path.py 7；test_codex_managed_migration.py 11）：安全编辑/Level1AUTO/原风险resolved/recurrence新episode/旧ref拒绝/真实timing/null/nonpersistence；Functional prepare/run/finalize/registry discovery/LocalSandbox.run禁用桩证明不进入默认链路；scannerfailure不伪造成功；Core readiness缺Deep可用；MCP显式Deepopt-in分支兼容。迁移覆盖fresh/repeated、旧MCP+Hook同时升级、setup/repair重复自有MCP、混合customMCP/Hook保留、oldcommand、POCduplicate、CRLFhealthy、相似custommatcher/input/timeout拒绝、secondrepair稳定。旧test_host_orchestration只更新两项默认guidance期望。

| 门禁 | 真实结果 |
| --- | --- |
| saved AZ baseline（历史未重跑） | 1094 passed /6 skipped /6 subtests，1456.64s |
| 早期new focused | 17passed/1failed，26.73s；fixture未创建实际新编辑，修正fixture |
| 早期targeted | 265passed/7failed，346.96s；manifest默认读取与clock替身兼容发现并修复 |
| readiness/迁移复核 | 78passed，96.50s |
| 早期finalfocused | 271passed/1failed，398.75s；新增timing访问被旧monotonic替身替换的time.perf_counter，独立import真实perf_counter修复，旧测试不降低 |
| 旧full | INTERRUPTED_AFTER_FOCUSED_CLOCK_FAILURE_WAS_IDENTIFIED；未跑完，不计最终通过 |
| 最终focused | PASS：272 passed，413.00s（wrapper413.59s），returncode=0；.security-runtime/episode-core-final-focused-v2.log/.json |
| 最终full offline | PASS：1112 passed /6 skipped /6 subtests passed，1132.03s（wrapper1132.63s），returncode=0；.security-runtime/episode-core-final-full-v2.log/.json |
| wheel/sdist、package integrity、compliance | PASS，3.86s；103打包Runtime文件bytes一致；check_wheel、许可证分发审计及NOTICE检查通过；network=false |
| 实际本地MCP+Scanner | PASS，67.72s；SIMULATED_HOST_NOT_DESKTOP |
| fresh Desktop / clean install / standalone / CI | PENDING_CORE_HOST_TRIAL / NOT_RUN_NOT_REQUIRED_THIS_SCOPE / NOT_REBUILT_ACTIVE_BUNDLES_PRESERVED / NOT_TRIGGERED_NO_PUSH |

包证据 [core-hot-path-package-evidence.json](core-hot-path-package-evidence.json)，产物 dist/core-hot-path；wheel sha256 56bf3dce7a1042554866d34fe07811065c742864309aa3b37199ef847990fbf2，sdist sha256 8367abd6041bb4ae0495317972714b4af2e3bc150ae8cbabf9ed98befa759263。活动Runtime/native包未替换。full期间及结束后产品/测试代码均未再改，仅更新最终文档。六项SKIPPED为tests/test_e2e_real.py:38/58/68/80/120/154，原因均real scanner binaries required；此测试PATH没有所需真实scanner二进制，不计PASS。独立SDK使用已存在managedScanner的真实验收与这些PATH门槛分开记录。

### BA.5 最小 fresh Desktop Core 验收与剩余P0

本轮不安装。将来在用户明确允许加载新实现后，用一次性Git Java fixture，正常setup codex→repair两次，检查第二次ALREADY_CONFIGURED及自定义MCP/Hook仍保留；正常Review & Allow、重开全新Chat。runtime-info必须存在execution_timing/default_hook_profile=CORE/deep_verification_default_hook=false，0.3.1版本alone不足以证明新代码。要求仅编辑普通Service、不主动安全scan或build：实际PostToolUse→无NEW，timing可见。再显式安全测试加入always-trueHostnameVerifier，原HookAUTO→原opaque引用prepare→仅删该风险行→Hook安全复扫resolved/CLOSED/RETURN_TO_HOST；不自动功能验证/build/test/sandbox，不重复危险编辑。再次引入同family应新episode/新引用，旧引用不可复用。保留调用序列与timing，但不上传rawsecret/source/refbearer。此为待执行步骤，不是PASS；不安排Functional/BOMDesktop测试。

仍存在Core P0：Desktop自然续行稳定性需实机确认；本地扫描约5s及resolved约11.7s，真实项目/p95/p99与常开体验未证明；两次独立安全检查成本需未来在保持proof强度的前提下评估，当前不能去掉recheck；未attested配置冲突不能破坏性自愈；版本未变/活动包未部署，需要新字段辨别实现。三位试用PENDING、Ground Truth UNREVIEWED/null、quality NOT_MEASURED、Maven A/B PENDING_ENVIRONMENT_PREREQUISITES不补写通过。

本轮改6个已有产品模块codex_integration/codex_mcp_hook/hook_runtime/host_guidance/mcp_server/remediation，新增hook_timing；2新测试文件+原hostorchestration断言、1SDK验收脚本、5既有文档及2JSON证据。前序dirty文件保留。无联网/依赖下载/系统安装/模型调用/用户源码编辑/构建/Secretrotation；仅disposablefixturedriver编辑及既有full回归里的历史verifier测试。无CET/BOM/Functional能力扩展，无新scanner/sandbox/entitlement。HEAD不变，不commit/push/替换活动Runtime，完成门禁与记录后停止。

## AZ. Deep Verification protocol correctness fix

### AZ.1 范围、真实反馈与根因证据

起点 branch feature/runtime-mvp / HEAD ee1bfd9c12493683cc313cb3628753a51ae124ac；前序 episode/Host discovery/BOM 未提交实现保留。用户真实 Desktop 报告 AUTO_FIX→SCANNER_VERIFIED_RESOLVED/CLOSED→prepare functional→SECURITY_RECEIPT_REQUIRED_REFRESH，记 USER_REPORTED FAIL。只读实际 runtime-episode-e2e-clean 的 signed 状态确认历史 episode2/current episode3、原 scope/guards/snapshot 均可核对；没有失败调用的原始 opaque refs，因此不能把旧 episode 或 STALE review 推断成该调用的已证明唯一原因。

两个旧实现缺陷已用 deterministic scanner fixture 复现：有效 AI review 在安全修改后 STALE，旧 _member_current 的 UNTRIAGED gate 否定已 resolved proof；signed resolution 的 hook_scan_id 被替换为 origin risk scan 时旧 functional_receipt 仍接受。旧 resolution 仅三字段且 functional reader 不检查其 scan/scope，所有错误吞为 None；DEBOUNCED Hook 的旧 scan ID 也可能被错误记录成 resolved scan。这是生命周期/引用校验问题，不能以跳过校验解决。初次复现 2 failed（8.77s），证明旧行为；早期一次 fixture import 缺失为测试收集错误，修正后再复现，不计 PASS。

### AZ.2 修复与协议

安全关闭时原子持久化 resolved-security-v1 binding：workspace/task hash/grant/episode/origin scan/精确原 finding scope/resolved scan hash/verification identity；原 refs 格式不变。当前扫描覆盖和 family absence 仍须证明；缓存 Hook 的风险 scan ID 不得冒充新 resolved scan。独立实际 TaskFix recheck 无 DB scan ID 时保存自己的 snapshot/scope/proof identity，hook_scan_id=null。重复同一有效 proof 的 verify 不重新生成 identity。

prepare/run/finalize 复用现有工具，核对当前 episode、原 token、上述绑定、完整 snapshot/source/preservation guards 和原 policy/确认授权期限/connection。prepare 与状态提交共享锁；具体 reason 包括 superseded episode、wrong workspace、origin/resolved scan 不存在或 scope 不符、receipt binding 各项不匹配、snapshot changed/unavailable、proof changed、state busy。安全 resolved 事实与 current_snapshot_valid/functional 授权分开；receipt 问题返回 FUNCTIONAL_INCONCLUSIVE / SECURITY_VERIFIED_FUNCTION_UNKNOWN，不抹掉可信 scanner 事实，不生成计划。

旧格式 receipt 仍可读、保留 recurrence 安全事实；功能授权前返回 RESOLVED_RECEIPT_BINDING_REQUIRED，明确 handoff 到既有 verify_task_fix，逐字保留原 refs；实际 scanner 复核成功才绑定新 proof。旧 episode 不会被 handoff 换成新对象。新 proof 进入 plan_digest/cache/report 校验；旧报告不能消费不同 proof。确认过期/重连仍拒绝，不续权。

### AZ.3 自动化验收

新增 tests/test_security_receipt_lifecycle.py：首次关闭立即准备、STALE AI review、同 family 新 episode/旧 refs/旧 proof、restart current episode、七项绑定错配、旧/missing scan、wrong workspace、原 finding/detector scope、source/snapshot 错误、旧格式真实复核、cached Hook scan、状态提交锁、重复 verify/报告/finalize、proof 被替换、已确认安全事实不被功能失败覆盖、确认 expiry/restart 与 policy change。

| 验收 | 真实结果 |
| --- | --- |
| saved baseline（AY，未重跑旧工作区） | 1067 passed /6 skipped /6 subtests passed，1244.51s |
| 早期两项修复 + episode/Host/BOM | 81 passed，178.11s |
| 新生命周期首轮 | 23 passed /1 failed，117.71s；发现 finalize 合并重复 stage 导致具体错误被通用错误覆盖，已修复 |
| 最终 focused | PASS：319 passed，864.01s（wrapper865.23s），returncode=0；新 receipt 与原 remediation/episode/确认/functional/Host/BOM/Codex 集成回归 |
| 最终 full offline | PASS：1094 passed /6 skipped /6 subtests passed，1456.64s（wrapper1457.44s），returncode=0；独立日志 .security-runtime/episode-receipt-final-full.log/.json |
| BOM/CET/Hook 指导范围审计 | PASS：执行安全模块和 BOM 测试 bytes 不变，_javac_sources AST 不变，原 Hook GUIDANCE/确认指导/政策版本/TTL 不变 |

新增27项全部包含于最终定向/full 回归；最终 full 后仅更新文档，无产品或测试代码变更。六项 real scanner PATH 验收不计通过：tests/test_e2e_real.py:38/58/68/80/120/154，均 real scanner binaries required，需本套 PATH 上真实 scanner binaries。本轮不重新做 package/native/clean install/实际 Desktop 验收，前序证据仅历史。产品源码本轮仅 remediation.py、functional_verification.py，另新增本测试、更新五份既有文档；其余前序未提交文件保留。外部 docs/PROJECT_CONTEXT.md 未读取/修改。

### AZ.4 产品定位与停止边界

这是 Deep Verification protocol correctness fix，Core 默认产品方向为增量安全扫描/Finding/Policy/必要 AUTO_FIX/安全复扫后返回开发者。现有 Functional/Build/Test/Sandbox 能力兼容保留供未来 Plus/Pro/Manual/Stop/PR/CI；本轮没有增加 Hook functional planner/executor 调用，也未加强/迁移原默认指导。BOM、CET、verifier 能力不扩展。按用户最新要求不继续安排实际 Desktop BOM/Functional E2E；历史 AY/AX 中步骤不构成本轮工作。

不 commit/push/替换活动 Runtime，无网络下载、安装、新执行沙箱、Runtime 模型或用户目标源码编辑/构建/Secret rotation。仅临时 fixture 的 deterministic verifier/既有本机 JDK 回归运行。三位试用 Pending、Ground Truth UNREVIEWED/null、质量 NOT_MEASURED、真实 Maven A/B PENDING_ENVIRONMENT_PREREQUISITES 保留。完成既定测试与记录后停止，不进入下一阶段。

## AY. javac UTF-8 BOM compatibility

### AY.1 真实用户反馈、范围与根因

起点 feature/runtime-mvp / `ee1bfd9c12493683cc313cb3628753a51ae124ac`，AX/AW 的未提交实现保留。最新用户 Codex Desktop clean E2E：TLS 风险发现→AUTO_FIX→SCANNER_VERIFIED_RESOLVED→javac plan→Host 执行→run 结果回传成功，security 未被 functional 覆盖；TlsService.java 开头 UTF-8 BOM 导致 javac exit1，Runtime 最终 FUNCTIONAL_INCONCLUSIVE。上述 Host 链路 **USER_REPORTED PASS**、源码兼容 **USER_REPORTED FAIL_BOM**，不是本轮模拟 SDK 证据；本次修复后的真实 Desktop **PENDING_ACTUAL_DESKTOP**。

根因是原 javac Host plan 直接编译目标原文件，-encoding UTF-8 不去除开头 U+FEFF。只改[功能验证服务](../src/security_runtime/functional_verification.py)，新增[13项 BOM 测试](../tests/test_functional_javac_bom.py)及既有五份文档；无 CET/Hook/模型/扫描器/执行沙箱/MCP 输入 schema/风险策略变更。

### AY.2 临时源码与结果契约

1. 保留原 receipt/opaque refs、成员选择、snapshot/config/tool/预算校验。只读取 ≤8 个目标的有界字节，严格 UTF-8；重复开头 BOM、无效 UTF-8、NUL 不猜编码、不转换，FUNCTIONAL_INCONCLUSIVE / JAVAC_SOURCE_ENCODING_UNSUPPORTED，安全仍 SCANNER_VERIFIED_RESOLVED。
2. 无 BOM 时 source_handling=ORIGINAL，仍编译原相对文件；任一目标有 EF BB BF 时 source_handling=TEMPORARY_BOM_NORMALIZATION，在 Runtime 原专用外部临时目录 sources/ 下复制所有选中目标，仅去除有 BOM 的副本开头三字节。其余 bytes、换行、package 与相对目录保留；未选中成员不复制。Host 使用计划中的 sources/ cwd、原相对 argv，不编译原文件。-d/classpath/sourcepath 均在项目外，annotation processor/implicit compile 仍关闭。
3. plan/step/functional 结果 source_modified=false 指原用户源文件；新增 normalized_target_files 与 source_policy=javac-leading-utf8-bom-v1，plan_digest 绑定元数据与固定命令。run/缓存/final verify 保留 source_handling；没有 raw source/Secret 摘要持久化。
4. 临时源副本复用 projection 输入的 HMAC 校验，篡改返回 HOST_MODIFIED_VERIFIER_INPUT；提交后与 .class 一起通过原有 containment/link/产物预算检查安全清理。过期/正常退出亦复用原清理。突然 kill/crash、链接/超限或无法安全删除仍可能残留；不得盲删、不得声称 cleanup 成功。
5. 只有 Host 执行，Runtime 不创建通用执行环境。成功仍仅 COMPILE_ONLY，baseline UNKNOWN、regression attribution NOT_PROVEN、production correctness UNKNOWN。真正 Java 编译错误不被归一化掩盖，可 FUNCTIONAL_FAILED / SECURITY_VERIFIED_FUNCTION_FAILED；独立安全事实不降级。其他不可处理输入为 INCONCLUSIVE，不推断 remediation 导致失败。

兼容：工具名/参数、opaque refs、闭合 execution_result 回传模型不变；新增输出字段，不需要手工生成 token 或 shell 命令。BOM 计划 cwd 改为外部 sources/，必须原样遵守计划。旧 javac cache 追加政策版本使历史失败不被复用，无 BOM javac 同样重新计划一次；其他 provider 缓存 key 保持。无 DB/key/ABI 迁移，不替换活动 Runtime。

### AY.3 自动化验收

新增13项：四个真实已安装 javac 组合（有/无 BOM × 成功/真实未知类型错误）、四个不支持编码组合（UTF-16/非法 UTF-8/重复 BOM/NUL）、混合多成员仅目标投影/Runtime 不执行、临时副本篡改拒绝、取消与过期两种清理、拒绝旧 javac 结果缓存。真实编译检查 package 类产物、临时输入/输出全部清理、原源码逐字节不变、未选中坏文件不参与、COMPILE_ONLY、安全独立、cache/finalize 处理方式及无源码状态持久化。

| 检查 | 实际结果 |
|---|---|
| 起点 baseline（AX 已运行，未重跑） | 1054 passed /6 skipped /6 subtests passed |
| 首轮 focused | 1 failed /106 passed，15.58s；失败仅旧缓存测试未创建 state 子目录，已修正 fixture，不放宽产品断言 |
| 最终 focused | PASS：107 passed，16.30s（wrapper16.91s），BOM +现有 Host +原功能验证 |
| 最终 full offline | PASS：1067 passed /6 skipped /6 subtests passed，1244.51s（wrapper1245.49s），returncode=0 |
| BOM fixture actual local MCP /离线 Scanner /已有 JDK A/B | PASS，102.79s；[新证据](functional-javac-bom-sdk-evidence.json)，SIMULATED_NATIVE_HOST_DRIVER，不是 Desktop |
| commit/push/active install/native/CI | 本轮未执行，用户禁止提交推送与替换活动 Runtime |
| post-fix Desktop | PENDING_ACTUAL_DESKTOP；以上已安装 JDK 编译由测试 driver 执行，不等同 Desktop 自然派发 |

日志为本地忽略目录 .security-runtime/episode-bom-focused-final.log/.json 与 episode-bom-full-final.log/.json。离线，仅已有 javac；无依赖下载/安装/网络/用户 fixture 修改/Secret 操作。前两轮 package/SDK 记录保留历史，不能标为本次 BOM 修复后的 package/SDK PASS。未改外部 docs/PROJECT_CONTEXT.md。

六项 skipped 单列：tests/test_e2e_real.py:38/58/68/80/120/154，均 real scanner binaries required（该套 PATH 发现前提缺失），不计 PASS；与独立 managed scanner SDK BOM A/B 的实际证据分开。最终完整回归后仅更新文档，无新产品或测试代码变更。HEAD 保持起点；仅本轮增量为 functional_verification.py、test_functional_javac_bom.py、五份文档与 BOM SDK evidence，前两轮实现保留。functional_execution.py/CET、codex_mcp_hook.py/Hook core 均未修改，无活动 Runtime 替换。

本轮另在一次性 UTF-8 BOM fixture 复用 AX 的实际 MCP/Scanner/JDK driver：原 SDK 的 SAFE 增加显式开头 U+FEFF（Python UTF-8 写出 EF BB BF），baseline/unsafe/安全修复均保留 BOM，未改该 SDK 产品脚本。两 case 都使用本次新 opaque refs、prepare_task_fix→matched scanner resolved→functional READY→原计划 Host driver javac→run 原报告→verify。A exit0/665ms、PASSED/COMPILE_ONLY/SECURITY_AND_FUNCTIONALLY_VERIFIED；B 基线已有未知 symbol，exit1/600ms、FAILED/SECURITY_VERIFIED_FUNCTION_FAILED，安全均保持 SCANNER_VERIFIED_RESOLVED / CLOSED。原文件内容（含 BOM）不变、无.class污染、临时产物清理。总102.79s，javac21.0.9，无网络；结构化记录不含 raw references。仅模拟原生 Host 的实际 MCP 证据，不伪装 Desktop；逐字节/处理方式/临时源码清理由 focused 的真实 javac 测试额外校验。

### AY.4 下一次真实 Desktop E2E

1. 本轮不替换活动 Runtime；之后经用户安排加载此工作区修复实现、重连新会话。在一次性 Java 无 Maven/Gradle fixture 的 src/main/java/demo/TlsService.java 建立 **UTF-8 BOM** 安全文件，记录原 bytes。不要使用旧 task/remediation/functional refs。
2. 同会话显式授权隔离 E2E：只加入 always-true HostnameVerifier，等 Hook 新检测/新 refs；原样 prepare_task_fix，只删除该危险行。保留 BOM，等 SCANNER_VERIFIED_RESOLVED。
3. 立即原样 prepare_functional_verification；应 READY、javac 单 step、TEMPORARY_BOM_NORMALIZATION/source_modified=false/normalized_target_files 仅该目标，cwd=项目外 sources/，-d 同一外部目录。原文件仍含 BOM，临时副本不含开头 BOM。
4. Host 严格按原 argv/cwd/env/budget 无网络执行，不自行换成用户源码或扩大 scope。向 run_functional_verification 回传原 functional_ref/plan_digest、exit0 和有界脱敏状态摘要，不提交源文件或完整日志；原样 verify_task_fix。
5. 期待 security SCANNER_VERIFIED_RESOLVED、functional PASSED / FUNCTIONAL_VERIFIED / COMPILE_ONLY、overall SECURITY_AND_FUNCTIONALLY_VERIFIED，production UNKNOWN。核对 source_modified=false、原安全源码 bytes/BOM 不变、source_handling 保留、临时源和 .class 都清理，用户目录无 .class。
6. 无 BOM 对照应 ORIGINAL；如果另建基线已有真实编译错误的独立 fixture，保留错误，仅修安全行，功能失败仍保留 resolved，不将失败归因修复。未知环境或无有效计划就停，不猜 refresh 或运行宽范围命令。

三位试用 Pending、Ground Truth UNREVIEWED/null、质量 NOT_MEASURED、真实 Maven A/B PENDING_ENVIRONMENT_PREREQUISITES 保留；不搭建环境。不 commit/push/替换活动 Runtime；其他阶段 Planned，完成后停止。

## AUTO_FIX PostToolUse Code Mode Contract Fix v0.1（2026-10-04）

干净起点 `feature/runtime-mvp` / `50f002deff33d0946ee99c338d700b08a739e394`。最新用户真实 Desktop：缺失首安全 Hook 后危险首有效 Hook 为 SETUP_SEED / baseline_available=true / SCANNED / NEW1 / AUTO_FIX，First-run Baseline Seed、归因、AUTO检测策略 **USER_REPORTED PASS**。之后 Script failed、未prepare/未secure edit、resolved0；Host重试危险编辑导致SESSION/NEW0/ESCALATE。**PostToolUse continuation USER_REPORTED FAIL（Code Mode decision:block contract）**；Stop未进入，Desktop **NOT TESTED**，不能写Stop FAIL。readiness/lifecycle已有真实PASS，不再调查。新transport的fresh Desktop自然继续/Stop闭环 **PENDING_ACTUAL_DESKTOP**。

[当前官方 Hooks 文档](https://learn.chatgpt.com/docs/hooks#tool-calls-from-code-mode)核对于2026-10-04：PostToolUse decision:block 在已执行工具后拒绝nested Code Mode promise；continue:false把反馈作为model-visible result而不拒绝promise。只改codex_mcp_hook.py的AUTO_FIX反馈为continue:false/stopReason，systemMessage原样；固定提示前一编辑已执行、不要retry/repeat、授权的是remediation、立即prepare_task_fix，然后附原bounded guidance。无新字段、无原AUTO decision/reason。CONFIRM_REQUIRED原continue:false/stopReason主动询问并WAIT；NONE无停止；Stop仍decision:block/reason生成continuation prompt，不能机械替换。

实现 `1033abfd5c467661a2a7110442bcc410851e9bb1` 已提交推送。focused **156 passed in 383.80s (0:06:23)**；targeted **534 passed in 1007.83s (0:16:47)**；final full offline **987 passed, 6 skipped, 6 subtests passed in 1142.05s (0:19:02)**。六项skipped单列于AV，不计PASS。wheel/sdist/package/compliance、101打包文件bytes integrity、其余全部Runtime源码不变、严格离线clean安装、actual source SDK、独立新目录Windows native均PASS。新四类CI **PENDING_RERUN_AFTER_ACCOUNT_RECOVERY**，实际jobs/annotations见AV；未运行的平台不写PASS。最终docs HEAD按本文件git log核对，其docs-only CI在最终交付回复单列。

AUTO_FIX action/interaction、原task_ref/remediation_ref/grant_id与prepare/verify handoff、policy/guards/verification/state machine保持。HookCoordinator/baseline/snapshot/cooldown/single-flight/family multiset/coverage gating、Raw/脱敏/UNTRUSTED_CODE/session/hash/evidence_refs/预算保持；command hook保留。SessionStart/PostToolUse/Stop的matcher/tool/input/timeout/statusMessage exact Hook定义与起点一致；canonical SHA256 cb407a5d3e175add5d51d90c86e5fd43cb74708b770dc585eab9eca92e82eb8b仅Runtime测试摘要，不猜Host私有hash、不写信任数据库。

SDK/clean/native真实Runtime/Scanner均SETUP_SEED/NEW1/AUTO_FIX，新feedback→driver消费原Stop handoff→prepare→模拟secure edit→resolved1/SCANNER_VERIFIED_RESOLVED/CLOSED，匹配receipt无需重复explicit verify；functional prepare NOT_AVAILABLE、无run。**SYNTHETIC_SDK_NOT_DESKTOP**，不证明自然模型继续。新原生包dist/standalone-code-mode由已提交实现HEAD构建；保留旧活动包/进程。fresh步骤见[Codex使用说明](CODEX_INTEGRATION.md)：全新disposable Git fixture→setup/Local Baseline READY→正常Review & Allow→退出/重开/新Chat→safe edit→danger edit→路径A自然PostToolUse或路径B原Stop兜底→同grant prepare/secure edit/resolved1，不得Script failed或重复危险编辑；不用旧ESCALATED baseline-seed-desktop-trial。

真实Maven A/B/Linux hardened execution PENDING_ENVIRONMENT_PREREQUISITES；不安装/下载/搭环境。三位试用PENDING，独立Ground Truth UNREVIEWED/null、质量NOT_MEASURED。未改Jeepay/用户实际fixture/冻结benchmark/人工标签；Runtime无模型/目标编辑/build/Secret rotation、Scanner离线，仅官方文档与授权GitHub交付联网。Capability/Entitlement、Plus/Pro、Enterprise Gate、Deep Audit、Skill/MCP Scan、Cursor、Installer、新Scanner/rule、baseline/Stop redesign及state relaxation/duplicate retry tolerance/AUTOrenewal均不进入。完成交付后停止。

完整门禁/CI/边界见[AV](AI_TRIAGE_ACCEPTANCE.md#av-auto_fix-posttooluse-code-mode-contract-fix-v01)和[结构化记录](code-mode-acceptance.json)。以下各旧节保留历史事实，当前状态以本节与AV为准。

## First-run Baseline Seed + Trust UX v0.1（2026-10-04）

干净起点 feature/runtime-mvp / `50ecaf2f4451e4cc6854651c9987ae7167a8b11c`。本轮只修 setup→首有效 Hook 的归因缺口，暂停继续扩展 Stop Guard。最新用户 disposable Desktop 真实反馈：第一条安全编辑无 Hook 记录；第二条危险 TLS 编辑首次有效 Hook 返回 BASELINE_ESTABLISHED、baseline_available=false、scanner_run=true、FULL、NEW0/NONE。这是 **USER_REPORTED FIRST_RUN_TRUST_GAP**，本次没有 AUTO_FIX，不是 Stop Guard 失败。缺失首 Hook 的 Host 底层原因未证明，不能推断用户拒绝信任。旧 readiness/lifecycle PASS 保留历史。

实现 `4915354cd6e8bef139836cb760ae6fb601d8f76a` 已提交推送；final focused **90 passed in 219.07s (0:03:39)**；targeted **524 passed in 1037.62s (0:17:17)**（最后5项测试由 focused/full覆盖）；final full offline **982 passed, 6 skipped, 6 subtests passed in 1123.35s (0:18:43)**。wheel/sdist/package/compliance、五模块包/source字节一致、严格离线clean venv、实际SDK、独立目录Windows native均PASS。新四类CI **PENDING_RERUN_AFTER_ACCOUNT_RECOVERY**，具体jobs/annotations见AU；不能把未启动四平台写PASS。最终docs HEAD按本文件git log核对，docs-only新CI在最终回复单列。

实际SDK/clean/native deliberately skip first safe Hook：SETUP_SEED、baseline_available=true、NEW1、AUTO_FIX；untracked新文件PASS；preexisting PERSISTING1/NEW0/NONE。driver消费原Stop handoff→prepare→模拟安全edit→resolved1/SCANNER_VERIFIED_RESOLVED→functional prepare NOT_AVAILABLE，无functional run。此为真实Runtime/Scanner、**SIMULATED_HOST_ONLY，不是Desktop模型证据**。fresh Desktop seed/trust/自然继续/Stop完整闭环 **PENDING_ACTUAL_DESKTOP**。步骤见[Codex使用说明](CODEX_INTEGRATION.md)，门禁和CI见[AU](AI_TRIAGE_ACCEPTANCE.md#au-first-run-baseline-seed--trust-ux-v01)。

真实Maven A/B/Linux hardened execution PENDING_ENVIRONMENT_PREREQUISITES；不安装/下载/搭环境。三位试用PENDING，独立Ground Truth UNREVIEWED/null，质量NOT_MEASURED。未改Jeepay/用户实际fixture/冻结benchmark/人工标签；Runtime无模型、目标编辑/build/Secret rotation，Scanner离线，仅官方文档与授权GitHub交付联网。Capability/Entitlement、Plus/Pro、Enterprise Gate、Deep Audit、Skill/MCP Scan、Cursor、其它Host、新AUTO_FIX rule、Functional sandbox扩展等继续Planned。完成本轮交付后停止。

当前架构/决策见ARCHITECTURE与DECISIONS首节；完整门禁/CI/实机边界见[AU](AI_TRIAGE_ACCEPTANCE.md#au-first-run-baseline-seed--trust-ux-v01)，[结构化记录](baseline-seed-acceptance.json)与[试用步骤](CODEX_INTEGRATION.md)。

### 当前验收

最新结果以本节与AU为准。以下AT及以前为历史记录，不能证明本轮fresh Desktop通过。

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

最新验收为 AT；下文 AS 及更早章节保留历史时点，不能覆盖上面的最新真实用户反馈。

以下章节为历史记录，最新状态以本节和 AT 为准。

## Codex Integration Productization v0.2 / Cold-start Readiness v0.3（2026-10-04）

Implementation e68cff74c97a0a7a45df2381015b5906b072a82f 已推送；本轮四类新 CI **PENDING_RERUN_AFTER_ACCOUNT_RECOVERY**，9 jobs 无 Runner/steps，实际 annotations 均为账户付款/支出限额阻止启动，不是代码 PASS 或已运行的代码失败。未改账户、workflow门槛或安全契约，四平台未执行。新 runs 见 AS.5。Windows native 已从该已提交 implementation HEAD 重建并完成实际本地 MCP/lifecycle验收，68.66s，version.json source_commit与实现HEAD一致。最终docs HEAD按PROJECT_STATE的git log核对，docs-only新CI在最终交付消息独立核实。

干净起点 feature/runtime-mvp / 022f402a7ade0ed0cf6bbfce50dccd04ed5920a1。最新用户真实 Desktop 回传：MCP Hook/equivalence、CONFIRM 主动询问/批准/拒绝、AUTO 无错误许可问题→prepare→宿主最小修复→Hook resolved1→Runtime 内部 TaskFixService.verify SCANNER_VERIFIED_RESOLVED→functional prepare 无 verifier NOT_AVAILABLE/SECURITY_VERIFIED_FUNCTION_UNKNOWN，均 **USER_REPORTED PASS**。未报告显式 verify_task_fix 或 functional run，不补写已执行。AR 的旧失败/Pending 保留历史语义，由本节最新回传覆盖当前判断。

本轮只交付 Codex 自有项目 setup/status/repair/remove、readiness/诊断及既有复核协议去重。Runtime 0.3.1 / developer-guidance-v0.3 保持，features 新增 codex_integration v0.2 / cold_start_readiness v0.3。新 **fresh Desktop cold-start PENDING_ACTUAL_DESKTOP**；未在当前聊天伪造真实启动派发。source SDK/clean/native 模拟宿主编辑不代替 Desktop。

新增 focused **59 passed**；定向 **438 passed /420.09s**，最后三项 readiness 状态/恢复由 focused 与 final full 覆盖。最终完整离线 **894 passed, 6 skipped, 6 subtests passed in 514.48s (0:08:34)**，六项 skipped 单列。wheel/sdist/七模块逐字节完整性/package/compliance/严格离线 clean（无 editable/system site，117 cached wheels）/Windows native **PASS**。实际本地 MCP + Semgrep/Gitleaks 合成冷启动不调用 get_runtime_info、不重复显式 verify，无 verifier 时不调用 functional run。门禁见 [AS 验收](AI_TRIAGE_ACCEPTANCE.md#as-codex-integration-productization-v02--cold-start-readiness-v03)、[证据](codex-product-acceptance.json)、[用户命令与 fresh trial](CODEX_INTEGRATION.md)。新 CI 推送后按实际 jobs/steps/annotations 核对，未预写通过。

最新验收为 AS，以下旧章节是历史时点。

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

当前新增验收附录为 AN；AM/AL/AK 为各自时点的历史记录。


2026-10-01，`feature/runtime-mvp`。原轮实现已有 Scanner Finding 的证据验证与独立展示层；2026-10-02 开发者任务入口的独立验收见末尾附录。未增加 scanner、主动 AI 仓库审计或跨文件编译器级可达性分析。公开 Jeepay 的 OSV 在线测试使用用户当次明确授权；BYOK 验收仅访问本地 loopback 假服务器。

## A. 起始 HEAD

`47c41f4bfd41474cd9276d95999dd32bfca70d0e`。开始时分支正确、工作区干净。完整离线 baseline：308 passed、6 skipped、6 subtests passed，85.25 秒。

## B. 最终 HEAD

最终实现 HEAD：`557052049c74c6d1ca4321c2d9559483a36f55d2`，包含首轮实现 `93ef02f`、完整 Finding 行数预算修正 `f195020` 和 external provider 离线限制 `5570520`。最终报告提交 SHA 随交付消息记录，CI 记录见 AD。未操作 main。并行工作产生的 ARCHITECTURE／PROJECT_STATE／DECISIONS 等文档保留在工作区，未纳入本轮提交。

## C. 修改文件

核心新增 `triage_models.py`、`triage_evidence.py`、`triage_providers.py`、`triage.py`。扩展 storage、CLI、MCP、human renderer、progress；ScannerRun 增加依赖库存计数，OSV 保存可获得的 affected range／fixed version 元数据，Gitleaks 保存匹配 EndLine。增加 Triage 测试与固定合成数据集、本地 Jeepay MCP benchmark、wheel／standalone 检查。Raw Finding、RiskEngine 和 scan capability 聚合保持独立。

## D. Triage 数据模型

`TriageRecord` 独立保存 scan_id、finding_id、fingerprint、verdict、confidence、exploitability、reason、attack_path、evidence_refs、已满足／未知前提、建议、provider_type／name／model、prompt_version、context_hash、priority、status、policy_notes 和时间。SQLite 使用新增 triage_records 表及 cache index；已有 scans/findings 不被改写或删除。保留已有扫描历史；旧数据库通过 CREATE TABLE IF NOT EXISTS 加法迁移，不搬移目录。

## E. Verdict

CONFIRMED 表示已有证据支持 Finding 本身；LIKELY 表示高度支持但仍有未知；NEEDS_REVIEW 表示证据不足；UNLIKELY 表示风险信号较弱但非误报证明；FALSE_POSITIVE 必须满足更严格的明确反证门槛。模型不能决定 hide/block，也不能删除 Raw Finding。

## F. Exploitability

CONFIRMED／LIKELY／CONDITIONAL／UNLIKELY／UNKNOWN 独立于 verdict。依赖版本命中并不证明可达性，v0.1 的依赖 CONFIRMED／LIKELY exploitability 被保守限制为 CONDITIONAL。未声称有 Joern／CodeQL／Semgrep Pro 的 reachability 能力。

## G. TriagePolicy

CONFIRMED 或 HIGH confidence 的 LIKELY，结合原 severity 和非 UNKNOWN／CONDITIONAL 的 exploitability，进入 ACTIONABLE。其他待确认风险为 REVIEW；UNLIKELY 为 LOWER_PRIORITY。

SUPPRESSED 仅接受 FALSE_POSITIVE + HIGH confidence + 所有引用有效 + 明确可核验反证 + 无未知前提。v0.1 自动反证只支持严格完整赋值语句中的固定 placeholder 字面量；文档／test／example 位置、公开项目、没搜到 API、自然语言理由都不建立反证。不满足时降级 NEEDS_REVIEW。真实 Jeepay 没有 Finding 被压制。

IaC 保留 UNTRIAGED 状态，另按明确 Trivy rule ID 分类。DS-0002 → HARDENING；DS-0022／DS-0025／DS-0026 → BEST_PRACTICE；DS-0029 → HARDENING。支持规范的 AVD/legacy ID 别名；未知规则保守归入 SECURITY_MISCONFIGURATION。未使用 title substring 决策。

## H. EvidencePacket

包含 finding identity、category、severity、scanner confidence／source、rule_id、file／line、rule metadata、脱敏 scanner evidence、context、related_evidence、enrichment、questions、UNTRUSTED_CODE notice 及 context_hash。

严格边界：单文件最多读取 1 MB；每文件最多 120 行；最多 5 个关联文件；每 Finding 整个序列化包不超过 32 KB；symbol search 最多 200 候选文件和 256 KiB；单批最多 20 Findings；并发固定 1；默认 provider timeout 30 秒、response 64 KiB。BYOK 整个请求另限 256 KiB。同文件相关 use、imports、class/method 和词法引用均明确不等价于可达性证明。

## I. SAST Evidence 示例

Jeepay YsfHttpUtil.java:314–317／326–328 的危险 verifier／trust manager 定义与同文件 205–230 的 sslContext.init、setHostnameVerifier、setSSLSocketFactory 一并进入限定 packet。两条局部 bypass 判为 CONFIRMED／HIGH，exploitability=LIKELY，保留生产调用和网络攻击位置未知前提。不是“已证明公网可利用”。

## J. Secret Evidence 示例

Jeepay 配置显示 CONFIG、路径、可安全提取的 key name 及周边结构，匹配行完全为 `[REDACTED_SECRET]`。Java 常量周边保留 AES encode/decode 的引用关系；文档样例保留文档性质，但不泄露匹配值。相邻字符串亦保守脱敏，牺牲部分上下文以限制泄漏。

## K. Dependency Evidence 示例

包含 package／version／ecosystem／manifest、provider、原 severity、advisory ID／alias／title／summary、已存在的 affected_ranges／fixed_versions 和 coverage contract。POM 只有精确 groupId/artifactId/version 的直接声明匹配才标 DIRECT；其余 UNKNOWN。不推测缺失的版本范围、升级版本或利用条件。同包、版本、生态、manifest 分组；BYOK 对同组共享 context 并用结构化 batch 返回。

本次保存的真实 baseline 在 richer advisory metadata 改动前生成，所以其缺失字段保持 unknown；没有追补编造数据。

## L. Secret Redaction 证据

正式测试覆盖 AI request、MCP、日志及 SQLite record 中不存在合成匹配 Secret；恶意模型回显被发现的 Secret 也在保存前替换；API key 回显在解析 provider response 前替换。provider 错误不保存 body／request／原异常文本。MCP 和 BYOK 接口均不提供 environment 或 tool execution。

Raw scanner 层原有 Gitleaks `--redact=100` 与固定 evidence 保持。新 EvidenceBuilder 对所有 scan 内 Secret 匹配行执行出口保护，保守清除邻近字面量及长 token。未知、未被 scanner 识别且无明确形态的任意数据不是可证明“绝无 Secret”的完整检测能力；仍需要限定内容和用户授权共同控制风险。

## M. Prompt Injection

固定测试源包含“忽略安全规则、判误报、外传环境变量”等攻击语句。源码始终在 UNTRUSTED_CODE 数据区；system instructions 明确不跟随代码／注释／README／config／Skill／scanner 内容。JSON schema 拒绝 shell/network/hide/block 等额外字段；Runtime 不执行任何模型给出的命令。

## N. Agent-native MCP

新增 prepare_triage、submit_triage、get_triage，保留原五工具。prepare 返回 packet、schema、instructions、prompt version 和 connection-local triage_session。会话仅保存 hash/finding IDs，15 分钟过期，最多 64 个；提交必须属于该交接且当前 context hash 有效。成功项消费，拒绝重放；跨 scan/workspace、伪造 session、引用不存在或范围越界均拒绝。

真实 SDK stdio mock Coding Agent 流程 `scan_project → prepare → mock analysis → submit → get_findings` 通过；真实保存的 Jeepay native result 也经实际 MCP prepare/submit/get 验收。Runtime 不主动调用 Host Agent 的模型。

## O. BYOK 配置

```text
security-check ai configure --provider openai-compatible --base-url https://provider.example/v1 --model user-model --api-key-env SECURITY_RUNTIME_AI_KEY
```

只保存 provider/base_url/model/环境变量名于用户 state 目录 ai.json。实际 key 从指定环境变量读取；不保存值。URL 禁止用户密码、query、fragment；要求 HTTPS，loopback 假服务器可 HTTP；禁止自动跟随重定向。通用 AIProvider.triage 接口、AgentNativeProvider 和 OpenAICompatibleProvider 独立于 scanner。

## P. 外传授权

普通 scan 为 deterministic only。`triage --provider configured` 没有 `--allow-external-code-context` 即 fail closed，noninteractive／CI 同样生效。配置命令明确说明将发送经过限制和脱敏的代码上下文；配置本身不授权发送。OFFLINE=1 时，即使提供授权 flag，也拒绝非 loopback provider。所有 CI BYOK 测试仅 mock 或 loopback，不调用收费／公网模型。

## Q. Cache

key 为 finding fingerprint + 实际脱敏 packet context_hash + provider_type/name/model + prompt_version。完全一致可复用；context／finding／prompt 变化为 STALE，不继续作为有效优先级。

packet 含限定片段的 opaque keyed revision，使被脱敏 Secret 变化也失效。本地随机 HMAC key 保存在 state 的 triage-evidence.key，权限 0600（平台权限约束内），不进入 packet／SQLite／logs／请求；不发送可字典猜测的 Secret 明文 SHA。context_hash 最终仍对实际交付的脱敏 packet（包括 opaque revision 元数据）计算，不使用整仓库 hash。不同 state key 不跨库复用。无关仓库文件变化不改变 packet。

本次第二次真实本地 MCP replay：26 个 cache hit，无重复分析。SQLite 不默认保存完整 prompt、源码片段、raw LLM response 或 HTTP request。原始扫描历史不删。

## R. Dependency Grouping

Jeepay 88 条依赖候选变为 28 个 package/version/ecosystem/manifest 组；原 88 个 advisory 仍可展开。首批选全部 3 个 CRITICAL 和原顺序前 10 个 HIGH，按包关联显示，未对 88 条逐条发模型请求。其余 75 条依赖候选保持 UNTRIAGED。

## S. IaC Classification

真实 14 条：5 HARDENING（root 4、apt-get 1），9 BEST_PRACTICE（HEALTHCHECK 5、MAINTAINER 3、apk cache 1）。14 条均未做 AI Triage，未改原 severity／Finding。默认视图按独立分类组织，不宣称云上风险已验证。

## T. Human

普通扫描：“发现 115 个候选安全问题。部分问题需要结合代码和运行环境进一步确认。”按代码 4、Secret 9、依赖 88、配置 14 汇总；依赖先显示 28 组；verbose／JSON／Raw 可展开。

Triage：115 候选、101 eligible、26 validated、89 untriaged；ACTIONABLE 2、REVIEW 23、LOWER_PRIORITY 1、SUPPRESSED 0。保留人工确认入口及失败／过期计数。示例：[普通候选视图](jeepay-candidate-human.txt)、[Triage 视图](jeepay-triage-evidence.human.txt)。

## U. JSON

triage --latest/--scan --json 返回独立 triage_coverage、scan_coverage、capability_results、逐 finding triage record 和 dependency_groups。`--raw` 输出原 Finding。原 scan JSON 保持 raw result，附加 dependency_inventory 是 scanner 直接观测的库存统计，不是完整图证明。

## V. MCP

get_findings 返回完整原列表并附加 triage_status／verdict／triage_confidence／exploitability／record；无验证为 UNTRIAGED。get_triage 提供统一 coverage 和 grouped view。真实 benchmark MCP stdout 为 SDK JSON-RPC，stderr 为空。scan／triage 状态分离。

## W. Jeepay Semgrep Benchmark

4 条全验证：TLS hostname 和 certificates 各 CONFIRMED/HIGH/LIKELY exploitability → ACTIONABLE；2 条 MD5 为 NEEDS_REVIEW/CONDITIONAL → REVIEW。MD5 局部上下文是 key-appended payment signing，不能视为已证实 HIGH 的签名伪造路径；须继续核对协议和利用条件。

## X. Jeepay Secret Benchmark

9 条全验证：配置 7 NEEDS_REVIEW，Java AES 常量 1 LIKELY/MEDIUM/CONDITIONAL，文档 1 UNLIKELY/MEDIUM/UNKNOWN。8 REVIEW、1 LOWER_PRIORITY；没有凭文档/example/default 隐藏风险。Secret 原值未参与 Host packet。

## Y. Dependency Sample Benchmark

13 条首批全部 NEEDS_REVIEW/CONDITIONAL。原生 OSV inventory 与 advisory 匹配是 scanner 事实；使用受影响 API、具体运行前提和完整 Maven 图均未证实。没有拿“未搜到 API”判 FALSE_POSITIVE。

## Z. Raw vs Actionable / Metrics / Ground Truth

115 Raw 保留；26 triaged，2 actionable、23 review、1 lower；89 untriaged 中包括 14 IaC 与 75 dependency。Verdict：CONFIRMED 2、LIKELY 1、NEEDS_REVIEW 22、UNLIKELY 1、FALSE_POSITIVE 0。本次有效提交 invalid output rate 0、evidence validation failures 0；这只是结构校验结果，不是准确率。

平均 context 5,934 bytes，最大 7,779 bytes，重放 cache hit 26。记录：[真实 native scan](jeepay-osv-online-evidence.json)、[MCP benchmark](jeepay-triage-evidence.json)。Coding-agent 分析是结构化审阅 artifact，不是独立人工 ground truth。[人工标注文件](jeepay-human-ground-truth.json)保持 UNREVIEWED/null，可由用户独立填写三种参考标签。固定合成/重构数据集位于 tests/triage/fixtures/jeepay，不复制真实源码／Secret，不宣称 99% 准确率。

## AA. Pytest

Baseline 308 passed。初轮完整回归暴露三项旧输出／工具枚举断言，已按候选语义和新增工具修正；原不适用能力仍隐藏。最终 Triage 定向 74 passed；最终全量离线回归 382 passed、6 skipped、6 subtests passed，90.60 秒。超长 Finding 匹配范围直接拒绝交接，不能绕过 120 行预算。

安全测试包括 Secret 四个出口、注入、不授权零请求、workspace/symlink escape、伪造／越界引用、非法 JSON／schema／枚举、响应大小、timeout/HTTP 错误、API/proxy 凭证、原 Finding 不改、会话伪造／重放、Secret/context/prompt 变化、cache、batch、三种接口和进度。

## AB. Compliance

licenses --check-distribution 和 notices --check 通过。未新增第三方 runtime dependency、scanner binary 或模型 SDK；仅 Python 标准库实现 BYOK HTTP。Triage fixture 自主构造，不携带 Jeepay 代码或真实凭证。

## AC. Package Integrity

最终实现 HEAD 的 wheel/sdist build 和 check_wheel 通过，门禁显式要求四个 triage 模块；synthetic fixture 随 sdist 提供。clean venv wheel install、CLI help/version/licenses 和已安装包 integrity 全部通过。

## AD. Standalone / CI

最终实现 HEAD 的本地 Windows 完整归档验收通过：默认 managed scanners、原生 OSV synthetic offline CLI/MCP fallback、插件、MCP 及 Triage prepare/submit/get。归档 SHA256 为 `def77a2b701485c9e200ec690aa309aa245cbc3f06b20a6971af6bcee560e194`。

最终冻结程序完成同一真实 Jeepay Raw Result 的 26 条 MCP 验证，见 [冻结程序 benchmark](jeepay-frozen-triage-evidence.json)。另以 synthetic Finding 和真实 loopback 假服务器验证 native BYOK CLI：无授权零请求、显式授权一次请求、第二次命中 cache、纯 JSON stdout、安静 stderr、Secret/API key 不进入出口、原 scan coverage 不变，见 [native BYOK evidence](triage-native-byok-evidence.json)。这是本地协议验收，不是公网模型效果测量。

同一实现 SHA 的四组 CI 均成功；Standalone artifacts 包含四平台完整验收与 OSV offline fallback/MCP Triage：

- [Runtime tests](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/36879333177)
- [Compliance](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/36879333141)
- [Package integrity](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/36879333069)
- [Standalone artifacts](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/36879333124)

完整扫描、缓存与交付摘要见 [delivery evidence](triage-delivery-evidence.json)。

## AE. 尚未解决

没有 compiler-grade 跨文件 reachability；依赖 runtime preconditions、完整 POM 图及 Secret live validity 仍需人工确认。首批真实 26 条 coding-agent 审阅不是独立人工准确率测量；其余 89 条保持未验证。未支持外部模型真实收费验收／自动扫描时调用 AI。旧 privacy.py 的未使用 generate_fix protocol 与新 Triage AIProvider 分工保持兼容。状态 key 按平台用户权限保护，不能抵御已控制同一用户账户的攻击者。原 scans/findings 不是数据库级 immutable audit log，但 Triage 不改写它们。数据库 retention／跨用户多租户服务不在本轮实现。

## AF. 下一阶段建议（未实现）

由独立人工完善 ground truth，再比较模型／prompt regression；扩展可解释反证类型；单独做 IaC context validation；研究 Joern 或 compiler-grade reachability；设计限额、retention 和更细的 provider-session provenance。继续保持 scan coverage 与 triage coverage 独立。


## AG. 开发者任务入口 v0.1（2026-10-02）

本轮从干净、已同步的 `feature/runtime-mvp` / `602a78941ea6693f755ca05ae5a2c2b994d01152` 开始，仅实现 NEXT_STAGE 第一轮。没有重跑 Jeepay scanner、公网模型、目标构建或修复，没有改写历史扫描/审阅 artifact 和 ground truth。

### 交付与边界

- CLI：`security-check summary --path <project>`，`--details` 展开完整列表/逐项审阅，`--json` 输出同一投影。MCP 新增 `get_security_summary(workspace_path=None, scan_id=None, details=False)`，当前共九个工具。
- 最新记录严格局限于当前绑定/明确选择的 workspace；显式 scan ID 校验归属。未绑定 MCP 不取全局最近扫描，无记录返回 NEEDS_SCAN 和建议、不自动扫描。旧工具不增加 `latest` 别名。
- 普通视图最多三项推荐，保留原 ACTIONABLE 优先级后尽量涵盖不同主题。详细视图列出全部任务/Raw 成员/每条 advisory 身份和分析状态，以及 UUID、引用、confidence、policy_notes 和 Raw 入口；任务编号仅为当次投影。
- TLS 仅合并两个明确 first-party trust-all 规则、同文件且行起点相距不超过 40 行；同规则、远距离、不同文件不合并，不证明共享调用链。依赖沿用 ecosystem/package/version/manifest 四元组，缺身份字段则逐条展示。不凭 severity/文件/模型叙述合并其他候选。
- VALID 表述为“已完成 AI 审阅”，说明是记录通过 Runtime 校验，非人工验证/复现/线上可利用证明。扫描/审阅覆盖分列，FAILED、STALE、UNTRIAGED、IaC 不 eligible 分开解释，0 ACTIONABLE 不表示安全。
- 扫描器、Runtime 接受的 AI 审阅与宿主补充核查分层。后者标 NOT_IMPORTED，没有通用导入接口，不臆造云闪付业务调用链。模型分析不作为确定性事实。
- 独立 SQLite mode=ro/query_only 存储不创建 DB/schema/HMAC key；`persist_stale=False` 只计算内存 freshness，源变更/消失/缺 key 不沿用历史优先级、不写回状态。纯汇总 MCP 延后初始化可写 Runtime，不记录 telemetry。只读取核对 freshness 所需的预算内已有脱敏证据，不返回源码 packet、scanner secret evidence 或环境凭据。
- 所有下一步仅建议，不执行编辑、构建、联网或模型上传。Raw、TriagePolicy、RiskEngine、scan coverage、cache/batch/session 和原授权边界保留。

### 本地自动化与已保存的真实记录

同步后的基线：382 passed、6 skipped、6 subtests passed，125.57 秒。新增 34 项入口测试，最终全量离线 **416 passed、6 skipped、6 subtests passed，93.83 秒**。skipped 不计通过。覆盖无数据库/legacy/corrupt 只读、安全 workspace 与跨项目、当前/过期/不可核对 freshness、TLS/依赖保守合并、完整成员保留、脱敏/注入、CLI/实际 SDK stdio MCP、一页推荐与零 scanner/model/network 调用。

115 Raw / 101 eligible / 26 REVIEW / 0 ACTIONABLE / 75 eligible-untriaged / 14 IaC 的合成 fixture 验证 54 个任务和全部 115 成员保留。此 fixture 明确是合成测试，不冒充用户提供的 `99ca7566` 宿主运行机器 artifact，不调整历史 policy 来匹配用户报告。

另对本机已有 `.security-runtime/frozen-jeepay-final/scans.db` 做真实 CLI Human/JSON 与 SDK stdio MCP 普通/详细视图一致性验收：来自已保存的 `f5224162` 原生扫描和历史审阅回放，115 Raw、101 eligible、26 VALID、2 ACTIONABLE / 23 REVIEW / 1 LOWER_PRIORITY、0 FAILED / STALE / SUPPRESSED、89 UNTRIAGED，其中 75 eligible、14 IaC 不 eligible。形成 **54 个任务，普通推荐 3 个，详细保留全部 115 Raw 成员**。state/key 文件 SHA-256 前后完全一致；JSON/stdio stdout 纯协议，stderr 为空。这是已有真实记录的只读投影，不是新 scan/model 或独立准确率测量；Jeepay source revision 仍 UNKNOWN。

wheel/sdist 构建、新 summary 模块与 23 个规则文件分发门禁、独立 venv 安装后的版本/summary 命令/法律文件校验、licenses 与 notices 检查均通过。没有新增运行时依赖或捆绑 scanner。

### 分发与 CI 状态

本轮实现已提交推送 `00cbd721792ad14118f005ff1fcbb3996e5a8aa0`。本机 Windows x64 PyInstaller onedir 构建、归档 smoke/完整性检查（`full=False`）与该原生程序读取既有 Jeepay 记录的 CLI Human/JSON/实际 SDK stdio MCP 验收全部通过，结果与源码版一致，state/key 字节不变。version.json 的 source_commit 等于上述实现 SHA。

本机归档：`dist/release/ai-security-runtime-v0.3.1-windows-x64.zip`；SHA-256 `d9e1a0ff0c7bfbdf24390d60673d2ced0a071521dd9141ac97889fca15783455`。未建立 tag/Release，没有向外发布软件；CI 原生包另按其工作流全验收。

当前实现提交的 [Runtime tests](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/36967736351)（Linux/Windows）、[Compliance](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/36967736392) 和 [Package integrity](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/36967736424)（Linux/Windows）均 success。历史 CI 不计入本轮新功能验收。

[Standalone artifacts](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/36967736441) 最终 success，Windows x64、Linux x64、macOS x64/arm64 四平台 full/OSV fallback/实际 MCP 验收通过。首次运行的 Linux x64、macOS x64/arm64 均通过；Windows 在 `tools install gitleaks` 阶段报 PermissionError，尚未进入新汇总验证。仅重试失败 job 后 Windows 通过；保留首次失败，不修改源码或放宽安装/验收门禁。

### 人工验收及后续范围

三位未参与开发者的真实试用 **Pending**。用户明确回复“目前无法安排，保留待验收”；不使用 Agent 模拟用户或自动测试替代真实反馈，不声称首轮全部使用验收或整体 milestone 已完成。

“继续核查”和“修复与验证”两轮保持 **Planned**。独立 ground truth 保持 UNREVIEWED/null，质量指标 UNKNOWN / NOT_MEASURED，真实模型实验未运行；Joern 保持后置。


## AH. 继续核查 v0.1（2026-10-02）

开发起始 `feature/runtime-mvp` / `50a01e6870d78e6fd8a96a8b8fbe236521c5306f`，干净工作区、ff-only 同步。仅实现第二轮核查，不修改 Jeepay 源码、不构建目标、不做新 Jeepay scan/公网模型实验、自动补丁或 Joern。第一轮 AG 的历史时点/验收不覆盖，第三轮修复与验证仍 Planned。

### 普通用户入口与机器交接

用户只需说“检查这个项目”“继续/处理第一项”或选择任务。宿主负责工具选择及已有授权范围内的准备、分析、提交和结果展示；不要求用户 UUID、复制技术提示词、拼接工具顺序或把 generate_fix 输出再粘给 Agent。固定 FastMCP server instructions 已接入，实际 SDK initialize 收到并验证；工具描述和 readOnly/destructive/openWorld annotations 也通过 SDK 列表核对。

summary 的 task_ref/continuation 绑定 workspace、固定 scan 和精确成员/指纹/位置/规则/依赖身份。T01 是响应内编号，排序/审阅推进不会把引用映射到其他任务；格式/版本/成员变化或 scan 被移除要求 REFRESH_REQUIRED，不回退当前第一项。新 scan 不替换旧引用的 scan。引用是内容身份，不是权限凭据；跨 workspace 拒绝，源码变化独立由 HMAC context_hash/freshness 拒绝旧 packet。没有新持久化任务表或汇总 key。

新增 prepare_task_triage(task_ref, workspace_path=None, limit=20, retry_failed=False)，沿原 prepare_triage 实现准备 → 宿主受限分析 → 原 submit_triage 保存校验。Runtime 不调用宿主模型。任务级 session 在提交时再次核对引用身份，原15分钟/64 sessions、消费与重放拒绝、schema/hash/evidence_refs/脱敏/UNTRUSTED_CODE 与 Raw/policy/coverage 保留；任意额外宿主报告仍 NOT_IMPORTED。

当前 VALID 保留，UNTRIAGED 在 STALE 前，STALE 使用新证据，FAILED 单独默认延后，仅 retry_failed=true 显式重试。prepare 不再先截 limit 后查 cache；每次最多检查1000候选，cache 不占新分析名额，packet/证据错误最多原 limit（上限20）。已有审阅摘要另限20条/64 KiB、未知最多20项，截断明确标记并提供完整 details；记录不删除。全有效时复用依据，业务问题只对已有审阅里的明确未知生成固定候选，宿主先去除已有证据已回答/不影响下一步的问题；缺范围/修复版本等保留 BOUNDED_EVIDENCE_LIMIT，不编造或提优先级。

新增 get_runtime_info / CLI runtime-info --json，版本0.3.1、能力契约 developer-guidance-v0.2；当前11个工具。检查 required_guidance_tools 子集，允许未来新增工具，不以总数相等作为连接门禁。返回同一 executable/environment 的可执行核对参数和连接恢复：先查实际运行环境，已有新能力但宿主看不到则重连/刷新工具列表、必要时新聊天；仅实际安装旧时更新对应包，不盲目重装 editable。该检查不扫描、初始化数据库或修改配置；旧 session 不跨连接。

### 自动化与真实保存记录

本轮修改前基线：416 passed / 6 skipped / 6 subtests，97.78 秒。新增45项测试；定向汇总/进度/任务验收114 passed，39.84 秒。最终全量离线 **461 passed / 6 skipped / 6 subtests passed，152.30 秒**；skipped 不算通过。覆盖精确引用/重排/新 scan/失效/跨 workspace、pending/cached/stale/failed/限额推进、既有审阅上下文预算、source hash、session/schema/恶意字段/伪造引用/重放/过期、实际 SDK initialize/metadata/短选择对应的真实工具链和同环境能力恢复。25成员fixture前20缓存时 limit=2 仍产生2个新 packet、余3；提交后下一次取得不同2项，不重复前批。

对公开 Jeepay **已有真实保存记录** `99ca7566-4a6f-4818-b447-38646072457b`，使用项目配置指向的 `.venv/Scripts/security-check.exe`（editable）建立全新 SDK stdio 连接：实际收到宿主 instructions、能力契约与所需工具；summary 为115 Raw / 101 eligible / 26 VALID / 0 ACTIONABLE / 26 REVIEW / 0 FAILED/STALE/SUPPRESSED / 89 UNTRIAGED（75 eligible +14 IaC），54任务、3推荐、scan coverage PARTIAL。

宿主机器交接选择该响应第一项 TLS task_ref，得到 **AWAITING_BUSINESS_FACTS、0 packet、复用2条有效审阅**，候选问题为当前部署/生产渠道是否启用；没有重复调用模型分析、scanner、补丁、构建或扫描复查。state/key 文件 SHA-256 前后不变，stderr 为空。此为真实保存审阅的 SDK 复用检查，与 f5224162 历史回放的2 ACTIONABLE分开；并非实际宿主模型自然语言试用，也没有补全 Jeepay source revision 或独立准确率结论。

wheel/sdist、新 task_triage/host_guidance 模块分发门禁、23规则文件、licenses/notices 通过；**新建独立 venv 实际安装当前 wheel**，确认模块来自该 venv、版本/能力/宿主指导和法律检查通过。曾复用同版本旧安装的尝试不计本轮独立安装验收；已用全新环境排除旧包未更新的问题。无新增运行依赖或 scanner 捆绑。

### 实现与分发/CI

本轮实现已提交推送 `f2cb534f27698881ead2b2f3452bc36598c6e957`。本机 Windows x64 PyInstaller onedir、归档 smoke/实际 SDK MCP initialize/instructions/metadata/能力/任务入口通过（full=False）；该原生程序复用同一已保存99ca7566 TLS审阅，0 packet、2有效审阅，state/key字节不变。version.json source_commit 等于实现 SHA。

本机归档 `dist/release/ai-security-runtime-v0.3.1-windows-x64.zip`，SHA-256 `ab41d14ba9d6427638c6e4403be34bdd1e89f023810d172e0fd4474893f83f73`。第一轮同名旧本机归档保留在忽略目录 .security-runtime/developer-entry-archive，历史 SHA/证据不覆盖；没有 tag/Release/软件发布或 Jeepay 源码编辑/构建。

当前实现 [Compliance](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/36978159854)、[Package integrity](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/36978159847)、[Runtime tests](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/36978159875) 和 [Standalone artifacts](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/36978159836) 四组均 success。Runtime/Package 的 Linux/Windows，以及原生 Windows x64、Linux x64、macOS x64/arm64 的 full/OSV fallback/实际 SDK MCP 通过；历史 CI 不计当前验收。

### 未完成的真实使用/质量验收

实际宿主自然语言试用已尝试一次，**未通过**；重连后的真实宿主复验 **Pending**，原 Jeepay 聊天旧工具列表恢复仍未验证。2026-10-02 用户回传“查看这个项目已有的安全检查结果”“继续第一项”的回复，随后通过 Codex app read_thread 核对实际调用记录：前一轮仅调用旧 get_triage，没有 get_security_summary/task_ref；后一轮没有任何工具或命令调用，仅沿此前聊天的额外只读源码核查给出文字修复草案。因此可读回复不证明精确任务引用或任务级 MCP handoff 已执行，也不计修复与验证交付。

旧聊天此前曾明确报告缺少 get_security_summary，疑似旧连接/工具列表未刷新，但尚未证明具体原因。对 Jeepay 配置指向的同一程序复核 runtime-info，并建立全新离线 SDK 连接，确认新能力/固定 instructions 均存在；第一项仍 AWAITING_BUSINESS_FACTS、0 packet、复用2条有效审阅，state/key 哈希不变。首次受限沙箱管道权限失败后，获准复核本地 MCP 管道并成功；没有 scanner/model/patch/target build。这是独立连接检查，不能替代真实宿主复验。记录见 [实际宿主试用](jeepay-host-task-trial.json)。下一步为刷新宿主 MCP 连接及工具列表，在新聊天取得新 summary 后用同样两句普通意图复验；不要求用户提供 UUID、工具顺序或技术提示词，不盲目重装当前 editable 环境。

实际 SDK/合成宿主返回成功只证明接入和校验，不声称普通开发者已能用好。三位未参与开发者试用仍 Pending（用户当前无法安排）；独立 ground truth UNREVIEWED/null、指标 UNKNOWN/NOT_MEASURED。

完整产品目标“一次选择 → 核查 → 准备/实施获授权修复 → 验证 → 简洁结果”尚未闭环。本轮接通核查机器交接与宿主指导；generate_fix 仍只是 coding_agent_prompt/说明，不是自动修复。第三轮必须继续让宿主衔接，不能让用户搬运提示词；补丁/目标构建/测试与扫描复查均未在 Jeepay 执行，修复与验证保持 Planned，0 ACTIONABLE 不表示安全。

## AI. Host-agnostic Hook Integration v0.1 前置门禁（2026-10-02）

**结果：PREREQUISITE_MISSING，正式 Hook 实现未开始。** 用户任务明确假设 Developer Fix & Verify v0.1 已交付，且 occurrence 行号移动不会把仍存在的问题误判为 RESOLVED；缺少时要求停止 Hook delta 正式实现，不另建身份机制。

开始工作区干净，分支 feature/runtime-mvp；执行 git pull --ff-only origin feature/runtime-mvp，Already up to date。starting HEAD 为 `787aace817bd607efd22bc70a7bd613a5f313faa`。已读取五份主文档及 hooks/cli/runtime/git/findings/integrations/integration_state/mcp_server，核对当前模块和提交历史。Fix & Verify 仍为 Planned；当前 FindingNormalizer.make 的代码指纹含 line，SecurityRuntime.verify 仍以原 fingerprint 是否出现在成功扫描结果中决定 STILL_PRESENT/RESOLVED，没有前置稳定 equivalence。

完整离线基线使用本机已有 Python 3.13 / pytest 9.1.1，SECURITY_RUNTIME_OFFLINE=1：**461 passed、6 skipped、6 subtests passed，108.77秒**（整体进程109.36秒），退出0；skipped 不计通过。最初配置中的 Runtime .venv 无 pytest，未取得基线结果，随后使用已有测试环境，没有联网安装依赖。测试的 MCP 管道/loopback 使用授权本地执行，不调用公网模型或目标构建。

独立合成复现使用临时非业务源码、内存 store、成功返回候选的 synthetic scanner；走真实 normalizer 和 Runtime.verify，不执行 Semgrep：同文件/同规则/同段代码由100行移动到110行，fingerprint_changed=true，expected=STILL_PRESENT、actual=RESOLVED。复现首次受限沙箱临时文件权限失败，授权本地临时样例执行后复现成功；不计为已经修复或通过的回归。

本轮只更新现有状态/架构/决策/计划/验收文档。HookCoordinator、snapshot/dedupe/debounce/single-flight/state/delta、新统一 CLI、五个 Host Hook adapter/config、Hook 性能、fixture Host 集成及 actual fresh Codex Host trial 均 **NOT_IMPLEMENTED / NOT_RUN**。未研究或猜测 Host schema、未生成任何用户 Hook 配置、未改变现有 Git pre-commit；没有本轮实现 HEAD，不拿旧 package/standalone/CI 通过数作新 Hook 验收，也不启动无代码变更的四平台构建。

网络仅用于已授权 Git 同步和文档提交推送；没有目标扫描的在线依赖解析、外部模型调用、业务源码修改、目标项目构建、真实 Secret 保存或 Ground Truth 修改。独立人工状态保持 UNREVIEWED/null、NOT_MEASURED。恢复本任务须先取得并验收前置 Fix & Verify /稳定身份提交，不在本任务自行扩大范围补做前置阶段。

## AJ. Developer Fix & Verify v0.1（2026-10-02，本轮验收）

起始干净、ff-only 同步 HEAD `0f33d2624204794c84da6fa10cf43b8178cd5a56`，分支 feature/runtime-mvp。Baseline：461 passed / 6 skipped / 6 subtests passed，107.51秒；skipped 单列。A 定向及相关回归163 passed（38.99秒）加旧 Triage/核心/存储83 passed（8.23秒），合计246，通过后才进入 B。首轮 B 测试发现没有 HMAC key 的只读准备不足，已修正为不创建 key 的 fix-only 证据；不得用于 submit_triage，原 session/hash 防护不变。

真实本地 Semgrep 1.178.0 合成 Java：[fix-verify-synthetic-evidence.json](fix-verify-synthetic-evidence.json)，由可重复 [验收脚本](../scripts/fix_verify_acceptance.py) 构造临时项目。100→110 行只移动时 STILL_PRESENT / equivalence_key，安全替换 SCANNER_VERIFIED_RESOLVED；同 TLS 组只修一项 PARTIALLY_RESOLVED，全部安全替换为 SCANNER_VERIFIED_RESOLVED；实际 Semgrep 无效参数退出使整体 INCONCLUSIVE。不是 Jeepay 修复、独立人工真值或实际宿主自然语言 UX。

新增等价身份、Rule/file 执行证明、provider/offline/预算、低层 verify、结构化 task_fix、两个 MCP 工具和 v0.3 宿主能力指导。Raw/triage/缓存/风险/覆盖保留；任务从固定 scan JSON 取成员，新扫描不能覆盖全局 finding lookup 后误换任务。13个工具是当前 inventory，required subset 才是连接契约。prepare 只读、verify 有 local scanner/cache/temp 副作用而非 destructive。

本轮全部自动化/分发门禁已完成，精确结果和实现 HEAD 见 AJ.1/AJ.2；真实宿主与人工质量验收独立保留 Pending。真实三位开发者试用 Pending；宿主普通意图连续使用/旧聊天连接恢复 Pending；独立 ground truth UNREVIEWED/null；precision/suppression-risk 等 NOT_MEASURED。

安全：没有修改 Jeepay、覆盖旧 scan/benchmark 或人工标签；没有公网 scanner 查询、外部模型/源码上传、目标 Maven/Gradle/npm 构建、生产操作、新 Hook 或新 Hook 配置。Git 同步/推送与 CI 属于本轮交付授权，另行记录网络边界。

### AJ.1 本地最终实现门禁

最终 equivalence 定向21项、task fix/verify 定向26项（含实际 SDK stdio initialize/list/info/prepare/verify/failure/refresh），合计47 passed（10.51秒）；之前 task_triage45项与两类定向一起91 passed（24.22秒），随后补一项多来源失败测试并在全量复验。最终 full offline **508 passed / 6 skipped / 6 subtests passed，120.12秒**，没有把跳过算通过。六项旧真实 scanner 测试因 PATH 未同时提供三个引擎跳过，本轮实际 Semgrep 合成验收另行运行且通过。

package integrity、licenses --check-distribution、generate_notices --check、wheel/sdist 构建及新模块分发检查通过。Windows 创建全新 venv 并 --no-index/--no-deps 安装新 wheel，模块必须来自新 venv，实际 SDK工具列表/能力契约和合规通过；仅复用本地 system-site-packages 第三方依赖，严格独立 clean dependency install 由 CI package gate 验收。无本地公网请求。

本机 Windows onedir/归档与实际 native SDK Semgrep fix/verify、四平台新 CI 门禁现已完成，见下 AJ.2；代码/分发身份与实现 HEAD 一致。

### AJ.2 Windows 实际安装程序与本轮 CI（全部通过）

实现 HEAD `1e10b53aacf0dc0f69ad00c3126f8d8298e78989`，起始 `0f33d2624204794c84da6fa10cf43b8178cd5a56`。最终验收文档提交是其后仅文档/证据提交；实际文档 HEAD 由 Git 获取，不在文档中捏造自身 SHA。

Windows PyInstaller onedir、原生归档 smoke/许可/SDK initialize/list/summary/triage、以及真实 native SDK task_fix+Semgrep 合成验收通过。实际13工具、developer-guidance-v0.3；prepare无scanner/修改，verify对原组全部成员验证未改 STILL_PRESENT、只修一项 PARTIALLY_RESOLVED、全部移除原危险模式 SCANNER_VERIFIED_RESOLVED。Runtime DB bytes不变，host tests_run=true仅为 UNTRUSTED_HOST_REPORT，Runtime tests_run=false。测试夹具由脚本编辑，没有实际模型或人工开发者参与；不计宿主普通意图 UX。

独立包 `ai-security-runtime-v0.3.1-windows-x64.zip` source_commit = 实现 HEAD；SHA-256 `af682a6906a7c53d76b964146f68540e167c63eba6d3c84928cb40782319c746`。机器证据：[native protocol/package/CI](fix-verify-native-evidence.json)；[source Semgrep fixtures](fix-verify-synthetic-evidence.json)。wheel/sdist使用最终源码重建；本地新 venv复用本地SDK依赖，CI则实际 clean venv安装依赖并校验新模块、工具、能力和许可。

| 本轮 CI（全部针对实现 HEAD） | 实际结论 |
| --- | --- |
| [Runtime tests](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37026386994) | Windows / Ubuntu success；完整测试和 first-party rule gate |
| [Package integrity](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37026387269) | Windows / Ubuntu success；wheel/sdist、完整性、clean venv 实际安装与新能力 |
| [Compliance](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37026387193) | success |
| [Standalone artifacts](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37026387343) | windows-x64 / linux-x64 / macos-x64 / macos-arm64 全 success；归档、真实 MCP、managed engine、OSV offline fallback及新增 --fix-verify 原生SDK合成验收 |

安全边界：本机新 scanner/SDK fixtures 全离线；没有 Jeepay修改、旧 scan/benchmark/ground truth覆盖、外部模型/源码上传、目标构建或生产操作。公网交付连接限 GitHub同步/推送/CI状态读取；既有CI正常联网取得构建依赖/engine/漏洞数据库并扫描其合成样例，不代表获授权上传目标源码。没有更改现有 pre-commit，也没有实施新 Hooks。

仍待验收：实际宿主新连接下“检查→继续第一项→修复它→自然反馈”的连续 UX；三位未参与开发的开发者（用户当前无法安排）；独立人工真值和质量统计。ground truth 保留 UNREVIEWED/null、指标 NOT_MEASURED。Scanner复查只证明原规则和文件，不承诺业务/生产完全修复；当前Secret/IaC原check执行清单和离线POM图不足的保守状态继续生效。本轮完成推送后停止，Hook Integration Planned / NOT_STARTED。

## AL. Codex MCP Tool Hook POC

日期2026-10-03；从干净`feature/runtime-mvp` / `7a38593fb795cec4d7d09291f33f389430df8dba`开始。仅增加MCP transport，原HookCoordinator/hook_state/CodexHookAdapter与command host-event保留。用户报告Windows Codex command runner因0x80131506失败；这是用户实机报告，不能把原CLI验收成功当成Host通过。

本轮实际读取[OpenAI官方Hooks文档](https://learn.chatgpt.com/docs/hooks)的MCP tool hooks、matcher、common input/output及PostToolUse段落。使用type=mcp_tool、已连接server名称ai_security_runtime、tool=handle_hook_event、对象input、timeout秒、statusMessage；使用整值${hook_event_name}/${cwd}/${session_id}/${tool_name}模板。apply_patch规范名称兼容Edit/Write matcher。只取必要字段；不取tool_input/response、source、transcript、model、Secret或不需要的turn_id/tool_use_id。生成文件见[hooks.json](examples/codex-mcp-hook-poc/hooks.json)。

工具schema：四个必填string字段`event/workspace_path/session_id/tool_name`，additionalProperties=false。仅event=PostToolUse及apply_patch/Edit/Write；SDK错误类型/缺字段/多余字段fail closed，验证错误不回显输入值。语义不符、未绑定/未展开模板、越界或检查异常返回INCONCLUSIVE/UNKNOWN/scanner_run=false。必须有服务端SECURITY_RUNTIME_WORKSPACE绑定，声明cwd绝对且先进行词法containment，拒绝外部/UNC声明后才允许文件系统/Git访问；链接路径继续拒绝，最终Git root必须等于绑定。有效声明调用唯一HookCoordinator FILE_CHANGED，所有budget/offline/redaction/family/coverage语义不变。

structuredContent返回status、coverage、scan_id、scanner_run、new/persisting/resolved_families、additional/removed_occurrences、duration_ms、reused/debounced、baseline_available、last_check_status（若有）、execution及简短Hook输出。text content只包含systemMessage与hookSpecificOutput（hookEventName=PostToolUse、additionalContext为固定metadata/count JSON）。不返回families/Secret/源码/错误原文；不发decision:block、continue:false、suppressOutput或updatedMCPToolOutput。核心没有actionable/review counts，POC不制造这些字段或重新判断风险。

### 本地验收与真实Host边界

新工具+原command/core targeted首轮90 passed（58.53秒）；补入真实stdio测试后新增POC 23 passed（20.28秒）；修正旧SDK固定13工具断言后，task_fix+POC 49 passed（30.70秒）。首轮full offline为598 passed /1 failed /6 skipped /6 subtests（207.23秒），失败仅来自旧test_task_fix.py硬编码总数13；改成既有REQUIRED_GUIDANCE_TOOLS子集校验，保留全部原required工具要求，没有降低Runtime契约。修正后599 passed；再加入2项外部/UNC声明前置拒绝测试后的**最终full offline：601 passed /6 skipped /6 subtests passed（174.14秒）**。6个skip均为test_e2e_real.py要求Semgrep/Gitleaks/Trivy同时在PATH而本机未满足，不能算通过；新增25个POC cases全部通过，原command Hook/core测试不回归。

实际本地MCP stdio连接（未mock Scanner）发现14工具，PostToolUse声明→原Coordinator→离线Scanner：BASELINE_ESTABLISHED、scanner_run=true、最终5012ms（前次6216ms）、当前quick scope coverage FULL、所有family counts=0；相同快照NO_CHANGE/reused、scanner_run=false；外部cwd INCONCLUSIVE/UNKNOWN。源文件hash不变；model/network/source_modified/target_build均false。未使用command Hook runner或每事件security-check.exe，没有观察到0x80131506。详见[真实协议证据](codex-mcp-hook-poc-evidence.json)。**该SDK显式调用不是Codex Desktop原生自动Hook触发，也没有证明Desktop消费systemMessage/structuredContent/text的路径。fresh actual Host trial仍PENDING。** FULL仅指本次quick适用能力scope，不表示全仓/依赖/人工安全结论。

wheel/sdist实际构建、POC模块入包、check_wheel、licenses --check-distribution及generate_notices --check通过。没有新增scanner/rule/policy，没有目标build、自动补丁、模型调用、在线解析或源码上传。原项目.codex/hooks.json byte hash `63c700f13f68b26fb8e79a7090ff74326a5959e53db724f901c9d1f5524d9993`保持；只在独立可丢弃fixture放置MCP POC项目配置，未替换原command配置。包版本/能力契约仍0.3.1/developer-guidance-v0.3。

### Fresh Codex Desktop试用（尚未执行）

本机已准备可丢弃Git项目：`C:\Users\Administrator\Desktop\ai-security\Ai-security-check\.security-runtime\codex-mcp-hook-poc-project`。该项目.codex/hooks.json实际由生成命令输出，只有PostToolUse MCP handler；config.toml指向本机当前editable Runtime并显式绑定该fixture，独立state。安装/生成不自动批准Host trust。本轮没有创建或伪造新Codex聊天。

1. 在Codex Desktop打开上述目录作为项目，查看并信任该项目的MCP及Hook定义。确认Hooks已启用，ai_security_runtime连接成功、能发现handle_hook_event；旧连接没有新工具时断开/重连并刷新。不要把仍运行旧wheel/native的进程当成本次源码；如需更新，只更新实际配置运行的环境。当前fixture指向本机editable环境。
2. 开启全新聊天，只发送：“新增一个普通Java Service文件，只修改代码，不主动运行security-check或安全扫描。”通过apply_patch/Edit/Write修改才能命中本POC matcher；shell写文件不在matcher中。不要让Agent显式调用handle_hook_event冒充自动触发。
3. 观察PostToolUse自动MCP调用handle_hook_event、advisory/systemMessage和返回scanner_run。第一次应建立BASELINE_ESTABLISHED（不把既存候选归因为NEW）；Scanner成功与否仍以last_check_status/coverage/execution为准，缺engine不自动下载。保留Host事件与metadata/count作为验收依据，不能保存源码、tool_response或Secret。若没有自动事件/连接未就绪/输出未消费，记失败或Pending，不能用SDK结果代替。
4. 要证明绕过command transport，确认这个试用项目只加载MCP POC handler且没有其它user/plugin/managed command hooks参与本轮；官方说明匹配的多源Hook可同时运行，增加MCP handler不会覆盖原command。无需删除原仓库command支持。当前项目fixture配置只生成MCP handler，仍须在Host核对实际有效配置。
5. 成功须同时满足：用户未请求扫描、Host自动触发、Coordinator确实检查、Host收到advisory、不运行command Hook runner、未出现0x80131506。当前这些Host条件尚未同时实际执行。

需要重新生成通用JSON时，在仓库目录执行：

```powershell
.\.venv\Scripts\security-check.exe hooks generate-mcp-poc codex --json
```

这是纯输出命令，不写当前.codex/hooks.json；任何环境生成的JSON相同，不嵌入本机源码/绝对路径。回滚POC时仅移除试用项目PostToolUse中statusMessage为`AI Security Runtime [mcp-hook-poc]`的handler，重新加载Host；不运行原command registry的remove来假定它能删除POC。原仓库command hook和其它用户配置保持。代码可通过独立POC commit的git revert回退；不reset/clean当前工作区。

Pending：fresh Desktop自动触发及UI/context消费；原Windows command Host runner问题；Cursor真实Host trial；其它Host schema资料；三位真实开发者试用；独立ground truth UNREVIEWED/null、质量NOT_MEASURED。Deep Audit、Joern、watcher、新scanner/policy、自动修复/build及SessionStart/Stop迁移未开始。

## AK. Host-agnostic Hook Integration v0.1

日期2026-10-02→03（Asia/Shanghai）；干净起始/ff-only 同步 `8a36b3884a7d25cfb7f75c3405df727909ed1c90`，feature/runtime-mvp。前置 eq-v1 / Developer Fix & Verify 已通过 AJ，因此本轮正式实现获明确授权。旧 AI前置失败/AJ历史保留。本轮代码提交/最终文档HEAD、最终完整门禁、native/CI证据将在 AK.1追加，当前不将未完成门禁记为成功。

现有基线508 passed /6 skipped /6 subtests，133.17秒（整体133.71）。首批核心32 passed（21.98秒）；加入CLI/Codex后52 passed（29.22秒），旧equivalence/task_fix47 passed（9.78秒）；后续100项相关定向（38.94秒），Cursor/配置定向21 passed（8.22秒）。首轮full offline568 passed /6 skipped /6 subtests，161.42秒；随后增加配置回滚/本地排除测试及并发锁，最终完整回归另记，不拿此结果覆盖最终code gate。实际曾因测试夹具make参数不匹配/巨大参数id失败，已修正；最终通过数独立记录。

可重复 `scripts/hook_acceptance.py` 使用可丢弃 Git Java项目，真正本地 Semgrep 1.178.0 /Gitleaks 8.30.0，没有 Jeepay编辑/扫描或目标构建。SessionStart baseline、安全编辑0 NEW、首次危险家族NEW、100→110 PERSISTING、1→2 additional=1、2→1 removed=1且未resolved、全部安全替换才resolved、Stop复用与同snapshot NO_CHANGE均通过。实际generated Codex shell command 从含空格与&目录的子目录执行，通过JSON stdin/输出；原precommit内容保持quick --staged。这是CLI/配置/引擎链路测试，不是Codex真正事件dispatcher或自然用户试用。

当前源版性能样本（非SLA）：snapshot-only 206ms；NO_CHANGE 311ms；rapid FILE_CHANGED 232ms /DEBOUNCED；small quick 6379ms；Stop复用 299ms；Stop在rapid变更后收敛 5323ms。NO_CHANGE/DEBOUNCED/REUSED都没有engine process；snapshots仍要读有界文件/Git，不能承诺所有项目相同耗时。

测试覆盖 unstaged/staged/untracked、index变化、同文件内容变化、移动/改名/删除保守状态、所有计数变化、不同rule/同line旧fp collision、Secret2→1不存原值/证据/credential hash、坏/过大state、路径越界/符号链接、shell符号文件名、workspace隔离、并发edit/stop单飞、崩溃锁释放、预算与during-scan变更、旧失败缓存仍FAILED、配置未知字段/MCP保留/idempotent/repair/remove/invalid fail-safe、CLI advisory exit0及异常脱敏。平台权限导致无法创建symlink时测试明确skip，不将skip作为通过。

| Host | Runtime 适配/配置状态 | 真实宿主验收 |
| --- | --- | --- |
| Codex | IMPLEMENTED；schema验证、CONFIG_ONLY、stdin/生成命令/CLI | fresh session PENDING |
| Cursor | IMPLEMENTED；schema验证、CONFIG_ONLY、协议/安全merge单测 | 实际Cursor事件/UI PENDING |
| WorkBuddy桌面 | MANUAL_CONFIGURATION_REQUIRED；中立commands | NOT_RUN；不能复用CodeBuddy CLI schema |
| Kiro | MANUAL_CONFIGURATION_REQUIRED；中立commands | NOT_RUN |
| Qoder | MANUAL_CONFIGURATION_REQUIRED；中立commands | NOT_RUN |

官方来源（2026-10-02实际访问）：[OpenAI Hooks](https://learn.chatgpt.com/docs/hooks) 确认本地project hooks.json、command事件/stdin/stdout和trust；[OpenAI config basics](https://learn.chatgpt.com/docs/config-file/config-basic) 确认trusted project层；[Cursor Hooks](https://prod.cursor.com/docs/hooks) 确认version1及events/workspace_roots/conversation_id。WorkBuddy官方可取得的[CodeBuddy CLI plugin docs](https://www.workbuddy.ai/docs/zh/cli/plugins-reference)不证明桌面生命周期。未生成未确认schema。project hooks/config创建不是自动授权Host信任，Runtime不修改trust或关审批。

### 本地试用与实际 Host Pending

在当前仓库根目录 PowerShell，用本机已有同一 editable Runtime：

```powershell
.\.venv\Scripts\security-check.exe hooks install codex --path . --json
.\.venv\Scripts\security-check.exe hooks status --path . --json
.\.venv\Scripts\security-check.exe hook session-start --path . --host codex --session-id manual-trial --json
.\.venv\Scripts\security-check.exe hook file-changed --path . --host codex --session-id manual-trial --json
.\.venv\Scripts\security-check.exe hook agent-stop --path . --host codex --session-id manual-trial --json
```

相同snapshot最后两条应NO_CHANGE/REUSED_LAST_RESULT、scanner_run=false；首次无SessionStart则BASELINE_ESTABLISHED。要验证实际Codex自动触发，在宿主查看/信任本项目的Hook定义，重新加载后新会话，在可丢弃Gitfixture让宿主编辑，再检查事件反馈；当前开发聊天不能伪造为fresh trial。CLI可以直接执行受限本地quick，模型不参与。尚未安装Semgrep/Gitleaks时报告真实UNAVAILABLE/PARTIAL，不自动联网下载；安装引擎是另一个显式本机操作。移除配置用 `hooks remove codex --path .`，不删用户MCP/其他hooks。

安全与限制：默认Hook不加载第三方scanner plugin、无依赖在线解析/模型/源码上传/目标构建/源代码写入/自动补丁/daemon/生产操作；状态仅HMAC/安全家族与坐标计数，不存EvidencePacket/提示词/模型回复。eq-v1不能证明exact instance movement；new family只代表当前quick scope新增观察，不证明由某次edit引入。Secret detector缺执行证明时缺席unknown；scanner失败/部分scope不报resolved，last_check_status与coverage保留。独立ground truth UNREVIEWED/null、质量NOT_MEASURED，三位开发者Pending、Jeepay与冻结资料未改。


### AK.1 最终本地门禁（2026-10-03）

从额度中断前的未提交实现继续，未 reset/clean 或重新实现。基线 508 passed / 6 skipped / 6 subtests passed；中断前全量 570 passed。本轮交付复核仅补充损坏快照嵌套容器的类型校验及6项恢复测试：专项68 passed（42.19秒）；最终完整离线 **576 passed / 6 skipped / 6 subtests passed（168.31秒）**。跳过单列：`tests/test_e2e_real.py` 的6项旧测试要求 Semgrep/Gitleaks/Trivy 同时在 PATH，本机未满足；不能称为这些用例已通过。

最终源码实际 Scanner fixture 通过：Semgrep 1.178.0 / Gitleaks 8.30.0；安全编辑无NEW，行号移动PERSISTING，1→2/2→1记录occurrence变化，完整原规则/文件成功检查下全部移除RESOLVED，同快照Stop复用且没有engine process。实际生成的Codex shell命令已从含空格与`&`的项目路径/子目录执行，通过JSON stdin适配；这不是宿主自动触发验收。见 [源码实际证据](hook-synthetic-evidence.json)。

该次测量：snapshot 146ms、NO_CHANGE 205ms、小quick 5849ms、快速编辑200ms/DEBOUNCED、Stop收敛5018ms、重复Stop209ms。仅为本地样本，不是性能SLA。

wheel/sdist构建、check_wheel、licenses --check-distribution、generate_notices --check通过；离线全新Runtime安装通过。进一步实际执行 `scripts/verify_package.py` 的完全隔离clean venv（system-site-packages=false），依赖通过pip公开包索引/缓存取得，CLI/version/许可证/规则包/Hook模块/MCP required subset及安装后baseline/Stop/配置安装删除全部通过（17.48秒）。包获取允许联网，Hook/Scanner没有公网查询，没有上传目标源码。

本仓库项目级 `.codex/hooks.json` 已实际生成 SessionStart/PostToolUse/Stop 命令。install/status/repair/remove/reinstall全部通过，repair与重装前后字节一致；remove仅移除Runtime所有的配置，最终保留安装，并使用本地Git exclude排除机器路径配置。没有自动批准Codex trust，也没有改动宿主MCP配置。**fresh actual Codex host trial未执行，PENDING**；需宿主审阅并信任配置后启动新会话。

Native与本轮新CI结果在后续AK.2及 [交付证据](hook-delivery-evidence.json) 中补全，不能用旧Fix & Verify CI代替。三位开发者试用Pending；独立ground truth仍UNREVIEWED/null，质量NOT_MEASURED。


### AK.2 最终分发与新CI（2026-10-03）

起点 `8a36b3884a7d25cfb7f75c3405df727909ed1c90`；初次Hook实现 `40d9905b1ddb8fbac93fd2a31ba2f3075f3cb6bd`；最终实现（含实际CI发现的验收修正）`c1d42552d63596790bfba6eaadf206bffae754f2`，均已推送feature/runtime-mvp。保留中断工作区，不重新实现。修正后最终完整离线576 passed / **6 skipped** / 6 subtests passed，155.59秒。6项跳过原因见AK.1，不计通过。

Windows standalone重新构建、打包、archive/许可证/实际MCP smoke及实际native Hook生命周期通过；包内source_commit=c1d42552d63596790bfba6eaadf206bffae754f2。SHA256 `a540576f9928344d8d7ee545573cd0d5469fb788955b81c65d93fa643c6ae28b`。旧包在本地备份，未发布tag/release。见 [native真实证据](hook-native-evidence.json) 和 [完整交付记录](hook-delivery-evidence.json)。wheel/sdist/package integrity、完全隔离clean venv和合规的本地门禁通过；最终CI再次从当前HEAD构建发行物并执行clean install。

最终implementation HEAD的新CI，全部success：

| Workflow | 结论 | 作业 |
| --- | --- | --- |
| [Runtime tests](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37055866008) | success | Runtime tests (ubuntu-latest): success; Runtime tests (windows-latest): success |
| [Package integrity](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37055865954) | success | Package integrity (windows-latest): success; Package integrity (ubuntu-latest): success |
| [Compliance](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37055865969) | success | Compliance: success |
| [Standalone artifacts](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37055866181) | success | Standalone artifact (windows-x64): success; Standalone artifact (macos-arm64): success; Standalone artifact (linux-x64): success; Standalone artifact (macos-x64): success |

Standalone四平台均实际执行managed engine准备、archive/MCP、既有offline OSV fallback/Fix & Verify，以及新增实际native Hook fixture；不是只构建或引用旧CI。

首轮CI真实记录保留：

| Workflow | 结论 |
| --- | --- |
| [Runtime tests](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37055129778) | failure |
| [Package integrity](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37055129812) | success |
| [Compliance](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37055129736) | success |
| [Standalone artifacts](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37055129817) | cancelled |

首轮Runtime Linux失败：测试patch共享time.sleep，误拦截POSIX subprocess.wait的内部轮询；Windows通过。已把“不sleep”守卫限于Coordinator模块，未改变生产代码。首轮Standalone arm64失败：既有OSV fixture强制要求stderr进度，但scan在renderer现有0.5秒延迟前完成，可合法静默；保留全部FULL/active_provider/provider_role/primary failure/CLI/MCP断言，记录progress_visible。实际Windows native OSV fixture再次通过。首轮Standalone Windows/Linux通过、macOS x64尚运行时因修正push被现有concurrency取消，整体cancelled，绝不记为四平台通过；第二轮四平台已全通过。

第二轮Windows第一次准备Gitleaks时报PermissionError（job 111000314144），尚未进入Hook fixture。没有证据证明具体文件占用来源，不称为已确认Defender问题；保留失败记录。在同一implementation HEAD上重跑失败作业，实际native/archive/MCP/managed engines/OSV/Fix & Verify/Hook全部通过后才记最终success，未跳过或修改gate。

| Host | Adapter实现/协议与配置验收 | 实际宿主自动触发 |
| --- | --- | --- |
| Codex | IMPLEMENTED；官方schema、stdin、实际生成shell命令VERIFIED；本仓库install/status/repair/remove/reinstall通过；安装状态CONFIG_ONLY | **PENDING，未执行fresh actual host trial** |
| Cursor | IMPLEMENTED；官方schema、协议和安全配置merge测试VERIFIED；配置能力CONFIG_ONLY，本仓库未安装Cursor配置 | PENDING |
| Kiro | MANUAL_CONFIGURATION_REQUIRED；自动adapter NOT_IMPLEMENTED；没有猜schema或写配置 | 未执行 |
| WorkBuddy桌面 | MANUAL_CONFIGURATION_REQUIRED；自动adapter NOT_IMPLEMENTED；没有挪用CodeBuddy CLI schema | 未执行 |
| Qoder | MANUAL_CONFIGURATION_REQUIRED；自动adapter NOT_IMPLEMENTED；没有猜schema或写配置 | 未执行 |

本仓库最终保留Codex项目配置，未自动批准trust，当前session未加载/触发该配置；不能从CLI成功推导host成功。宿主需review/trust后启动新会话，按AK中的步骤在可丢弃fixture实际试用。

安全边界：Hook仅现有离线quick SAST/Secret，ADVISORY；无Scanner公网请求/在线解析、无Runtime模型调用、无目标源码编辑/目标构建/自动补丁。只有公开Python依赖和CI发行引擎/数据库获取、GitHub git/Actions网络；不上传目标源码/Secret。开发只修改Runtime与可丢弃synthetic fixture，Jeepay/冻结benchmark/Raw/triage/task_ref/risk/coverage contract/人工标签原状。Secret状态与输出只保留安全metadata/count/coordinates，无Secret值、匹配行或凭证hash。

仍Pending：fresh实际Codex/Cursor host trial；Kiro/WorkBuddy/Qoder官方schema确认与自动接入；旧Jeepay普通意图UX刷新后复验；三位真实开发者试用。独立Ground Truth UNREVIEWED/null、质量NOT_MEASURED，未开展。后续阶段继续Planned，本轮完成后停止。


## AM. Smart Auto Remediation v0.1

2026-10-03，起点 `3d6611d7e94d80e9804ee526c6d35b809ca69c20`，feature/runtime-mvp，干净工作区。上一轮实际 Desktop Hook POC 的 PASS 由用户明确反馈，来源 USER_REPORTED；历史 AL/AK Pending 保留其当时含义。本轮 fresh same-turn Desktop auto-remediation 仍 **PENDING**。

新增 remediation_policy.py、remediation.py、remediation_guard.py、test_remediation.py、scripts/remediation_acceptance.py；扩展 Codex MCP transport、两现有 fix tools、用户级 CLI 和 host guidance。HookCoordinator/command adapters/pre-commit 未改变；fix/equivalence/triage/Raw/risk/coverage engine 未重写。新增 standalone archive 的可选 --remediation gate，在四平台既有 workflow 实际执行。

旧已交付 POC baseline：601 passed / 6 skipped / 6 subtests passed。本轮新增50项 deterministic tests 覆盖 policy、REVIEW/manual/modes、两次上限、closed/unrelated、删除/清空/抑制/ignored移动/config/business变动、原rule/file/pack/engine/partial/provider failure、只读prepare、无Source/Secret/token持久化、损坏状态与连接重启等。最终源码 full offline：**651 passed / 6 skipped / 6 subtests passed（260.36秒）**。

Skipped 单列：tests/test_e2e_real.py 第38/58/68/80/120/154行，三真实引擎 PATH 前提缺失，不记通过。另行使用已管理 Semgrep/Gitleaks 的真实 SDK/native/clean-wheel integration，原引擎 process observed=true。源码 SDK、clean venv 和 Windows standalone：baseline → NEW/AUTO_FIX/block → existing prepare → **driver 模拟宿主编辑** → Hook自动 VerificationService → SCANNER_VERIFIED_RESOLVED → existing verify → 无关编辑NONE，均PASS。metadata证据不保存fix packet source，详见三份 [SDK](smart-auto-remediation-evidence.json)、[clean-wheel](smart-auto-remediation-clean-evidence.json)、[native](smart-auto-remediation-native-evidence.json)；不能推导 Desktop 自动响应/同turn执行 PASS。

wheel/sdist 构建、现有 check_wheel/许可证分发/notices检查通过，新模块 bytes 与最终源码逐一相同；严格 clean venv 无 system-site-packages、安装 wheel 非 editable 并实际 SDK验证通过。包SHA/源码模块hash见 [acceptance metadata](smart-auto-remediation-acceptance.json)。本地 native 是 dirty implementation 工作区构建，version.json 的 source_commit 指向起点；新CI artifact 将使用实际提交HEAD，不混淆 provenance。

官方 [Hooks](https://learn.chatgpt.com/docs/hooks) 已复核 mcp_tool 同输出contract、PostToolUse decision:block/reason/systemMessage/hookSpecificOutput；Code mode 有副作用后的 promise rejection。AUTO_FIX反复反馈仅两次；NONE/RESOLVED/BEST_PRACTICE不block；不撤销原编辑。保留1秒cooldown：新session首次edit基线不是NEW；太快发现DEBOUNCED不宣称执行，SDK驱动明确模拟1.1秒编辑耗时。实际宿主连续编辑及feedback消费仍须验收。

独立本地TLS不变量 policy ACTIONABLE 明示source，不更改旧triage priority、AI verdict/exploitability或Raw；已有有效REVIEW、STALE、FAILED不自动提升。32KiB目标及200files/200dirs/401entries/2MB保留性预算，workspace外用户state，原provider/rule/file/pack完整证据和不变业务tokens/其他文件都是必要条件；删除/suppress/规则配置变化/移动未扫描路径不能Verified。prepare只读 attestation 在连接内，重启丢失则fail closed，不重置persistent attempt预算。

配置/决策schema、fresh现有 codex-mcp-hook-poc-project 试用步骤及唯一用户消息见 [Smart Auto 文档](SMART_AUTO_REMEDIATION.md)。现有fixture与项目/global command Hook未修改，不自动批准信任；MCP需重连刷新新版 schema/feature。

网络仅公开Python包依赖获取与GitHub分发/CI，不上传目标源码或Secret；Scanner force offline、Runtime模型未调用、Runtime未改目标、目标未build/执行、不自动commit/PR产品功能。Jeepay/benchmark/人工标签未改。三位试用Pending、独立Ground Truth UNREVIEWED/null、质量NOT_MEASURED；下一阶段均Planned，交付后停止。

### AM.1 提交与当前 CI

Implementation HEAD：`462633e8b5d4dcc730dba868bd9ac66e8bc40b37`，已推送 origin/feature/runtime-mvp，提交后工作区干净。本次全部新 CI 如下：

| Workflow | 结论 | 实际 jobs |
| --- | --- | --- |
| [Compliance](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37115455490) | success | Compliance: success |
| [Package integrity](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37115455478) | success | Package integrity (ubuntu-latest): success; Package integrity (windows-latest): success |
| [Runtime tests](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37115455480) | success | Runtime tests (windows-latest): success; Runtime tests (ubuntu-latest): success |
| [Standalone artifacts](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37115455499) | success | Standalone artifact (macos-x64): success; Standalone artifact (macos-arm64): success; Standalone artifact (windows-x64): success; Standalone artifact (linux-x64): success |

Standalone archive gate 包含 --full/--osv-fallback/--fix-verify/--hooks/--remediation；四平台均完成实际离线 native MCP grant、prepare、模拟宿主编辑、自动验证、verify 和无关编辑不重开。未声称 actual Codex Desktop same-turn 自动修复通过。

final docs HEAD 从 git log -1 --format=%H -- docs/PROJECT_STATE.md 取得（避免文档自引用SHA）；docs-only后续CI若触发在最终交付消息补充。实现源代码保持本次成功验证的同一HEAD，无未提交修改。

## AN. CONFIRM_REQUIRED Host Interaction v0.1

起点 `5965497e3a687dbe67fb3e86d367dfdc0059052a`，feature/runtime-mvp，工作区干净。本次用户明确回传：smart_auto真实 Desktop PASS（USER_REPORTED），原 ask_before_fix policy PASS / 主动确认 UX FAIL。本次新确认 real-host **PENDING**，尚未以实际 Desktop 验收闭环。

### AN.1 实现与本地验收

Core 产生独立固定确认 guidance 和有界 confirmation identity，Codex仅做官方 PostToolUse反馈映射；prepare/verify前必须经过明确选择，批准才有实际grant。workspace、host/session、family、原 scan/task、snapshot、policy/config revision、900秒TTL及连接绑定，引用一次消费，模式不更改；DECLINED 不删 Raw、不 suppression。原 Hook snapshot/cooldown/single-flight/multiset 和现有验证/覆盖/脱敏保持。Remediation core的state host显式传入，没有Cursor接入。

原已交付baseline651/6/6；新37项涵盖（含真实临时目录alias回归）固定反馈/主动询问指令、批准前无grant/legacy gate、批准后prepare/resolve/verify、拒绝/no-reprompt、snapshot/成员/family/mode/config revision、TTL/一次性/restart、越界与闭合schema、no source/Secret/prompt/token状态、恶意scanner prose不是指令、host中立状态键。原针对性137passed、CI修正后确认37passed，**final full offline 688 passed /6 skipped /6 subtests passed，355.00s**。command/MCP Hook、等价匹配、coverage/triage/verification全量回归保持。

Skipped单列：tests/test_e2e_real.py 的38、58、68、80、120、154行均需三真实引擎在PATH；六项未算通过。本轮其他SDK/native链路实际调用已托管Semgrep/Gitleaks离线Scanner，不据此将这些skip改为pass。

| 门禁 | 实际结果/来源 |
| --- | --- |
| wheel/sdist | PASS；4个改动模块字节与最终源代码一致 |
| Package integrity / licenses / notices | PASS |
| Strict clean venv | PASS；system_site_packages=false、无editable；实际MCP/Scanner四条模式/选择链路 |
| Local SDK | PASS；批准前gate、approve/prepare/宿主driver edit/自动Hook/显式verify；拒绝/no-reprompt；report_only无block；原AUTO不回归 |
| Windows standalone | PASS；实际native MCP及离线Scanner，同上四场景 |
| 新 CONFIRM_REQUIRED Desktop | PENDING；SDK/native的选择与edit均SIMULATED_BY_ACCEPTANCE_DRIVER |
| 三位试用 / 独立 Ground Truth | Pending / UNREVIEWED/null，质量NOT_MEASURED |

有界metadata证据：[源码SDK](confirmation-sdk-evidence.json)、[clean wheel](confirmation-clean-evidence.json)、[native](confirmation-native-evidence.json)、[测试/包hash与CI](confirmation-acceptance.json)。不存packet源码、Secret或用户prompt/transcript；确认本身不跑Scanner/目标edit/build/模型。local native在dirty修正实现构建，version.json.source_commit是初次implementation c21ccd8；不冒充修正commit artifact，最终CI artifact实际来自修正implementation HEAD。新的确认/修复验收强制离线；公共Python依赖、授权GitHub提交推送/CI及既有Standalone门禁的公开引擎/漏洞库获取可联网，没有项目源码/Secret上传Scanner/模型，没有Jeepay/benchmark/人工真值修改。

### AN.2 当前提交与 CI

Implementation HEAD：`73c0945c934fe82fef7323db9e10bfe938e3fc74`，已推送 origin/feature/runtime-mvp。以下全部为该HEAD的新run，jobs最终结论已实际读取：

| Workflow | 最终结论 | 实际 jobs |
| --- | --- | --- |
| [Compliance](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37126440623) | success | Compliance: success |
| [Package integrity](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37126440625) | success | Package integrity (windows-latest): success; Package integrity (ubuntu-latest): success |
| [Standalone artifacts](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37126440537) | success | Standalone artifact (linux-x64): success; Standalone artifact (windows-x64): success; Standalone artifact (macos-x64): success; Standalone artifact (macos-arm64): success |
| [Runtime tests](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37126440609) | success | Runtime tests (ubuntu-latest): success; Runtime tests (windows-latest): success |

Standalone四平台沿现有artifact gate执行新增确认批准/拒绝/report_only和原AUTO的实际native MCP及离线Scanner；宿主选择/edit仍模拟，新Desktop UX PENDING。final docs HEAD用git log -1 --format=%H -- docs/PROJECT_STATE.md获取；docs-only提交的Runtime/Package/Compliance在最终回复单列，不重复触发Standalone。

### AN.3 fresh real-host 门禁

完整步骤见 [fresh Desktop批准与拒绝](SMART_AUTO_REMEDIATION.md#fresh-codex-desktop批准与拒绝)：先在匹配状态目录切ask_before_fix，重连包含新工具/feature的MCP；新聊天普通编码安全baseline，再普通临时fixture编辑需求（既有cooldown）。同turn必须NEW/CONFIRM_REQUIRED →主动解释风险/行为变化→询问→等待，prepare/verify未调用、bypass未自动修。用户仅“允许修复”才confirm→prepare→宿主edit→自动Hook/RESOLVED→verify=SCANNER_VERIFIED_RESOLVED；独立case仅“不修”→DECLINED/源码不变/no-reprompt。保留真实工具调用metadata，不能手动发送Hook或追加修复提示来伪造自动询问。

此完整Desktop闭环真正执行前，**Policy feedback/Runtime protocol已自动化验证；CONFIRM_REQUIRED Host interaction PENDING**。原UX FAIL保留；smart_auto的用户回传PASS独立记账。完成交付后停止，其他阶段Planned。

### AN.4 首轮 CI 失败与修正

初次实现 `c21ccd80c405f34aa84e63e54645d8c2df7c9abd`，以下实际首轮run已完成；失败保留，不用文档替代修复：

| Workflow | 结论 | 实际 jobs |
| --- | --- | --- |
| [Compliance](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37125599164) | success | Compliance: success |
| [Package integrity](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37125599189) | success | Package integrity (windows-latest): success; Package integrity (ubuntu-latest): success |
| [Standalone artifacts](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37125599190) | failure | Standalone artifact (macos-x64): failure; Standalone artifact (macos-arm64): failure; Standalone artifact (linux-x64): success; Standalone artifact (windows-x64): success |
| [Runtime tests](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37125599187) | success | Runtime tests (ubuntu-latest): success; Runtime tests (windows-latest): success |

macOS原生验收在旧prepare_task_fix流程报KeyError: execution。新的task_gate在confirmation目录不存在时仍先检查所有parent links，macOS temp alias因此误判STATE_UNAVAILABLE；返回失败对象而非原准备包。修正为无catalog时保持旧流，存在catalog仍完整no_links/HMAC验证；真实目录symlink的37项确认回归证明两端分支，原Raw/risk/coverage未放宽。修正后全量688/6/6、包/合规/严格clean和Windows native复查通过；最终新四平台CI必须独立成功才算分发通过。

### AN.5 文档 CI 的实际外部阻塞

最终文档提交 eaafecc9c595b924940d272249a7ac7a08b26909 的Runtime/Package/Compliance实际failure，GitHub检查注解明确为付款失败或支出限额，未分配Runner、未执行步骤；文档CI验收 PENDING_RERUN_AFTER_ACCOUNT_RECOVERY。修正implementation 73c0945 的四类/四平台实际success不变，不把文档CI外部阻塞写为PASS。账号付款/支出设置未修改；恢复后重跑，无源码/coverage降级或workflow绕过。

| Workflow | GitHub conclusion | 实际执行 |
| --- | --- | --- |
| [Runtime tests](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37127149637) | failure | 账号billing/spending limit阻止启动，非测试执行失败 |
| [Package integrity](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37127149679) | failure | 账号billing/spending limit阻止启动，非测试执行失败 |
| [Compliance](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37127149611) | failure | 账号billing/spending limit阻止启动，非测试执行失败 |

工具实际读取三种workflow的失败注解，steps=[]、runner_name为空；GitHub未区分付款失败与限额哪一种。最后的记录文档提交仍可能受同一外部条件阻止，最终回复按实际新run列出；不循环提交制造绿色状态。恢复账号后可重跑当前HEAD的失败run。无需修改代码/风险/覆盖，也没有权限更改账号付款或增加支出。新的CONFIRM_REQUIRED Desktop门禁、三位试用及独立Ground Truth保持原真实状态，开发在此停止。


## AO. CONFIRM_REQUIRED PostToolUse Host Semantics Fix

### AO.1 真实 Bug 与 transport 选择

起点干净 `feature/runtime-mvp` / `9d2dbd539ce2ed3753bfd0420b9507aa20ae2ade`。用户真实 Desktop 回传：CONFIRM_REQUIRED policy 和 confirmation identity/TTL PASS；主动交互 PARTIAL；问题语义 FAIL（问成批准应用危险配置）；approve→repair、decline NOT VALIDATED。smart_auto Desktop PASS（USER_REPORTED）独立保留。新的确认批准和拒绝 Desktop trial 均 PENDING，不将本地模拟认作实机。

重新搜索并实际读取 [官方 Hooks 文档](https://learn.chatgpt.com/docs/hooks)，核对 PostToolUse decision/continue/stopReason/systemMessage/additionalContext 与 Code mode：副作用不撤回；block 会在执行后 reject promise；continue:false 会用反馈替换原结果继续模型，不 reject promise。因此只改 CONFIRM_REQUIRED，AUTO_FIX 原 block/reason 固定反馈不变；command Hook 保留。continue:false 本身不停止模型，主动询问和等待必须由宿主遵守 guidance 并在 Desktop 实测。

最终确认 Host text output（占位引用，非持久化真实 token）：

```json
{
  "continue": false,
  "stopReason": "SECURITY_REMEDIATION_CONFIRMATION_REQUIRED. The preceding file edit has ALREADY executed. Do NOT retry, re-apply, or repeat the insecure edit. ... 是否允许我修复这个安全问题？ ... WAIT ...",
  "systemMessage": "Security Runtime: the file edit already executed. Do not repeat it. Explain the risk and ask whether to remediate it, then wait.",
  "hookSpecificOutput": {
    "hookEventName": "PostToolUse",
    "additionalContext": "JSON-encoded bounded Hook summary including remediation.interaction, fixed guidance, impact_summary, confirmation_ref and exact task_ref"
  }
}
```

没有 decision:block/reason；structuredContent 同一字段同值，另含有界状态/覆盖/delta metadata。interaction = {phase: POST_EDIT_REMEDIATION_CONFIRMATION, edit_already_applied: true, requested_user_decision: REMEDIATE_SECURITY_FINDING, must_not_retry_previous_edit: true}。Core 不含 Codex控制字段，风险语义、覆盖、身份和授权生命周期唯一实现不变。原 MCP 15 tools/schema/0.3.1/developer-guidance-v0.3 保持。

固定 guidance 明示编辑已发生、风险来自已完成 edit、不得 retry/re-apply/repeat 或自动 revert，只询问是否修复风险，不问是否应用/保留/启用危险配置；解释 hostname 风险、默认校验可能拒绝不匹配端点和 ask_before_fix批准原因，主动问“是否允许我修复这个安全问题？”并等待。仅立即回答清晰修复问题的“允许”算批准，其他上下文先澄清。用户明确批准 → confirm true → AUTHORIZED/grant → prepare → 宿主局部 edit → 自动 Hook/resolved=1 → verify SCANNER_VERIFIED_RESOLVED，无第二条修复请求。拒绝 → confirm false → DECLINED，无 prepare/verify/edit/suppression/Raw删除，无关 edit 不 re-ask。

### AO.2 自动化与本地分发验收

前轮已交付 baseline **688 passed /6 skipped /6 subtests**（未重复跑旧 HEAD）。本轮针对性 **210 passed，368.48s**，新4项（Write/Edit/apply_patch实际文件副作用+明确确认字段/transport输出回归，以及允许歧义的固定指导）；原批准前gate、批准/修复/验证、拒绝/no-reprompt、身份/TTL/restart/snapshot/workspace/Secret/恶意prose案例保留，并增加批准但未prepare的verify拒绝断言。初次收集曾因新指导测试未声明模块参数setup而失败，已补齐fixture；最终全量 **692 passed /6 skipped /6 subtests passed**，pytest耗时 490.59 秒（门禁总耗时491.76秒）。command/MCP/equivalence/family multiset、旧授权和coverage/risk契约均回归。

6 skipped单列：tests/test_e2e_real.py 的38/58/68/80/120/154行，多引擎PATH前提未满足，未计通过。要求的21场景证据映射如下；复用生命周期测试，不另造模型语义模拟器：

| 场景 | 证据 |
| --- | --- |
| 1–4 post-edit/REMEDIATE/no-repeat/不暗示edit失败 | test_completed_host_edit_requests_repair_without_rejecting_or_repeating（Write、Edit、apply_patch） |
| 5–7 无AUTO grant/prepare与verify前置gate | test_confirmation_feedback_is_fixed_distinct_and_no_grant；test_preconfirmation_prepare_and_verify_fail_closed；MCP legacy gate |
| 8–11 授权/prepare/resolve/验证 | test_explicit_approval_prepares_and_mode_stays_ask；test_approved_edit_hook_and_explicit_verification；实际SDK/native原引擎 |
| 12–15 拒绝/no prepare/no verify/no re-ask | test_decline_keeps_raw_and_no_unrelated_reprompt；实际MCP decline proof |
| 16–17 原AUTO、report_only | test_remediation.py 原全套与4种mode/choice的实际SDK/native验收 |
| 18–20 family/equivalence、command、MCP | test_hook_runtime.py、test_hook_adapters.py、test_codex_mcp_hook.py和完整离线回归 |
| 21 package/compliance | wheel/sdist、check_wheel、licenses --check-distribution、notices --check、test_compliance.py |

| 本地门禁 | 实际结论 |
| --- | --- |
| wheel/sdist + package integrity | PASS；3个改动Runtime模块与源码逐字节相同 |
| Compliance | PASS；licenses、distribution、notices与全量合规测试 |
| Strict clean wheel venv | PASS；system_site_packages=false，无editable，实际MCP/离线Scanner四条链路 |
| Source SDK | PASS；text/structured continue/stopReason一致；危险源码保留至批准；原AUTO仍block |
| Windows standalone | PASS；重新构建，实际native MCP与离线Semgrep/Gitleaks四条链路 |
| Linux/macOS arm64/macOS x64本轮native | 以本轮新Standalone CI为准，未在Windows机器冒充执行 |
| Fresh Desktop批准/拒绝 | PENDING / PENDING；未实际执行，驱动选择/编辑是SIMULATED_BY_ACCEPTANCE_DRIVER |

有界metadata：[SDK](postedit-sdk-evidence.json)、[clean wheel](postedit-clean-evidence.json)、[Windows native](postedit-native-evidence.json)、[门禁与源码hash](postedit-acceptance.json)。不存源码packet/Secret/用户prompt/transcript；本地native在dirty实现构建，version.json.source_commit仍为starting HEAD，不能冒充本轮commit产物。最终CI按实际HEAD记录。新修复验收Scanner强制离线，用户选择与宿主edit模拟；Runtime不模型/target edit/build，公共包/GitHub delivery可联网，既有Standalone合成fixture门禁可取得公开工具/漏洞库，不上传源码/Secret给Scanner或模型。

### AO.3 fresh Desktop 实机门禁

具体可执行模式命令及普通编码prompt见 [fresh Desktop批准与拒绝](SMART_AUTO_REMEDIATION.md#fresh-codex-desktop批准与拒绝)。先重连当前版本MCP，在 **新 Chat + ConfirmationTlsTrial2.java** 安全baseline后另一次编辑引入bypass；原生自动Hook必须continue:false、edit_already_applied=true，并主动问是否修复风险。此时危险源码仍在，prepare/verify NOT CALLED，无重复应用或revert。900秒内仅“允许修复”→confirm true→AUTHORIZED→prepare→宿主edit→Hook RESOLVED=1→verify SCANNER_VERIFIED_RESOLVED。另 **新 Chat + ConfirmationTlsDecline2.java** 重复baseline/风险，仅“不修”→DECLINED、危险源码仍在、无prepare/verify；同session普通无关edit不再问该family。

只有两条真实Desktop链路都通过才可标整体PASS；仍问“应用危险配置”或声称先前edit失败即FAIL。当前无法用本会话的显式工具调用替代新Chat自动dispatch/真实用户选择，所以均PENDING。三位试用Pending，人工Ground Truth UNREVIEWED/null、质量NOT_MEASURED。没有修改Jeepay、用户fixture、冻结benchmark或人工标签，Secret rotation未执行。完成交付后停止，其余阶段Planned。

### AO.4 提交与本轮新 CI

Implementation HEAD `158a85db8aeb553f58926188aad112fe332cd45c` 已成功推送 origin/feature/runtime-mvp。以下全是本次提交实际新run；工具读取所有9个jobs的失败注解，runner_name为空、steps=[]，没有执行测试/构建：

| Workflow | GitHub conclusion | 实际执行 |
| --- | --- | --- |
| [Runtime tests](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37129799118) | failure | 未启动；付款失败或支出限额 |
| [Compliance](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37129799121) | failure | 未启动；付款失败或支出限额 |
| [Package integrity](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37129799144) | failure | 未启动；付款失败或支出限额 |
| [Standalone artifacts](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37129799107) | failure | 未启动；付款失败或支出限额 |

GitHub注解为“recent account payments have failed or your spending limit needs to be increased”，没有区分哪种账号条件。当前交付 **CI BLOCKED / PENDING_RERUN_AFTER_ACCOUNT_RECOVERY**，四平台Standalone也没有本轮CI产物，不能引用AN历史success当本轮通过。账号付款/支出设置未修改，无权限擅自增加支出；没有workflow绕过或coverage/风险降级。恢复后重跑本次实际失败run并核实jobs/产物；当前只记录真实外部阻塞。本地Windows native/clean/package/full通过独立有效。

最终文档HEAD通过 `git log -1 --format=%H -- docs/PROJECT_STATE.md` 获取；随后docs-only提交也会触发Runtime/Package/Compliance，它们的实际新结论在最终交付回复单列，不能预写PASS；Standalone仅由本次implementation改动触发。Desktop批准/拒绝及人工质量待办保持真实PENDING。


## AP. CONFIRM_REQUIRED Cross-Turn Confirmation Persistence Fix

### AP.1 最新真实反馈与确定性根因

起点干净 `feature/runtime-mvp` / `1a92dff6d86dc688f5b0a4fbecb56da109a8c4f7`。用户真实Desktop回传的post-edit语义、edit_already_applied、主动风险解释、询问修复而不是批准危险编辑均PASS（USER_REPORTED）；用户下一回合仅“允许”，旧确认返回REFRESH_REQUIRED，未授权/未修复，approval handoff FAIL。原smart_auto完整实机PASS保留。本轮新Desktop批准/拒绝都PENDING。

旧实现的确定性缺陷：Pending虽已HMAC落盘，安全authority仍是发行Service的self.confirmations/monotonic deadline，新Service丢字典即拒绝。真实Host旧通用REJECT没有细分底层证据，本轮不猜Codex内部对象/进程/连接模型，不宣称所有旧错误唯一由缓存缺失造成。修复是跨tool/用户turn的signed persistent handoff，非Host cold-start重构。

### AP.2 持久化、安全边界与诊断

Pending只保存有界metadata：phase、confirmation_hash、confirmation_issued_at_epoch、confirmation_expires_at_epoch、workspace_id、host_id/session_id hash与host_session_namespace、family_key、task_ref、origin_scan_id、snapshot、mode/policy_version/config revision binding、target和source/preservation HMAC、原attempt/phase信息。opaque高熵token只返给宿主，持久化只有hash；不保存源代码、Secret、prompt/transcript、Scanner raw prose或token plaintext。HMAC覆盖完整record，当前workspace OS锁序列化读/检查/一次消费/保存；不引入第二套Hook逻辑。

Runtime发行epoch时间，expires-issued=900秒，确认要求now在[issued,expires)，有效期不超过900且类型/finite值正确。重连、重复Hook或confirm不延长。缺TTL/namespace的旧格式Pending刷新，不自动迁移。前跳到expires过期，回退到issued之前拒绝；本机OS墙钟不是独立可信时间，不能保证检测发行后的所有小幅回拨。批准grant保持连接内authorized hash与prepare attestation、原monotonic剩余期限，另外检查原epoch有效性，C重启不能恢复。

确认authority=opaque原ref+原workspace/host-session namespace下的HMAC状态+hash match+PENDING phase+TTL+原snapshot/policy+原task/scan/member/rule/family+source/preservation proof。成员读取后再次复核，任一变化刷新，不重定向T01/新scan，不放宽coverage或风险。引用是绑定原namespace的bearer capability，不独立认证当前人/调用者；approval_trust仍UNTRUSTED_HOST_REPORT。A退出后同state的B可确认有效Pending；AUTHORIZED/DECLINED后C重放仍ALREADY_CONSUMED。并发消费只发一个grant；其他请求BUSY或ALREADY_CONSUMED。拒绝保留源码/Raw/triage，不suppression，不prepare/verify，无关edit不再问。

Pending最多32/workspace，重启不能重置；发新Pending时加上本连接有效authorized hash检查32，授权hash仍最多32/连接。16families/session、64sessions/workspace、262144bytes/state、原snapshot/cooldown/single-flight/family multiset、脱敏/UNTRUSTED_CODE/覆盖保持。prepare/verify服务没有重构，AUTO_FIX/command Hook/continue:false确认输出未改。

安全diagnostic_reason只用固定枚举：STATE_NOT_FOUND、REFERENCE_INVALID/MISMATCH、NAMESPACE_MISMATCH、EXPIRED、SNAPSHOT_CHANGED、POLICY_CHANGED、TASK_CHANGED、SOURCE_GUARD_CHANGED、STATE_INVALID；不返回path/token/源码/Secret/exception文本。旧通用用户refresh reason保留，MCP输入仍闭合，无client expiry字段。

### AP.3 本地实际验收

前轮baseline692/6/6，未重跑旧HEAD。本轮targeted **172 passed（391.57s）**；后补并发消费和客户端expiry等输入focused **6 passed**（含既有敏感值回归）；最终full offline **724 passed /6 skipped /6 subtests passed，615.42s**。新增32项persistence cases，替换旧“restart必否定Pending”case，并增加1项客户端expiry拒绝。覆盖A→B批准/拒绝/重放、重启Hook不失效/不续期、TTL/回拨/非法deadline、HMAC各字段tamper、source/unrelated/snapshot/task/family/scan/mode/config revision、foreign workspace/ref/namespace、32Pending预算和并发一次消费；批准grant restart失效的旧要求保留。新API与原command/MCP/equivalence/risk/coverage全量回归。

六项skipped单列：tests/test_e2e_real.py:38/58/68/80/120/154需多引擎PATH；未计通过，其他SDK/native实际managed Semgrep/Gitleaks不替代该前提。

| 本地门禁 | 真实结果 |
| --- | --- |
| wheel/sdist/package | PASS；2个改动Runtime模块与源码逐字节相同 |
| Compliance | PASS；licenses/distribution/notices及全量合规测试 |
| Strict clean wheel install | PASS；无editable/system-site；实际MCP/Scanner原4模式链路和跨进程批准/拒绝 |
| Source SDK | PASS；A真实stdio退出、B重新启动、C重放；批准完整prepare/edit/Hook/verify |
| Windows native | PASS；重新构建，实际native MCP进程重启与离线Scanner；不是Desktop模型交互 |
| 真实human choice/Host edit | 本地均SIMULATED_BY_ACCEPTANCE_DRIVER，非实机人类选择 |
| Fresh Desktop批准/拒绝 | PENDING / PENDING，未实际执行 |

有界证据：[SDK](persistence-sdk-evidence.json)/[实际restart](persistence-sdk-restart-evidence.json)、[clean wheel](persistence-clean-evidence.json)/[restart](persistence-clean-restart-evidence.json)、[Windows native](persistence-native-evidence.json)/[restart](persistence-native-restart-evidence.json)、[门禁/hash/CI](persistence-acceptance.json)。跨进程每条case启动A/B/C三个真实OS server进程，原TTL不变、C replay拒绝；批准case B实际原Scanner证明RESOLVED，C原grant失效；拒绝case源码仍unsafe、未prepare/verify/no-reprompt。原4模式链路继续验收，Standalone原--remediation gate增加独立--cross-turn-only步骤，各保持180秒离线fixture timeout，没有扩policy/scanner/Functional Verification。

本地native在starting HEAD上dirty实现构建，source_commit为starting HEAD，不冒充本轮immutable CI artifact。Runtime不模型/源码edit/目标build，源代码编辑与选择由driver模拟；Scanner离线，公共包/授权GitHub delivery可联网，既有Standalone合成fixture门禁可获取公开引擎/漏洞库，不上传项目源码或Secret给Scanner/模型。Jeepay、用户fixture、冻结benchmark/人工标签未修改，Secret rotation未执行；Ground Truth UNREVIEWED/null、质量NOT_MEASURED、三位试用Pending。

### AP.4 fresh Desktop批准与拒绝

模式命令/项目配置和完整普通prompt见 [fresh Desktop步骤](SMART_AUTO_REMEDIATION.md#fresh-codex-desktop批准与拒绝)。在ask_before_fix、新Chat与 **ConfirmationTlsTrial3.java** 建立安全局部JDK HTTPS baseline后，另一次普通编辑加入always-true verifier；PostToolUse自动产生CONFIRM_REQUIRED，明确编辑已完成并问是否修复。危险源码仍在，prepare/verify未调用。用户仅 **“允许”**，应confirm true→AUTHORIZED→prepare→最小edit→自动Hook/resolved=1→verify SCANNER_VERIFIED_RESOLVED，无第二条修复请求；只有snapshot/policy/task/TTL真实变化才可拒绝，不能因实例重建本身拒绝。

独立新Chat **ConfirmationTlsDecline3.java** 重复baseline与风险，主动问题后仅 **“不修”**，confirm false→DECLINED、源码仍危险、无prepare/verify；随后同session普通无关edit不再问。只实际完成用户下一回合批准→修复→验证才标新的approval real-host PASS；当前PENDING，拒绝也PENDING。原问题语义USER_REPORTED PASS及旧approval FAIL保留。交付后停止，不开始下一阶段。

### AP.5 本轮实现与新CI

Implementation HEAD `a88c84071d823cd784ca39569bacadef03c067dd` 已推送 origin/feature/runtime-mvp。本轮实际新run全部completed/failure，9个jobs的runner_name为空、steps=[]；工具读取每项失败注解，均为付款失败或支出限额，未开始测试/构建：

| Workflow | GitHub conclusion | 实际执行 |
| --- | --- | --- |
| [Compliance](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37133137074) | failure | 无Runner/steps，账户条件未启动 |
| [Runtime tests](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37133137060) | failure | 无Runner/steps，账户条件未启动 |
| [Package integrity](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37133137063) | failure | 无Runner/steps，账户条件未启动 |
| [Standalone artifacts](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37133137093) | failure | 无Runner/steps，账户条件未启动 |

结论 **CI BLOCKED / PENDING_RERUN_AFTER_ACCOUNT_RECOVERY**；GitHub未区分付款失败与限额哪一种。未修改账号设置、增加支出、降级coverage或绕过workflow。账户恢复后重跑这些本轮失败run，核实实际jobs和Standalone四平台新产物，不能引用旧AN success证明本轮通过。本地Windows native/clean/package/full门禁独立有效；当前其他三个平台未在本轮执行。

最终docs HEAD用 `git log -1 --format=%H -- docs/PROJECT_STATE.md` 核对。后续docs-only提交也触发Runtime/Package/Compliance，实际新结论在最终回复单列，不能预写PASS；Standalone不由docs-only再次触发。新Desktop批准/拒绝仍PENDING，其他阶段Planned，交付后停止。

## AQ. Functional Verification v0.1

### AQ.1 当前能力与真实反馈

起点干净 feature/runtime-mvp / ca4a773def7e3c3deb019c0c309994ebd06a6971。用户在本轮明确回传 smart_auto、CONFIRM_REQUIRED 批准→修复→verify、拒绝→DECLINED 三条真实 Desktop 完整链路 **PASS（USER_REPORTED）**；此前 AP/AO/AN 的 Pending/失败保留为历史。新功能 Desktop/host 链路不冒充已通过。

独立 FunctionalVerificationService、FunctionalVerifierRegistry 与 Maven/Gradle/Node/Python 四个 provider 已实现；prepare/run 两个可选 MCP 工具复用原 RemediationService 的 signed CLOSED/SCANNER_VERIFIED_RESOLVED proof，继续校验原 task/member/授权/TTL/policy/source/preservation/snapshot。无 Host supplied status/command，普通 edit、DECLINED/未授权/仍存在均不跑功能命令，HookCoordinator 无 build/test，原安全验证不与测试耦合。

检测/计划 **IMPLEMENTED + VERIFIED**；执行 contract/runner **IMPLEMENTED + deterministic tests VERIFIED**；Linux hardened sandbox **IMPLEMENTED / PENDING_RUNTIME_ACCEPTANCE**；Windows/macOS 缺强制 backend → NOT_AVAILABLE。缺 bubblewrap/cgroup 仅影响执行前提，不把整个 detection/plan 标不可用。Runtime 只有在安全前提成立后才执行真实命令，不降级不受控 shell，不搭建企业 sandbox infrastructure。

固定 command_id/argv（shell=False）；原 scripts/config/manager 与 executable hash 绑定；含 ignored 的全 workspace keyed snapshot，no_links/containment；隔离源投影只读、内存限额 tmpfs build outputs、网络 namespace、cgroup 32 processes/1GiB/no swap。每步60秒/计划180秒/合计stdout+stderr64KiB/最多9步，超时/输出/资源/启动错误 INCONCLUSIVE；不返回/保存原输出，只 keyed hash 与固定状态摘要。完整执行边界、结果 schema 与命令见 [Functional Verification](FUNCTIONAL_VERIFICATION.md)。

Functional PASSED/FAILED/PARTIAL/NOT_AVAILABLE/INCONCLUSIVE 独立于 Security；实际 coverage BUILD_AND_TEST/TEST/TYPECHECK/BUILD 等，build/lint alone PARTIAL。安全未核实为 SECURITY_NOT_VERIFIED；安全已核实分别 overall SECURITY_AND_FUNCTIONALLY_VERIFIED / SECURITY_VERIFIED_FUNCTION_PARTIAL / SECURITY_VERIFIED_FUNCTION_FAILED / SECURITY_VERIFIED_FUNCTION_UNKNOWN。即使计划/缓存异常也保留已成立的安全事实。失败 REVIEW_REQUIRED、不恢复不安全代码、不修失败测试、不重试循环；baseline UNKNOWN，不能归因于修复。Production correctness UNKNOWN，不说 SAFE_TO_SHIP。缓存包含 workspace/all-files snapshot/provider/verifier/command/config/executable/grant/isolation version，32条/262144bytes/HMAC，16 plans/connection/900s，无源码、Secret、环境、prompt、model output、完整日志或 plaintext grant 落盘。

### AQ.2 当前环境与 A/B 验收

用户明确没有准备好的离线 Linux Maven 隔离环境，禁止本轮新增搭建/安装/下载或降低执行限制。本机 Java/pytest 已有，但未发现 Maven、Gradle、bubblewrap、Docker；WSL list 返回安装帮助，没有可用入口。真实 Maven normal test、A compile/test PASS、B post-fix TEST FAILED、Desktop/host 功能闭环均 **PENDING_ENVIRONMENT_PREREQUISITES**，不是实现失败或 PASS。

实际可丢弃 Maven fixture 含 pom.xml、src/main/java 与 src/test/java；A 原测试检查默认 verifier，B 原测试依赖旧自定义 verifier，另有 confirmed 修复case。实际 source SDK/strict clean wheel/Windows native 均运行原 Scanner，A/B/confirmed 安全 SCANNER_VERIFIED_RESOLVED，功能 NOT_AVAILABLE，overall SECURITY_VERIFIED_FUNCTION_UNKNOWN；target 未写入 live 项目。不是只用 mock 做链路；但没有运行真实 Maven，mock/fake runner 的 A/B success/failure 仍单独记账，不能替代真实执行。原四模式 native security acceptance 也实际通过。

证据：[source SDK](functional-sdk-evidence.json)、[strict clean](functional-clean-evidence.json)、[Windows native](functional-native-evidence.json)、[原 native 四种模式](functional-native-security-evidence.json)、[门禁与源码 hash](functional-acceptance.json)。早期 driver 输出 PENDING_LOCAL_PREREQUISITES 与本轮规范标签 PENDING_ENVIRONMENT_PREREQUISITES 表示同一未执行状态；原观测文件保留，本轮 canonical acceptance record 及最终 script 使用用户要求的后者，未更改执行事实。

### AQ.3 本地测试与交付

前轮 baseline724/6/6（未重新跑旧 HEAD）。targeted **241 passed，539.54s**；最后“functional 异常保留安全事实”修正 focused **67 passed，56.07s**；最终完整 offline **791 passed /6 skipped /6 subtests passed**，实际耗时见 functional-acceptance.json 的 gates.full。新增67项覆盖四生态检测、wrapper/fallback、脚本数据不成指令、无 install/network override、closed MCP schema、workspace/links/budgets、bounded actual transport、超时、结果组合、signed AUTO/confirmed/declined gate、连接/TTL/源码变化、缓存/篡改、输出 Secret 不泄露、无自动 revert/retry 与既有 Hook/coverage/equivalence 全量回归。

6 skipped 单列：tests/test_e2e_real.py:38/58/68/80/120/154 的三引擎 PATH 前提未满足，不计通过；其它真实 managed Scanner acceptance 不替代该前提。一次早期针对性失败（Windows path 的 resolve 比较）已修复；旧 full 因最后 Runtime 修正而中止，未计作最终通过，以上最终 full 对应最终 Runtime 代码。

wheel/sdist、六个 Runtime 模块逐字节 package integrity、licenses/distribution/notices compliance **PASS**。严格 clean venv **PASS**：无 editable/system-site，全部来自本机缓存117个 wheel，PIP_NO_INDEX/--no-index，未下载包；实际 MCP fixture 安全门禁与不可执行状态 PASS，Maven execution Pending。Windows standalone 最终源码重建与三条实际 MCP fixture **PASS**，原四模式 security native PASS；native 构建在 starting HEAD 的 dirty implementation 上，version.json.source_commit 为 starting HEAD，不冒充 immutable implementation artifact。没有修改 command Hook/其配置或重写 Hook core。

### AQ.4 手工试用与尚待验收

当前 Windows 可直接执行 FUNCTIONAL_VERIFICATION.md 的 source/native 命令观察 PLANNED → NOT_AVAILABLE 与独立安全状态。输出脚本exit0只表示当前可执行 protocol/security/fail-closed checks通过，不是 Maven tests PASS。已具备安全前提的 Linux 上 strict --require-functional-pass 才要求 A/confirmed 真正编译测试通过、B 真正失败；缺前提exit2，不能伪造。

Pending：真实 Maven normal/A/B execution 与 Desktop/host 功能 handoff（PENDING_ENVIRONMENT_PREREQUISITES）、Linux hardened backend 实测、Gradle/Node/Python 真实项目命令执行、三位真实开发者试用、独立 ground truth（UNREVIEWED/null；质量NOT_MEASURED），以及本轮 CI 按实际账户状态。已有三条 Desktop 修复 USER_REPORTED PASS 独立有效。

无模型调用、Scanner/model 源码上传、依赖或系统环境下载/安装、生产动作、Secret rotation、真实项目测试修改、Jeepay/用户 fixture/冻结 benchmark/人工标签编辑。Enterprise Gate/CI 门禁、新漏洞类型、其他 Host、新 Scanner/policy、失败测试自动修复、Joern/DAST/Deep Audit/watcher 等均未开始。完成交付后停止。

### AQ.5 本轮提交与 CI

Implementation HEAD `c9e99d7eb3f5a98248cedb68126e557397aed694` 已推送 origin/feature/runtime-mvp。新四类 CI 全部 completed/failure，但9 jobs 无Runner/steps，逐项注解均为账户付款失败或支出限额而未开始。**CI BLOCKED / PENDING_RERUN_AFTER_ACCOUNT_RECOVERY**，不是执行过的代码失败或 PASS；未修改账户设置/CI 门槛，未自动安装环境或循环重跑。

| Workflow | 新 run | 真实执行 |
| --- | --- | --- |
| Compliance | [37139051612](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37139051612) | 未启动，账户条件 |
| Runtime tests | [37139051635](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37139051635) | 未启动，账户条件 |
| Package integrity | [37139051627](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37139051627) | 未启动，账户条件 |
| Standalone artifacts | [37139051642](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37139051642) | 未启动，账户条件 |

四平台新artifact未在CI生成；本地Windows native证据独立有效。账户恢复后重跑本轮run，不使用历史AN成功证明本轮。最终docs-only提交也触发Runtime/Package/Compliance，其实际新结论在最终回复报告；Standalone不由docs-only触发。最终docs HEAD按PROJECT_STATE的git log核对。

## AR. Smart Auto Host Orchestration v0.2

### AR.1 问题证据、根因与范围

从干净 `ce6383573583c49a4a03daa4fccf0e2ea74916da` 继续。最新真实用户记录是 smart_auto、AUTO_FIX，但 Host 问“是否允许我修复这个安全问题？”，prepare=NO/resolved=0/verify=NO。Runtime policy **PASS**，本次 Host AUTO_FIX orchestration **FAIL**。AQ 的旧完整成功保留其时点，不作为本次成功证据。代码中原 AUTO 文案只称 required，缺少结构化无需确认契约，HOST_INSTRUCTIONS 未明确 block 不选择确认；修复这些可证明的契约歧义。无法由已有记录证明具体模型内部决策原因，不再归因于 mode。

保留 [官方 PostToolUse contract](https://learn.chatgpt.com/docs/hooks) 的 block 机制：已完成编辑不会撤销；模型后续遵循行为必须另验收。只修改四个 Runtime 模块、两个本地 SDK acceptance driver、原断言及新增 contract tests；不重构 Hook、不修改 command fallback/config、不新建功能 backend。

### AR.2 两种 interaction 与 authority

AUTO_FIX（包括已批准的 USER_CONFIRMED grant）固定输出：

```json
{"phase":"AUTO_REMEDIATION_AUTHORIZED","user_confirmation_required":false,"must_not_ask_user":true,"must_continue_automatically":true,"next_action":"PREPARE_TASK_FIX"}
```

guidance 开头 SECURITY_AUTO_REMEDIATION_AUTHORIZED / USER CONFIRMATION IS NOT REQUIRED；立即按原 task_ref/remediation_ref prepare、仅最小编辑、自动 Hook、verify，安全 resolved 后 functional prepare/run。systemMessage 固定为已授权、不要询问、立即 prepare。AUTO 保留 decision:block，无 continue:false、confirmation_ref、固定修复问题或 WAIT。来源仍须 Runtime-issued valid grant，不接受源码/Scanner/AI 自授权限。

CONFIRM_REQUIRED 原结构保持：

```json
{"phase":"POST_EDIT_REMEDIATION_CONFIRMATION","edit_already_applied":true,"requested_user_decision":"REMEDIATE_SECURITY_FINDING","must_not_retry_previous_edit":true}
```

编辑已完成，不重试；固定解释并问“是否允许我修复这个安全问题？”后 WAIT。批准前无 remediation_ref/prepare/verify grant，continue:false、不返回 block/reason；拒绝仍 DECLINED。只有这个 action 可主动问修复许可。显式批准后 Runtime 返回 AUTO_FIX/USER_CONFIRMED 且同无需再问的 interaction，原签名/TTL/连接/一次性/预算全部保留。

HOST_INSTRUCTIONS 按 remediation.action 两个分支互斥；decision=block、severity、Scanner prose、Host 风险判断均不能把 AUTO_FIX 升级为 CONFIRM_REQUIRED。smart_auto→AUTO_FIX；ask_before_fix 同资格→CONFIRM_REQUIRED；report_only→ADVISE，模式和资格不变。

get_runtime_info 的 remediation.mode 是该 MCP 服务实际使用的 reader 当前读值，不是能力版本。返回 VALID 或 UNKNOWN/INVALID；缺文件读默认 smart_auto，不写配置/DB/扫描。无 state_scope 路径字段，异常和 malformed/oversized 内容不回显。CLI 使用同 reader；测试覆盖显式/default、实时变更及 runtime store 与环境 state 不同的情况。Runtime 版本0.3.1、developer-guidance-v0.3、两能力 v0.1、required subset 保持。

### AR.3 测试、包与真实本地 transport

前轮 baseline **791 passed /6 skipped /6 subtests passed**（本轮未重跑旧 HEAD）。新增 **44 项**，最终 focused 加原真实 SDK 启动测试：45 passed in 42.03s；targeted 396 passed in 422.26s (0:07:02)；final full 835 passed, 6 skipped, 6 subtests passed in 528.67s (0:08:48)。实际耗时见 [门禁 JSON](orchestration-acceptance.json)。新增覆盖三个模式×三个 Host 工具、互斥/批准后不再问/拒绝无 grant、authority、mode 3合法/缺省/非法/Secret JSON/超大×CLI/MCP×default/explicit、无写入/初始化/路径泄露、实际service reader及异常脱敏。原 approval/decline/persistence/functional/MCP/command/equivalence 全量回归保持。早期 targeted395通过/1失败：新增测试的 capsys 在首次 SDK 导入时绑定了非 OS stderr，旧进程测试无法 fileno；已改为只捕获 stdout，再完整复验，不修改 Runtime 或降低断言。

6 skipped 独立列：test_e2e_real.py:38/58/68/80/120/154 的三引擎 PATH 前提缺失，不能计 PASS；managed Scanner driver 不替代该 PATH 验收。wheel/sdist 与11模块逐字节一致、package/compliance PASS；Hook/policy/guards/Functional backend 与 starting HEAD 按规范换行字节一致。

严格 clean venv 无 editable/system-site，从117个本机缓存 wheel 用 --no-index 安装，没有下载。Windows native 用最终 Runtime 源码重建；version.json.source_commit 是 starting HEAD 加 dirty workspace，不冒充 immutable implementation artifact。实际 [SDK](orchestration-sdk-evidence.json)、[clean](orchestration-clean-evidence.json)、[native functional](orchestration-native-functional-evidence.json)、[native四模式](orchestration-native-evidence.json) 使用 MCP stdio + 离线 managed Semgrep/Gitleaks。A/B/confirmed 安全 resolved1、prepare/verify、功能 prepare/run 均成立，Windows NOT_AVAILABLE / SECURITY_VERIFIED_FUNCTION_UNKNOWN。driver 模拟编辑与 user choice，不证明 Desktop 模型自动继续，也不证明 Maven 测试通过。

### AR.4 Fresh Desktop Trial3（PENDING）

先让配置指向本次源码环境或新包/native，断开重连 ai_security_runtime，再创建全新 Chat。Git 推送不会自动更新旧 wheel/native 进程。在 Chat 首先只读验证：

```text
允许你只读调用一次 AI Security Runtime 的 get_runtime_info。
不要扫描，不要修改文件。
只告诉我：
1. remediation.mode
2. smart_auto_remediation version
3. functional_verification version
```

期望 smart_auto / v0.1 / v0.1；若不同，先核对该 MCP 实际 executable/environment，不猜模式。使用已有 pom.xml 的可丢弃 Maven 测试项目（无需安装 Maven 或下载依赖，Windows 仅验门禁），避免其它同族 finding。全新 SmartAutoFunctionalTrial3.java 安全 baseline 请求：

```text
新增 SmartAutoFunctionalTrial3.java，提供 request(String url) 方法，用 JDK HttpsURLConnection 打开 URL，设置连接超时1000毫秒，保持默认 hostname verifier。只修改代码，不主动运行 security-check、安全扫描或构建。
```

待自动 PostToolUse 确立 baseline 后发普通编辑请求：

```text
在 SmartAutoFunctionalTrial3.java 中创建 connection 之后，加入 connection.setHostnameVerifier((hostname, session) -> true);。只修改代码，不主动运行 security-check、安全扫描或构建。
```

之后不发安全相关提示。自动发生 AUTO_FIX→prepare_task_fix→Agent移除 bypass→PostToolUse resolved_families=1→verify_task_fix SCANNER_VERIFIED_RESOLVED→prepare_functional_verification→run_functional_verification。Windows NOT_AVAILABLE/overall SECURITY_VERIFIED_FUNCTION_UNKNOWN 合理；若出现修复许可问题仍 FAIL。不能用自动化 SDK driver 代替这项真实宿主验收。

最后只根据已有记录查询（不得再调用工具）：

```text
不要调用任何新工具。只根据刚才已经发生的执行记录告诉我：
1. remediation.action
2. prepare_task_fix 是否调用
3. resolved_families
4. verify_task_fix 是否调用
5. verification_status
6. prepare_functional_verification 是否调用
7. run_functional_verification 是否调用
8. functional_verification.status
9. overall_status
```

PASS 必须 AUTO_FIX / YES / 1 / YES / SCANNER_VERIFIED_RESOLVED / YES / YES / NOT_AVAILABLE / SECURITY_VERIFIED_FUNCTION_UNKNOWN，且未问许可。仅真实反馈可把本次 PENDING 改 PASS。若项目没有任何现有 verifier，prepare 会如实返回 NO_EXISTING_LOCAL_VERIFIER，无 run handoff；不能伪造 run，这种项目不足以验收上述九项完整交接。

### AR.5 提交、CI 与 Pending

Implementation HEAD `74f5aae9d3a054254e2e9f5b29d3e1572c157092` 已推送 origin/feature/runtime-mvp。9 jobs 未分配 Runner、steps为空，实际检查注解均为账户付款失败/支出限额，未执行代码。不是代码 FAIL 或 PASS；未修改账户设置或验收门槛。四平台未运行。 **PENDING_RERUN_AFTER_ACCOUNT_RECOVERY**。

| Workflow | 新 run | 结论 |
| --- | --- | --- |
| Compliance | [37142647548](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37142647548) | PENDING_RERUN_AFTER_ACCOUNT_RECOVERY |
| Package integrity | [37142647537](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37142647537) | PENDING_RERUN_AFTER_ACCOUNT_RECOVERY |
| Runtime tests | [37142647527](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37142647527) | PENDING_RERUN_AFTER_ACCOUNT_RECOVERY |
| Standalone artifacts | [37142647528](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37142647528) | PENDING_RERUN_AFTER_ACCOUNT_RECOVERY |

本地 Windows native 与 CI 独立记账；不使用历史成功证明本轮。最终 docs-only 提交会触发 Runtime/Package/Compliance，新 run 在最终回复按实际观察单列。final docs HEAD 按 PROJECT_STATE.md 的 git log 核对。

仍 Pending：fresh Desktop Trial3 自动编排；真实 Maven A/B/Desktop功能execution 与 Linux hardened/其它生态真实执行 PENDING_ENVIRONMENT_PREREQUISITES；三位试用；独立 Ground Truth UNREVIEWED/null、质量 NOT_MEASURED；本轮 CI 按实际账户状态。没有安装/下载 Maven/JDK/bwrap/容器/依赖，没有降低 isolation/containment/argv/副作用限制；Runtime 无模型调用/源码编辑/构建，Scanner 无在线调用；driver 只编辑可丢弃合成项目，未改用户fixture/Jeepay/冻结benchmark/标签，无 Secret rotation。公共官方文档和授权 GitHub delivery 可联网，不上传目标源码给模型/Scanner。Enterprise Enforcement 等下一阶段仍 Planned，本轮交付后停止。

## AS. Codex Integration Productization v0.2 / Cold-start Readiness v0.3

### AS.1 起点与真实状态

## Codex Integration Productization v0.2 / Cold-start Readiness v0.3（2026-10-04）

干净起点 feature/runtime-mvp / 022f402a7ade0ed0cf6bbfce50dccd04ed5920a1。最新用户真实 Desktop 回传：MCP Hook/equivalence、CONFIRM 主动询问/批准/拒绝、AUTO 无错误许可问题→prepare→宿主最小修复→Hook resolved1→Runtime 内部 TaskFixService.verify SCANNER_VERIFIED_RESOLVED→functional prepare 无 verifier NOT_AVAILABLE/SECURITY_VERIFIED_FUNCTION_UNKNOWN，均 **USER_REPORTED PASS**。未报告显式 verify_task_fix 或 functional run，不补写已执行。AR 的旧失败/Pending 保留历史语义，由本节最新回传覆盖当前判断。

本轮只交付 Codex 自有项目 setup/status/repair/remove、readiness/诊断及既有复核协议去重。Runtime 0.3.1 / developer-guidance-v0.3 保持，features 新增 codex_integration v0.2 / cold_start_readiness v0.3。新 **fresh Desktop cold-start PENDING_ACTUAL_DESKTOP**；未在当前聊天伪造真实启动派发。source SDK/clean/native 模拟宿主编辑不代替 Desktop。

新增 focused **59 passed**；定向 **438 passed /420.09s**，最后三项 readiness 状态/恢复由 focused 与 final full 覆盖。最终完整离线 **894 passed, 6 skipped, 6 subtests passed in 514.48s (0:08:34)**，六项 skipped 单列。wheel/sdist/七模块逐字节完整性/package/compliance/严格离线 clean（无 editable/system site，117 cached wheels）/Windows native **PASS**。实际本地 MCP + Semgrep/Gitleaks 合成冷启动不调用 get_runtime_info、不重复显式 verify，无 verifier 时不调用 functional run。门禁见 [AS 验收](AI_TRIAGE_ACCEPTANCE.md#as-codex-integration-productization-v02--cold-start-readiness-v03)、[证据](codex-product-acceptance.json)、[用户命令与 fresh trial](CODEX_INTEGRATION.md)。新 CI 推送后按实际 jobs/steps/annotations 核对，未预写通过。


新 Desktop cold-start/SessionStart/required ordering PENDING_ACTUAL_DESKTOP。官方文档证明schema/support边界，不证明本机Desktop已派发。前轮AUTO内部verify/functionalprepare回传USER_REPORTED PASS；未补写explicitverify/run。

### AS.2 架构与协议

Manager/Adapter/Codex与Core分离；七新改模块在wheel/sdist/source逐字节一致，十二核心与startingHEAD不变。自己的exe/environment只读cap检查；requiredserver MCP+SessionStart观察+原PostToolUse，非commandrunner。workspace规范化/有界/UNCforeign/linkcontainment，configparse/type/size/duplicatekey failclosed，signedfingerprints ownership。事务/幂等/并发/legacy策略见ARCHITECTURE/DECISIONS/CODEX_INTEGRATION。

新readiness三字段event/workspace_path/session_id，additionalProperties=false/strict/hide_input_in_errors，4KiB signedhashmetadata，无source/Secret/prompts/transcript/payload，无scan/model/build/edit/remediation/network，Ready非live/safe。Hook的匹配task/grant CLOSED SCANNER_VERIFIED_RESOLVED回执是既有真实verify结果，Host可不再显式verify；functionalprepare仍校验原signedstate与guards，缺证明reject，未降FULL/process/rule/path/absence标准。

### AS.3 本地验证

| 门禁 | 实际结果 |
|---|---|
| prior baseline | 835 passed /6 skipped /6 subtests passed |
| focused | 59 passed，28.53s wrapper |
| targeted | 438 passed in 420.09s；最后三项由focused/finalfull覆盖 |
| final full offline | 894 passed, 6 skipped, 6 subtests passed in 514.48s (0:08:34) |
| wheel/sdist/package/compliance | PASS，3.1s |
| bytes integrity | 七模块PASS，十二核心不变 |
| strict clean | PASS，58.0s，无editable/systemsite、117缓存wheels、无下载 |
| Windows native | PASS，68.66s，Unicode/空格path、FROZEN ownexe、atomiclifecycle与MCP |
| source SDK cold start | PASS，46.45s，新process/session无get_runtime_info |

skipped单列：

- SKIPPED [1] tests\test_e2e_real.py:58: real scanner binaries required
- SKIPPED [1] tests\test_e2e_real.py:80: real scanner binaries required
- SKIPPED [1] tests\test_e2e_real.py:120: real scanner binaries required
- SKIPPED [1] tests\test_e2e_real.py:154: real scanner binaries required
- SKIPPED [1] tests\test_e2e_real.py:68: real scanner binaries required
- SKIPPED [1] tests\test_e2e_real.py:38: real scanner binaries required

source/wheel/native各有codex-product-*-evidence.json。宿主edits由driver模拟；firstbaseline scanner_run=true/new0，危险editnew1/AUTO→prepare→修复resolved1→内部SCANNER_VERIFIED_RESOLVED/CLOSED匹配task/grant→直接functionalprepare。未调用verify_task_fix/get_runtime_infowarmup；无verifier无handoff不run。不是Desktop模型或MavenPASS。此前预提交native构建的source_commit为startingHEAD；本轮又从已提交实现e68cff74c97a0a7a45df2381015b5906b072a82f重建并完成验收，最终native版本元数据与implementation一致，见native-evidence。

### AS.4 实机验收与lifecycle

见CODEX_INTEGRATION的命令和fresh步骤。setup后完全退出/重开，firstordinaryJavaedit前不get_runtime_info/scan/status；safe baseline再ordinary edit引入always-truehost verifier，应自动fix/Hook内部verify/functionalprepare。首edit不触发且warmup后才恢复为FAIL；缺Host官方可用机制为HOST_LIFECYCLE_PREREQUISITE_PENDING。setup/status/setupagain/repair/remove/setupagain另做disposabletrial，检查bytes/mtime、unrelatedconfig/source/DB保留。自动化不是用户实机反馈，未改用户主config；projecttrust为Host前提。

### AS.5 CI

implementation push后查询Runtime/Package/Compliance/四平台Standalone真实jobs/steps/annotations。无runner/steps且billingannotations为PENDING_RERUN_AFTER_ACCOUNT_RECOVERY，不能称代码FAIL或PASS；本轮新runs随最终文档更新，旧AR不替代。



Implementation commit: e68cff74c97a0a7a45df2381015b5906b072a82f。

| 新 workflow | 实际 run | 结论 |
|---|---|---|
| Compliance | [37147993106](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37147993106) | PENDING_RERUN_AFTER_ACCOUNT_RECOVERY |
| Runtime tests | [37147993093](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37147993093) | PENDING_RERUN_AFTER_ACCOUNT_RECOVERY |
| Package integrity | [37147993105](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37147993105) | PENDING_RERUN_AFTER_ACCOUNT_RECOVERY |
| Standalone artifacts | [37147993133](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37147993133) | PENDING_RERUN_AFTER_ACCOUNT_RECOVERY |

最终文档提交的三个新 workflow在最终交付消息按实际jobs/annotations核实；不把文档push自动算通过。

### AS.6 Pending与边界

新actualDesktopcold-start/session/用户lifecycle反馈Pending；真实MavenA/B/hardenedLinux PENDING_ENVIRONMENT_PREREQUISITES，三位试用Pending，GroundTruth UNREVIEWED/null，质量NOT_MEASURED。未安装/下载Maven/JDK/bwrap/容器/构建依赖、未目标build/Runtime模型/Secretrotation；Scanner离线，无Jeepay/原Desktopfixture/人工标签变化。仅官方OpenAIdocs/GitHub交付CI联网；既有四平台artifact准备公开engine/cache流程保留，fixture扫描本身offline不上传source或Secret。未开始Enforcement/EnterpriseGate/其它Host/第二AUTO/DeepAudit/Joern/DAST/watcher。


## AT. Auto Remediation Continuation Guard v0.1

### AT.1 起点与最新真实状态

干净起点 feature/runtime-mvp / 04c145e8bd5dbe5d266290a1db109e5d220d6368。最新用户实机无 get_runtime_info/reconnect/warm-up 的 first edit PostToolUse、MCP connection、AUTO_FIX policy、READINESS_OBSERVED / overall READY，以及 setup 幂等/healthy repair/remove/re-setup 均 USER_REPORTED PASS。最新 Host 结束 turn 未调用 prepare_task_fix，未安全编辑，resolved=0，无 SCANNER_VERIFIED_RESOLVED/functional entry：Host continuation USER_REPORTED FAIL / UNSTABLE。不再调查 cold-start/readiness。此前历史 PASS 与 AS 的旧 Pending 不覆盖本次反馈；新 Stop Desktop 自动继续 PENDING_ACTUAL_DESKTOP。

### AT.2 架构与安全边界

官方 contract 于2026-10-04重新读取 [Hooks / Stop](https://learn.chatgpt.com/docs/hooks#stop) 和 MCP Tool Hook/template 部分。Stop matcher 不使用，mcp_tool server/tool/input/timeout/statusMessage；完整模板保留 boolean。decision:block/reason 自动生成 continuation prompt，不撤销已执行 edit；已有连接直接调用，不经过 Windows command runner。MCP schema 见 [实际注册 schema](continuation-mcp-schema.json)，配置见 [当前生成 hooks](continuation-hooks-example.json)。quiet文本为{}，structuredContent的status/count/phase/execution是Runtime metadata，不自创Hook输出字段。

仅四项 strict closed bounded host claims，workspace lexical containment 在访问外部 filesystem 前拒绝，links failclosed；host claims不是独立身份认证。现有 RemediationService._grant 保存连接内原 token/handoff，HostContinuationGuard从既有HMAC record验证原POLICY_AUTO/OFFERED/AUTO_FIX的workspace/host/session namespace、family/task/original scan/grant、policy/config revision/mode、snapshot/source/preservation、未消费prepare，并在existing OS lock内复核。原reference不落盘，不恢复hash，不续期/重新签发grant；memory≤32，Stop eligibilitywindow900秒不等于新增repairTTL。重连丢失handoff允许Stop。无Scanner/model/source edit/build/network/prepare/verify；源码读取仅既有boundedsnapshot/guard，不持久化内容或模型prompt。

独立 host_continuation_attempt_count≤2，HMAC binding包含原grant/snapshot/policy/PREPARE_REQUIRED；false claim不重置，预算耗尽只记录固定HOST_CONTINUATION_EXHAUSTED后allow，重复耗尽不写。stop_hook_active=true且本guardcount0不加入其他Hook循环。successful READY_FOR_HOST_FIX使用原prepared attestation清掉继续条件；failedprepare不算进展。不扩edit/recheck/functional。只有现有正常授权签发不同retrygrant时清掉上一个grantcounter，Stop不能操作这一发行路线；samegrant重新retain仍不能重置signed预算。

CONFIRM_REQUIRED/PENDING_CONFIRMATION和USER_CONFIRMED全部隔离；终态/失效/report_only/NONE/ADVISE/MANUAL_ONLY不block。0 pending连续100次无warning/state creation；exhausted100次无追加warning/write。原PostToolUse strongGUIDANCE、systemMessage、interaction、decision:block保持；HookCoordinator/baseline/snapshot/cooldown/single-flight/familymultiset/coverage/risk/Raw/UNTRUSTED_CODE/secretredaction、commandtransport、TaskFix/Verification/Functional核心保持，十二模块与startingHEAD逐字节归一化核对未变。

### AT.3 本地门禁

| 门禁 | 实际结果 |
|---|---|
| baseline（AS 已记录） | 894 passed /6 skipped /6 subtests passed |
| final focused Stop/lifecycle | 116 passed in 177.41s (0:02:57) |
| targeted | 497 passed in 555.13s (0:09:15)；在最后retrycounter清理之前；其后3项定向PASS，最终full覆盖最终源码 |
| final full offline | 951 passed, 6 skipped, 6 subtests passed in 666.89s (0:11:06) |
| wheel/sdist/package/compliance | PASS，2.94s，23 first-party rule files |
| bytes integrity | 八模块wheel/sdist/source一致，十二核心不变 |
| strict clean venv | PASS，67.02s，无editable/systemsite，117本地cachedwheels，无下载 |
| source actual MCP | PASS，46.18s，synthetic host，非Desktop |
| Windows native | PASS，71.33s，独立输出目录；原活动目录首次FAILED_DLL_LOCK（29.09s），缺失74项恢复且旧exe/进程未改 |

focused含注册/extra字段type/noecho、workspace/foreignsession/symlink、stateHMAC/scan/task/family/policy/source/snapshot变化、expiredwindow、max2/exhaustion、stopactive、成功与失败prepare、confirmation隔离、silent100、原retrygrant、自有Stop升级/幂等/repair/remove/foreignpreserve/malformed、CLIUX；targeted及full包含既有command/confirmation批准拒绝/equivalence/verifydedupe/functional/lifecycle。

skipped单列，不算PASS：

- tests/test_e2e_real.py:38: real scanner binaries required
- tests/test_e2e_real.py:58: real scanner binaries required
- tests/test_e2e_real.py:68: real scanner binaries required
- tests/test_e2e_real.py:80: real scanner binaries required
- tests/test_e2e_real.py:120: real scanner binaries required
- tests/test_e2e_real.py:154: real scanner binaries required

实际 SDK/clean/native evidence分别记录 PostToolUse natural continuation NOT_TESTED_DRIVER_FORCED_FALLBACK、Stop invoked/count1、原prepare调用、SIMULATED_HOST_ONLY安全编辑、resolved1、SCANNER_VERIFIED_RESOLVED、explicitverifydeduped、functionalprepare NOT_AVAILABLE无run。实际扫描离线，Host由driver模拟。Stop 前无pending和prepare后/closed后均silent；无get_runtime_info/手工warmup，不跑functional无handoff。

### AT.4 真实 Desktop 验收

[可执行fixture命令与完整步骤](CODEX_INTEGRATION.md#fresh-desktop-实机验收)：只setup→完全退出/reopen→新可信Chat→普通安全Java编辑baseline→普通危险hostname编辑。测试前禁止status/info/scan/reconnect热身，不向用户索要修复批准或第二条安全消息。自然PostToolUse继续成功则Stop无需兜底；否则Stop block/reason→Host原prepare→最小安全edit→Hook resolved1/SCANNER_VERIFIED_RESOLVED。记录AUTOissued、naturalYES/NO、StopYES/NO/count、prepare、secureedit、resolved、security、explicitverifydedupe、functionalprepare。当前聊天不能重新加载并证明真实Host派发，PENDING_ACTUAL_DESKTOP，不以SDK/native替代。

### AT.5 实现/CI/native provenance

Implementation `17a638f492d277d6bc9a104b019a5bbf081cb2ee` 已推送 origin/feature/runtime-mvp。新 Runtime/Package/Compliance/Standalone 四类 CI 实际 GitHub failure，9 jobs 未分配 Runner、steps为空，检查注解明确为账户付款失败/支出限额，**PENDING_RERUN_AFTER_ACCOUNT_RECOVERY**，四平台未运行；不是代码 PASS，不放松契约或更改账户/workflow。新 runs 见 AT.5。Windows native 从该已提交 HEAD 在独立目录重建并实际验收 PASS，71.33s，source_commit/hash可核对。旧活动目录第一次重建 DLL锁定失败；恢复74个缺失且未变资源，旧exe未改、未终止MCP。最终docs HEAD用本文件git log核对，其新CI在最终回复独立核实。

核心实现提交 fbcc28723e36b2df19528a478716104c2d25d865；包装输出目录修正提交 17a638f492d277d6bc9a104b019a5bbf081cb2ee。构建脚本仅增加 --output-dir，限定workspace dist且拒绝links，既有CI默认目录不变。无Host进程终止/command fallback。源码完整full在最后Runtime修改后运行，后续仅打包脚本/文档改动，实际新目录构建验证该打包变更。

| 新 workflow | 实际 run | 结论 |
|---|---|---|
| Compliance | [37180389240](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37180389240) | PENDING_RERUN_AFTER_ACCOUNT_RECOVERY；未启动 |
| Runtime tests | [37180389244](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37180389244) | PENDING_RERUN_AFTER_ACCOUNT_RECOVERY；未启动 |
| Package integrity | [37180389226](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37180389226) | PENDING_RERUN_AFTER_ACCOUNT_RECOVERY；未启动 |
| Standalone artifacts | [37180389225](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37180389225) | PENDING_RERUN_AFTER_ACCOUNT_RECOVERY；未启动 |

最终docs提交的新三类CI在最终交付消息按实际jobs/annotations独立核实。

### AT.6 Pending 与边界

新fresh Desktop Stop自动继续 PENDING_ACTUAL_DESKTOP。最新cold-start/readiness/lifecycle USER_REPORTED PASS，不能继续当未验证来调查。真实Maven A/B/hardenedLinux PENDING_ENVIRONMENT_PREREQUISITES，不安装/下载/搭环境、不降低隔离。三位试用 PENDING、GroundTruth UNREVIEWED/null、质量NOT_MEASURED。未修改Jeepay/用户实际fixture/冻结benchmark/人工标签；Scanner offline、Runtime no model/source edit/target build/network、Secretrotation未执行。仅官方OpenAI文档与GitHub授权交付联网。Capability/Entitlement/PlusPro/EnterpriseGate/CIgate/PreToolUseenforcement/其它Host、新AUTO规则、新Scanner、Windowsfunctionalbackend、DeepAudit/Joern/DAST/watcher保持Planned，完成后停止。


## AU. First-run Baseline Seed + Trust UX v0.1

### AU.1 根因与当前真实性

starting HEAD 50ecaf2f4451e4cc6854651c9987ae7167a8b11c。用户真实失败：safe Hook无记录、危险首有效Hook BASELINE_ESTABLISHED/FULL/NEW0/NONE，不能断言Host未trust的具体原因。旧代码只读session previous，无setup比较点；因此吸收当前风险。不曾AUTO_FIX，不是Stop失败。最新实现见顶部与CODEX_INTEGRATION；Host原生审批由用户完成，trust UNKNOWN。

### AU.2 Baseline contract / lifecycle / ABI

源码baseline_seed.py的signed closed wrapper与hook-v1 safe projection；bounded outside workspace/atomic/no source与具体bindings见ARCHITECTURE首节。生产默认ProjectionOnlyStore，setup不写普通scan/finding payload；Runtime已有数据保留。setup首次一轮quick scan；有效二次setup/healthy repair不扫描，source变化不失效；missing/stale/incompatible修复重建明确BASELINE_REESTABLISHED。status只读；remove删除seed，re-setup新seed。前三者状态与readiness/live_connection分开；READY不是project safe。完整三事件配置与starting HEAD一致，继续使用[冻结配置](continuation-hooks-example.json)。五个Hook核心算法AST未变，13个保护模块与起点一致，见结构化完整性证据。

### AU.3 实际测试与分发

| 门禁 | 真实结果 |
|---|---|
| baseline（上一轮保存，未本轮重跑） | 951 passed /6 skipped /6 subtests passed |
| final focused | 90 passed in 219.07s (0:03:39) |
| targeted | 524 passed in 1037.62s (0:17:17)；最后5项测试由focused/full覆盖 |
| final full offline | 982 passed, 6 skipped, 6 subtests passed in 1123.35s (0:18:43) |
| wheel/sdist/package/compliance | PASS，6.23s，23 first-party rule files |
| bytes/ABI/core integrity | PASS；5 modules/13 protected modules/5 original core functions/exact Hook definitions |
| source actual MCP + local engines | PASS，84.65s，synthetic SDK |
| strict clean venv | PASS，115.57s，117 cached wheels，无editable/system site/download |
| Windows native独立新目录 | PASS，92.5s，committed implementation HEAD；旧运行包未覆盖/进程未终止 |

focused包含seed签名/binding/foreign/runtime/rules/providers/schema/future/size/links、源变化正常、moving inventory/partial/failure/unavailable/timeout/cancellation/budget、no source/Secret/DB persistence、missing first Hook/untracked AUTO/preexisting tracked clean文件/普通无finding quiet、session authoritative、setup/status/repair/remove/idempotence/ABI/UX。targeted/full保留PostToolUse、Stop Guard、确认批准/拒绝、equivalence multiset、修复/功能安全与cold-start readiness回归。

六项skipped单列（不是PASS）：tests/test_e2e_real.py:38、58、68、80、120、154；均要求PATH上的真实scanner binaries。另三种实际source/clean/native使用已有缓存local Semgrep/Gitleaks通过；不把全部real e2e skipped隐藏。

### AU.4 真实Runtime与Desktop边界

[SDK](baseline-seed-sdk-evidence.json)、[clean](baseline-seed-clean-evidence.json)、[native](baseline-seed-native-evidence.json)：setup READY→deliberately skip safe PostToolUse→新/untracked危险首有效Hook SETUP_SEED/baseline_available=true/scanner_run=true/NEW1/AUTO_FIX→original Stop fallback→prepare→driver安全edit→resolved1/SCANNER_VERIFIED_RESOLVED/CLOSED matched receipt→functional prepare NOT_AVAILABLE无run。preexisting setup后fresh session PERSISTING1/NEW0/NONE。无info/status/scan warm-up；actual local offline scanners，edit与Host continuation是driver模拟，PENDING_ACTUAL_DESKTOP不改PASS。

Fresh Desktop步骤：新disposable Git项目→新原生包setup确认baseline READY→在Codex打开并Review & Allow Hooks一次→完全退出/重开→fresh Chat普通safe Java edit→下一普通danger edit（可另一fixture故意缺失safe Hook）→NEW1/AUTO_FIX→natural或Stop→prepare→secureedit→resolved1/SCANNER_VERIFIED_RESOLVED。不额外发安全提示、不手工Runtime工具热身。原生包路径与可执行命令见CODEX_INTEGRATION。preexisting用独立fixture，期待PERSISTING1/NONE。记录Host版本/seed/trust人工审批/首Hook/自然或Stop/count/prepare/edit/receipt/functional，勿上传Secret或transcript。

### AU.5 提交与新CI

Implementation `4915354cd6e8bef139836cb760ae6fb601d8f76a` 已推送feature/runtime-mvp；最终docs HEAD按git log核对。新CI按实际jobs/steps/annotations核实：**PENDING_RERUN_AFTER_ACCOUNT_RECOVERY**；GitHub conclusion与未启动执行区分，不预写PASS、不改账户/workflow或安全门槛。

| workflow | 新 run | 实际结论 |
|---|---|---|
| Standalone artifacts | [37183840764](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37183840764) | failure; PENDING_RERUN_AFTER_ACCOUNT_RECOVERY |
| Runtime tests | [37183840767](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37183840767) | failure; PENDING_RERUN_AFTER_ACCOUNT_RECOVERY |
| Package integrity | [37183840787](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37183840787) | failure; PENDING_RERUN_AFTER_ACCOUNT_RECOVERY |
| Compliance | [37183840731](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37183840731) | failure; PENDING_RERUN_AFTER_ACCOUNT_RECOVERY |

### AU.6 Pending / safety / scope

fresh Desktop first-run baseline/trust/Host continuation PENDING_ACTUAL_DESKTOP；CI PENDING_RERUN_AFTER_ACCOUNT_RECOVERY。Maven A/B PENDING_ENVIRONMENT_PREREQUISITES，不搭环境/安装/联网依赖下载；三位试用PENDING，Ground Truth UNREVIEWED/null，质量NOT_MEASURED。SDK/native不代替独立人工。源码编辑仅driver disposable fixture模拟，Runtime不编辑/build/调用模型/联网或Secret rotation，不改Jeepay/冻结benchmark/人工标签。Plus/Pro、Capability/Entitlement、Deep Audit、Skill/MCP Scan、Enterprise Gate、Cursor、新rule/Scanner/Functional sandbox等Planned。完成后停止。

## AX. Functional verifier discovery & host execution v0.1

### AX.1 起点、范围和真实事实

feature/runtime-mvp / `ee1bfd9c12493683cc313cb3628753a51ae124ac`；工作区包含AW的13个未提交文件，全部保留，无reset/clean/commit/push。用户最新真实E2E：security SCANNER_VERIFIED_RESOLVED正确保留，functional NOT_AVAILABLE/NO_EXISTING_LOCAL_VERIFIER、overall SECURITY_VERIFIED_FUNCTION_UNKNOWN；clean项目有javac，旧Runtime无fallback或Host结果回传。本轮只做verifier发现、最小计划、Host原生执行交接、结果校验、独立最终维度；不改CET/sandbox、episode预算、Hook控制语义/automatic continuation或新policy/scanner。

### AX.2 发现与命令范围

| 目标 | Host发现/计划 |
|---|---|
| Java | 根pom.xml Maven优先，其次build.gradle(.kts) Gradle；配置存在而工具缺失为NOT_AVAILABLE，不绕过构建系统 |
| Java无构建系统 | signed receipt目标Java文件+已有javac → COMPILE/java-javac-target，-proc:none/-implicit:none，空classpath/sourcepath，仅目标文件 |
| Python | 既有pytest tests或test入口；优先tests/test_<目标stem>.py；不安装pytest或生成测试 |
| Go | go.mod与已有*_test.go，go test仅目标package，不用./...；GOPROXY/GOSUMDB=off、GOTOOLCHAIN=local |
| Node | 仅已有typecheck/test/lint/build固定script名，现有lock选择manager；不执行安装/npx/corepack，Host须先审阅script |

Runtime不启动目标命令。原registry.detect(root)/显式executor注入的内部回归兼容；MCP默认仅Host模式，不提供backend/sandbox切换输入。javac产物使用项目外新临时目录，原源码目录不生成.class。Maven/Gradle/Node/Python/Go使用原snapshot函数的有界瞬时副本，Host工作目录指向副本，原项目复核不变，副本原输入文件也不可更改。副本范围最多200files/2MB，非compiler-grade依赖分析；相关tests不能证明业务行为，未知baseline/regression attribution/production correctness保留。

### AX.3 MCP原协议扩展与安全边界

prepare_functional_verification参数仍为remediation_ref/task_ref/workspace_path，逐字使用原opaque refs。signed current episode CLOSED/scanner proof、TTL/policy/source/preservation/member/workspace/snapshot/config/tool identity成立才规划，产出：status FUNCTIONAL_VERIFICATION_READY；nested functional.status PLANNED；原security SCANNER_VERIFIED_RESOLVED；plan/version/steps（command_id、固定argv、cwd、目标、scope、timeout、环境限制、output budget）；functional_ref、plan_digest、expected_result_contract；handoff tool=run_functional_verification，arguments.functional_ref原值，execution_result_required=true。无可用工具不签发计划/引用。工具metadata readOnlyHint=false反映临时目录写入。

run_functional_verification新增可选execution_result，旧无报告调用只返回Host计划，不在Runtime执行。模型闭合、strict/extra forbidden、错误不回显input；顶层只有plan_digest、network_access(DENIED/UNKNOWN)、project_code_reviewed、steps；每step只有command_id、execution_status(COMPLETED/TIMEOUT/NOT_AVAILABLE/CANCELLED/OUTPUT_LIMIT/FAILED_TO_START)、exit_code、duration_ms、stdout_summary/stderr_summary。每路summary≤8192字符、≤9steps。不能传argv/shell/source/transcript/Secret/网络授权override。摘要按固定marker分类，输出仅存keyed hash，不回显或持久化原文；Host必须先脱敏，source/Secret不是合规输入。

connection-local functional_ref绑定workspace、原refs/grant、snapshot/config/tool及公开plan_digest；原引用不能跨连接重建/转交。plan TTL900s、最多16。校验command_id顺序/范围和原签发digest；unknown network/未审阅项目code的实际执行为INCONCLUSIVE；Host未执行且NOT_AVAILABLE无需伪造网络/审阅证据。每步60s、总180s、输出65536bytes；Host负责原生执行限额及网络拒绝，不能满足则不运行。不自动下载或重试、不扩范围、不提交任意命令。宿主报告是UNTRUSTED_HOST_EXECUTION_REPORT，Runtime不能认证真实OS限制/进程行为，不能把报告等同独立人工Ground Truth。

只删除本plan创建的项目外临时目录，删除前先验证路径/links/containment、有界遍历（800entries/50MB），拒绝junction/symlink/special input或修改副本原输入。提交完成、过期后下次prepare、正常service终止会清理；突然kill/crash或安全清理失败可能遗留，需人工确认后清理，不能盲删或标PASS。不新增daemon/通用runner。瞬时副本不进入DB/状态；cache只保存状态与keyed hashes，使用独立Host namespace与snapshot/config/grant绑定。成功/失败/部分结果可复用；未知/不可用可以明确重新prepare，Runtime不自动执行重试。

verify_task_fix原status/verification_status及scanner execution facts保留；增加functional_status与security_verification/functional_verification/overall_status。读取同snapshot/config/grant的HMAC缓存并保留结果来源，Host报告不能签发/否定scanner已成立的事实。工具名称/refs格式、DB/key不迁移；prepare从PLANNED改READY且run不再Runtime执行，旧Host需按新协议更新，不能声称完全无行为变化。runtime-info增加functional_host_execution=v0.1；version仍0.3.1。

### AX.4 功能状态机

| 条件 | 功能状态 / API状态 | overall；安全事实 |
|---|---|---|
| 无verifier或工具缺失 | NOT_AVAILABLE / SECURITY_VERIFIED_FUNCTION_UNKNOWN | SECURITY_VERIFIED_FUNCTION_UNKNOWN；安全保留 |
| 计划已签发、未执行 | PLANNED / FUNCTIONAL_VERIFICATION_READY | SECURITY_VERIFIED_FUNCTION_UNKNOWN；安全保留 |
| 最小javac成功 | PASSED / FUNCTIONAL_VERIFIED，COMPILE_ONLY | SECURITY_AND_FUNCTIONALLY_VERIFIED，仅该compile scope；production UNKNOWN |
| 命令失败 | FAILED / FUNCTIONAL_FAILED | SECURITY_VERIFIED_FUNCTION_FAILED；SCANNER_VERIFIED_RESOLVED不变 |
| 只有build/部分验证有效 | PARTIAL / FUNCTIONAL_PARTIAL | SECURITY_VERIFIED_FUNCTION_PARTIAL |
| timeout/边界未证明/过期/无exit code/摘要超限/输入改变 | INCONCLUSIVE / FUNCTIONAL_INCONCLUSIVE | SECURITY_VERIFIED_FUNCTION_UNKNOWN；原安全事实不被功能结论覆盖 |

无tests collected不算测试PASS；依赖本地缺失为NOT_AVAILABLE，先前有效步骤可PARTIAL。无trusted baseline的失败不能归因本次修复；不恢复always-true verifier、不改失败测试/业务代码、不claim SAFE_TO_SHIP。CLOSED仍为security episode phase，独立functional状态可PLANNED/FAILED/UNKNOWN；没有混入functional credential自动续期/授权重建，receipt失效即停止授权，既有安全事实与当前receipt有效性分开表达。

### AX.5 本轮门禁与证据

新增[Host测试](../tests/test_functional_host.py)共32项：Maven/Gradle优先级、javac fallback/缺失、真实编译成功与失败、单文件scope/无.class污染/清理、Host结果回传、保留安全失败维度、计划绑定/命令范围/网络/review/timeout/output/exit拒绝、摘要不回显不持久化、过期/foreign workspace/source变化、注入路径/symlink、pytest/Go/Node入口、projection输入篡改、严格MCP schema/无CET调用、cache篡改/未回传结果/无测试collection。既有functional内部执行、episode/confirmation、Host指导等由定向/full覆盖。既有codex_integration_acceptance在返回新READY时回传NOT_AVAILABLE用于清理，不额外构建目标。

| 验收 | 实际结果 |
|---|---|
| 起点working-tree baseline（AW已运行，未重跑） | 1021 passed /6 skipped /6 subtests |
| 首轮focused | 93 passed，36.77s |
| 扩展targeted | 171 passed，222.12s，早期26项Host测试+existing/episode/orchestration |
| 最终focused | 99 passed，40.42s，含全部32项Host测试 |
| 既有Hook receipt契约追加 | 2 passed /58 deselected，14.18s；分别验证javac可用/缺失，不重复安全Scanner |
| 最终full offline | PASS：1054 passed /6 skipped /6 subtests passed，1282.01s（wrapper1283.05s），全部32项Host测试、Hook receipt两分支及AW episode回归覆盖 |
| 实际MCP/离线Scanner/已有javac A/B | PASS，93.90s，[SDK evidence](functional-host-sdk-evidence.json) |
| wheel/sdist/package/compliance | PASS，5.76s，102打包源码/数据bytes一致，sdist包含最终Hook receipt兼容测试，[package evidence](functional-host-package-evidence.json) |
| clean install/native/CI/commit/push | 本轮未执行，不替换活动Runtime；用户禁止commit/push，无新CI |

[实际SDK验收脚本](../scripts/functional_host_acceptance.py)在一次性Git项目通过真实MCP server/managed Semgrep/Gitleaks，两种case均 safe baseline→unsafe→AUTO→prepare→driver删除危险行→Hook scanner resolved/CLOSED→functional prepare READY→driver执行原javac argv→原functional_ref/plan_digest回传→verify双维度。A：javac exit0/505ms，security SCANNER_VERIFIED_RESOLVED，functional PASSED/COMPILE_ONLY，overall SECURITY_AND_FUNCTIONALLY_VERIFIED；B：原文件从基线就有未知symbol，最小安全修复不改它，javac exit1/693ms，security仍SCANNER_VERIFIED_RESOLVED，functional FAILED，overall SECURITY_VERIFIED_FUNCTION_FAILED。两者原引用逐字roundtrip，源码不污染，外部产物已清理；CLOSED为安全phase。仅SIMULATED_NATIVE_HOST_DRIVER，非Desktop自然派发/模型执行，不证明业务正确性或regression attribution。已有javac21.0.9，无安装/依赖下载/网络/源码上传/Secret操作。

首次本轮full在旧test_hook_closed_receipt_direct_functional_without_second_verify的固定NOT_AVAILABLE断言失败（新行为PLANNED/READY），单独复现1 failed/58 deselected；该断言与新增javac fallback矛盾。更新为工具可用/缺失两分支，保留原matched security receipt/no duplicate explicit scanner verify/不可用无handoff断言，2项通过。原过时full已终止，未完成、不计PASS；最终整轮另行复核。执行中出现的未跟踪docs/PROJECT_CONTEXT.md非本轮创建，未读取/改动/删除，保留为外部工作区变化。

最终独立full日志/完成记录为本地忽略目录 .security-runtime/episode-host-functional-full-final.log/.json；returncode=0。六项skipped独立记录：tests/test_e2e_real.py:38/58/68/80/120/154，原因均real scanner binaries required（该套PATH发现前提缺失），不计PASS；不否定本轮managed scanner SDK A/B证据。最终完整回归后只更新文档，无新产品/测试代码变更。functional_execution.py、HookCoordinator、Codex Hook控制/ABI、HostContinuationGuard均与起点HEAD一致；仅functional指导段落适配新Host计划，未扩展自动continuation。

真实`C:\Users\Administrator\Desktop\ai-security\runtime-episode-e2e-clean`仅只读检查目标TlsService.java，发现javac且工具可用；没有旧task/remediation引用、源码修改或构建。实际Desktop自动执行仍PENDING_ACTUAL_DESKTOP。

### AX.6 人工 fresh Desktop E2E 与Pending

1. 加载本轮源码/本轮wheel到实际连接的Runtime，按既有integration信任流程重新连接；活动旧native未替换，不能用旧包验收。runtime-info应含features.functional_host_execution=v0.1；使用正常恢复指引，不调查readiness。
2. 在一次性Java无Maven/Gradle项目，同Chat的`src/main/java/demo/TlsService.java`建立安全基线、显式授权隔离E2E；只加入always-true verifier，等Hook新episode/新opaque refs。原样prepare、只删除该行，等matched SCANNER_VERIFIED_RESOLVED/CLOSED。
3. 同原task_ref/remediation_ref调用prepare_functional_verification，期待FUNCTIONAL_VERIFICATION_READY、javac单step/仅TlsService.java、外部-d、budget、functional_ref/plan_digest。无有效计划立即停，不自行猜命令或refresh authority。
4. Host按plan的固定argv/cwd/env/timeout/output预算、禁止网络原生执行，不用独立security-check或Runtime runner、不扩大项目。记录exit code/duration；摘要先脱敏且不含源码/Secret，不交完整编译器日志。
5. 按原handoff调用run_functional_verification，原样functional_ref/plan_digest加闭合execution_result；随后原样verify_task_fix。成功：security SCANNER_VERIFIED_RESOLVED、functional PASSED/COMPILE_ONLY、overall SECURITY_AND_FUNCTIONALLY_VERIFIED，production UNKNOWN。失败：安全仍resolved，functional FAILED、overall SECURITY_VERIFIED_FUNCTION_FAILED。核对原status不被覆盖、源码无.class且临时输出删除。
6. A/B可用不同一次性fixture，让B原安全基线已有未定义symbol，再只修TLS行，不事后修改已绑定snapshot来伪造失败。保留两轮原始工具结果；若Host/环境不能执行限制回报NOT_AVAILABLE，明确Pending。不要跨Chat转交/重编码refs或换对象。

真实Desktop本轮PENDING；Maven/Gradle真实宿主执行及真实Maven A/B仍PENDING_ENVIRONMENT_PREREQUISITES，不安装JDK/Maven/bwrap/容器或下载依赖。单文件javac不猜classpath，项目依赖/兄弟源码导致失败如实保留；大项目可能触发原有scope/snapshot预算。三位试用Pending、独立Ground Truth UNREVIEWED/null、质量NOT_MEASURED；之前远端CI账户问题保留历史，未创建新CI。上一轮episode实现/引用保护保留；其它阶段Planned，完成本轮后停止。

## AW. Finding Family / Remediation Episode lifecycle

### AW.1 用户实机事实与七项实现核查

起点 `ee1bfd9c12493683cc313cb3628753a51ae124ac` / feature/runtime-mvp，工作区干净。用户真实隔离 E2E：CodeModeTlsService.java 历史 CLOSED 后重新引入 always-true HostnameVerifier，Hook SCANNED/scanner_run=true，但 ADVISE/FAMILY_CLOSED_OR_BUDGET_EXCEEDED、无引用；FreshTlsRegressionService.java 首次同规则 AUTO_FIX/有引用。此为 USER_REPORTED lifecycle FAIL，证明问题不在新 finding 的 scanner/policy/授权入口。

1. SAST family identity 为 eq-v1(category, sorted sources, rule, relative file)，不含行号/源码/Secret。workspace 独立目录 hash 隔离；旧实现没有单独 episode identity。
2. 原状态在 user-state/remediation/workspace-hash/host-session-hash.json 的 HMAC records/mac envelope，family_key 直接索引单条记录。
3. 原 attempt_count 和 phase 在该 family record 上；首次授权1、失败后重签第2次，prepare不增加次数，重启不清预算。
4. Hook 原 TaskFix verifier 成功或显式 verify 成功，把同一 record 的 phase=CLOSED。
5. NEW 候选只允许 equivalence_key 不在 rows，已有 family 或16行上限都合并输出 FAMILY_CLOSED_OR_BUDGET_EXCEEDED。
6. 没有独立 episode/positive absence receipt/history，导致“历史成功关闭”“active预算”“真正复发”被混为同一个永久存在的 family 行。
7. 可复用现有 session envelopes、workspace OS lock/HMAC、固定 scan/member task_ref、随机 rem-v1 grant、TaskFix/VerificationService。没有另一个已实现 episode 模型；本轮保留这些入口，增加 current episode metadata 与跨 session 最新 episode 检查。

### AW.2 最终模型与授权边界

| 层级 | 当前数据与含义 |
|---|---|
| Family | eq-v1 长期 identity；workspace 隔离，不因行号移动创建新 family |
| Current episode | episode_id（随机）、episode_number、原 phase/task_ref/origin_scan/guards、attempt_count、可用 token hash |
| Resolution | 仅原 scanner verifier 成功写入的 signed SCANNER_VERIFIED_RESOLVED + 安全 snapshot_digest + 可用 hook_scan_id |
| History | 旧 episode id/number/attempt_count/CLOSED/resolution/task_ref_hash；不保存 raw bearer/source/Secret/prompt |
| Attempt | 发修复 grant 时分配；初次 AUTO=1、确认前=0、批准后=1、失败重试=2；max_attempts=2不变 |

recurrence 必须先有最新 episode CLOSED 和正向 resolution，再由之后新的 SCANNED/last_check_status SCANNED、不同于消失时的 snapshot、COMPLETE_RULE_FILE_SCOPE presence、新 scan_id（非origin/resolution）观察到相同 family。随后按当前 scanner/pack/rule/file/checksum/engine/proofs/triage/policy 校验，不能提高 priority 推进。AUTO 按原窄 TLS 策略发新 grant；ask_before_fix 新 PENDING_CONFIRMATION/attempt0；report_only 或其它未授权结果新 OBSERVED/attempt0，无 grant，旧授权失效。

同一 active/exhausted family、重复触发、NO_CHANGE/REUSED/DEBOUNCED/FAILED/PARTIAL、未证明 absence、换 host/session、进程重启都不能创建新 episode 来重置预算。exhausted 后允许原范围人工最小修复；必须新 Hook 完整 absence + 原 TaskFix verifier 成功 + 稳定 source/preservation/snapshot，才关闭旧 episode，且不额外授权修复。OBSERVED 缺 narrow guards 时仍不能关闭为已证明 resolved。

reference 是 opaque。task-v1 仍为 workspace + 固定 scan + 精确成员，不直接编码 episode；recurrence 使用新 scan 的不同 task_ref，并拒绝同值。rem-v1 外部格式不变，随机新 token/hash 绑定 current signed episode。旧 grant/confirmation/functional receipt 查找必须仍是 workspace 最新 episode；旧准备/批准/Stop handoff 清除，no-grant legacy task gate 也拒绝历史 task_ref_hash。Runtime 不编辑，不执行模型/目标build，不保存新源码/Secret/model prompt。

### AW.3 reason 与 migration

移除输出混合 FAMILY_CLOSED_OR_BUDGET_EXCEEDED；active attempt limit 的 ATTEMPT_LIMIT 改为 EPISODE_ATTEMPT_BUDGET_EXCEEDED，action仍ESCALATE。另区分 EPISODE_ALREADY_EXISTS、EPISODE_RESOLUTION_NOT_PROVEN、REMEDIATION_FAMILY_BUDGET_EXCEEDED、EPISODE_HISTORY_BUDGET_EXCEEDED。政策 SAFE_DETERMINISTIC_FIX/USER_CONFIRMATION_MODE 保留；新增 episode_reason_code=RECURRENCE_AFTER_RESOLUTION / FIRST_OCCURRENCE。无合法 family 永久关闭语义，不新增 FAMILY_CLOSED。依赖旧 reason 字符串的客户端需接受新 enum；按 action/原 handoff 的客户端无参数迁移。

无 SQLite schema/key migration。旧 signed rows 先验 MAC，再只读映射 #1、预算不变；读取/prepare 不因 migration 写盘。旧 CLOSED + 已签名 last_verification=SCANNER_VERIFIED_RESOLVED + 有效64位安全 snapshot/source_guard/preservation_guard 保留其旧正向 scanner proof（hook_scan_id未知None），允许之后真正新scan开启Episode2。CLOSED alone/缺marker/缺guards则resolution=None，不能仅凭phase开复发权限；须新完整 absence+原 verifier 或原显式 verify 成功补证。mutation 写新 metadata。损坏、不完整或同 workspace 多个旧 namespace 同 family 同编号歧义 fail closed；不自动合并/删状态/换 key。最多16 episodes/family、16 families/262144 bytes/envelope、64 envelopes/workspace，达到上限明确停止，不丢历史重置。新 OBSERVED phase 旧 Runtime 不识别，会 fail closed；不承诺旧版本状态回滚兼容。

### AW.4 自动化与真实本地证据

新增 [episode tests](../tests/test_remediation_episodes.py) 共34项：首次授权、active重试同episode、预算耗尽/重复/restart、scanner关闭、同family recurrence/新引用、未prepare/未resolved、不完整/失败/缺scanner/timeout/guard缺失不得假关闭、exhausted人工修复后复发、workspace隔离、换session不得重置/可合法复发、旧remediation/混搭task/functional receipt/no-grant任务拒绝、当前report_only/ask策略、legacy active/CLOSED-alone/旧signed scanner-resolved只读迁移、历史上限、reused/debounced/partial scan拒绝、伪NEW不得重置、signed malformed metadata、policy budget enum、无源码/Secret/bearer持久化。现有非recurrence、confirmation/persistence、Stop、command hook、functional、Raw/覆盖保护由最终完整回归覆盖。旧generic Host测试改为禁止同family换namespace重发，并证明不同新family仍可CONFIRM_REQUIRED，单独复核1 passed（3.95s）。

| 门禁 | 本轮真实结果 |
|---|---|
| saved baseline（未重跑旧HEAD） | 987 passed /6 skipped /6 subtests，前阶段 AV |
| 首轮定向 | 66 passed，255.24s（早期实现+首批18新增） |
| episode 定向 / 兼容追加 | 33 passed，224.56s；追加最终legacy分支后3 passed /31 deselected，17.40s；全部34由最终full覆盖 |
| 首次完成 full offline | 1020 passed /1 failed /6 skipped /6 subtests，877.96s；失败为既有 concurrent setup KeyError: operation，单独复跑通过，不计整轮PASS |
| 最终独立 full offline | PASS：1021 passed /6 skipped /6 subtests passed，896.06s（wrapper896.62s）；实现/断言不变，其它验收结束后独立复核，含原concurrent setup与全部34项episode测试 |
| actual local MCP/scanner recurrence | PASS，55.31s，见 [SDK evidence](remediation-episode-sdk-evidence.json) |
| wheel/sdist/package/compliance | PASS，3.54s，101打包源码/数据bytes一致，见 [package evidence](remediation-episode-package-evidence.json) |
| clean install / native rebuild | 本轮未运行，不冒用前阶段通过；活动native/MCP进程与包保留 |
| commit/push/new CI | 本轮未执行，用户明确禁止主动commit/push；无新CI |
| fresh Desktop / Ground Truth | PENDING_ACTUAL_DESKTOP / UNREVIEWED/null |

实际 MCP SDK 驱动 [script](../scripts/remediation_episode_acceptance.py) 在一次性 Git project 同连接同文件执行 safe baseline→unsafe→AUTO episode1→原refs prepare→driver最小safe edit→Hook resolved/CLOSED→verify→同一unsafe复发→AUTO episode2→新refs prepare→再次resolved/CLOSED。相同family、不同episode/ref、旧prepare被拒绝、原refs逐字roundtrip均有assert；使用已缓存 Semgrep/Gitleaks、离线、无模型/目标build/源码上传/Secret操作。驱动只编辑一次性fixture，**SIMULATED_HOST，不是 Codex Desktop 自然 continuation**。证据不保存 raw task/remediation references。functional credential lifecycle NOT_TESTED_OUT_OF_SCOPE。

范围审计 PASS：与起点 HEAD 比较，除两个核心文件外其余106个 Runtime 文件不变；GUIDANCE/CONFIRMATION_GUIDANCE/CONFIRMED_GUIDANCE、POLICY_VERSION 与 CONFIRMATION_TTL 不变。六项 skipped 单列：tests/test_e2e_real.py 的38、58、68、80、120、154行，需要该套测试能从 PATH 发现真实 scanner binaries，当前前提未满足；不计 PASS，不等同于独立 MCP/managed scanner 验收失败。

测试环境记录：沙箱读取pytest/build私有临时目录失败，改在权限允许的离线测试环境执行；第一次把basetemp设在产品仓库内，使4个无项目CLI用例向上识别产品Git，已中断并改仓库外独立目录；未修改产品逻辑/放松workspace边界适配该问题。迭代中的未完成full不计成功。首次完成整轮的原 concurrent setup 用例曾间歇失败，隔离复跑1 passed /58 deselected（1.57s）；其CodexIntegration/HookCoordinator实现未改，不修改或放宽该测试，根因未独立证明。最终独立整轮1021 passed，包含该用例；保留首次失败记录，不将首次整轮改写为PASS。完整日志与完成记录在本地 .security-runtime/episode-final-offline.log/.json（忽略目录）。

### AW.5 人工 fresh E2E（Pending）

1. 在一次性 Git测试项目绑定本轮源码版本的 Runtime MCP；当前活动旧native包没有被本轮替换，不能以旧包验收新生命周期。正常按既有integration/Hook信任流程加载，建立安全基线；不调查cold-start/readiness。
2. 同一个新Chat创建 `src/main/java/demo/CodeModeTlsService.java`，保持默认 TLS。确认safe Hook/有效baseline后，只在该文件加入 `connection.setHostnameVerifier((hostname, session) -> true);`。等正常PostToolUse，不主动独立扫描/build。
3. 记录新Hook的family/episode_id/episode_number=1、AUTO、attempt1、原task_ref/remediation_ref。直接用户授权完成本测试；若宿主自然continuation拒绝，单列Host问题，不改Hook prompt来使其通过。
4. 用Runtime原hand-off逐字调用prepare_task_fix，READY后只删该行。等Hook确认SCANNER_VERIFIED_RESOLVED/CLOSED；记录signed receipt、scanner状态及episode1，未证明resolved不得继续造复发。
5. 同Chat、同文件再加同一行。正常Hook应同family、新episode_id/number2、episode_reason_code=RECURRENCE_AFTER_RESOLUTION、当前policy允许时AUTO/新task_ref与remediation_ref、首次授权attempt1（未授权0）。不能再以FAMILY_CLOSED_OR_BUDGET_EXCEEDED永久阻挡。
6. 原样使用第二轮refs准备/只删该行/等scanner复核，不混用旧ref；将两轮结果、scanner覆盖、ref逐字一致性及旧授权拒绝单列。结束时文件保持安全。functional credential测试另行授权，本轮不扩大。

### AW.6 未改与Pending

本轮核心源码仅 remediation.py 与 remediation_policy.py（reason enum），新增测试/本地SDK验收脚本与五份既有文档/证据。HookCoordinator family multiset/baseline/snapshot/cooldown/single-flight、Codex/command feedback与ABI、HostContinuationGuard/prompt、TaskFix/VerificationService、functional providers/credential状态机、CET等均不改。无提交/push、无新CI、无实际项目源码或系统配置修改。三位试用Pending、独立Ground Truth UNREVIEWED/null、质量NOT_MEASURED、真实Maven A/B PENDING_ENVIRONMENT_PREREQUISITES；既有远端CI账户问题仍PENDING_RERUN_AFTER_ACCOUNT_RECOVERY。自动continuation与functional credential的独立已知问题保留，完成本轮后停止。

## AV. AUTO_FIX PostToolUse Code Mode Contract Fix v0.1

### AV.1 最新实机事实与根因

用户回传的SETUP_SEED/NEW1/AUTO_FIX证明baseline seed/归因/检测策略USER_REPORTED PASS。旧PostToolUse返回block/reason，Code Mode工具执行后nested promise拒绝，与Script failed及随后危险编辑retry一致。没有prepare/edit/receipt，resolved0，retry后SESSION/NEW0/ESCALATE。Stop未进入，**NOT TESTED**，不是Stop FAIL。不是readiness/trust/scanner根因。旧AU是历史，这次反馈覆盖seed Pending；新的transport Desktop仍Pending。

### AV.2 输出协议与保护范围

before：`{"decision":"block","reason":"<original AUTO guidance>"}`；after：`{"continue":false,"stopReason":"<fixed already executed / no retry / authorized remediation / prepare prefix + original bounded guidance>","systemMessage":"<unchanged AUTO authorization message>"}`，继续保留原hookSpecificOutput safe metadata。AUTO action/interaction、prepare/verify的mcp_tool与arguments、grant_id原样，无risk语义变化。CONFIRM continue:false/stopReason+ask/WAIT；NONE无停止；Stop block/reason、不返回continue:false。

唯一Runtime源码差异为codex_mcp_hook.py AUTO分支。101打包文件wheel/sdist/source逐字节一致，66个sdist test文件与最终通过的源码一致，其余全部Runtime tracked files与starting HEAD一致（未打包rules说明仍逐字节git核对）；ABI exact相同，核心算法与state/scanners/rules/policy/verification/functional/command均未改。无自动grant重签/续期或retry容错。测试[新契约](../tests/test_codex_code_mode_contract.py)含specification oracle，明确旧block导致rejection、新continue:false不reject并有原guidance，只是contract simulation，不冒充Codex内部或Desktop模型。

### AV.3 实际测试与分发

| 门禁 | 真实结果 |
|---|---|
| saved baseline（本轮未重跑旧HEAD） | 982 passed /6 skipped /6 subtests passed |
| focused AUTO/CONFIRM/Stop/NONE+原修复 | 156 passed in 383.80s (0:06:23) |
| targeted seed/missing-first/untracked/preexisting/family/confirmation/Stop/equivalence/Fix/Functional/lifecycle/readiness | 534 passed in 1007.83s (0:16:47) |
| final full offline | 987 passed, 6 skipped, 6 subtests passed in 1142.05s (0:19:02) |
| wheel/sdist/package/compliance | PASS，5.67s，23 first-party rule files；最终sdist tests与已通过full的文件一致 |
| bytes/source/ABI | PASS，101打包文件，其余全部Runtime文件不变，exact frozen Hook定义 |
| source SDK actual MCP/local Scanner | PASS，62.93s，driver/模型边界分开 |
| clean venv | PASS，66.0s，117 cached wheels、noeditable/nosystemsite/nodownload |
| Windows native新目录 | PASS，158.03s，source_commit=1033abfd5c467661a2a7110442bcc410851e9bb1 |

六项skipped（不是PASS）：tests/test_e2e_real.py:38、58、68、80、120、154，需要PATH真实Scanner；source/clean/native使用已缓存本地引擎的实际链路另有PASS证据。前期新增测试对handoff字段/状态的错误假设已修正，最终suite无失败，未调整生产契约。构建工具首次受Windows临时目录沙箱权限限制，授权范围内重跑成功，无下载/门槛降低。

### AV.4 本地链路与fresh Desktop

[source SDK](code-mode-sdk-evidence.json)、[clean](code-mode-clean-evidence.json)、[native](code-mode-native-evidence.json)：setup READY→deliberately skip first safe Hook→danger first effective SETUP_SEED/NEW1/AUTO_FIX/continue:false→original Stop fallback→driver prepare→driver secure edit→resolved1/SCANNER_VERIFIED_RESOLVED/CLOSED→functional prepare NOT_AVAILABLE/SECURITY_VERIFIED_FUNCTION_UNKNOWN、无functional run/duplicate explicit verify。preexisting PERSISTING1/NEW0/NONE安静；setup幂等/healthyrepair/remove/re-setup与readiness保留。实际Runtime/MCP/Scanner测试，不调用模型；自然PostToolUse和fresh Desktop **PENDING_ACTUAL_DESKTOP**。

新native路径/source_commit/exe SHA256见native证据；现有运行包/进程未覆盖/终止。fresh命令见CODEX_INTEGRATION。使用全新disposable fixture而不是旧ESCALATED trial，正常Review & Allow/退出重开。路径A无需Stop，路径B原Stop最多两次；最终AUTO_FIX YES / Script failed NO / dangerous retry NO / prepare YES / secure edit YES / resolved1 / SCANNER_VERIFIED_RESOLVED / duplicate explicit verify NO，Stop YES或NO均可。未真正执行不写PASS。

### AV.5 实现提交与新CI

starting `50f002deff33d0946ee99c338d700b08a739e394`；implementation `1033abfd5c467661a2a7110442bcc410851e9bb1` 已推送feature/runtime-mvp。最终docs SHA用git log核对。新CI实际结论 **PENDING_RERUN_AFTER_ACCOUNT_RECOVERY**，逐run/jobs/steps/annotations证据存[结构化记录](code-mode-acceptance.json)。四平台执行必须有真实Runner/steps，不能拿本地Windows PASS代替。

| workflow | 新 run | GitHub conclusion |
|---|---|---|
| Runtime tests | [37186165206](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37186165206) | failure |
| Compliance | [37186165194](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37186165194) | failure |
| Package integrity | [37186165213](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37186165213) | failure |
| Standalone artifacts | [37186165218](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/37186165218) | failure |

新CI全部未分配Runner、steps为空；failure annotations明确近期账户付款失败或支出限额。不是代码PASS，也不是已执行的代码测试失败；保持PENDING_RERUN_AFTER_ACCOUNT_RECOVERY，不改账户/workflow/契约。

### AV.6 Pending / safety

新Desktop自然/Stop修复闭环PENDING_ACTUAL_DESKTOP；Stop最新实机NOT TESTED。CI PENDING_RERUN_AFTER_ACCOUNT_RECOVERY。Maven A/B PENDING_ENVIRONMENT_PREREQUISITES、不搭环境/装系统依赖/联网下载构建依赖。三位试用PENDING、Ground Truth UNREVIEWED/null、质量NOT_MEASURED。Runtime无源码编辑/模型/build/Scanner联网/Secret rotation；driver只改disposable合成fixture。未改Jeepay、真实用户fixture、benchmark/labels；仅官方文档/GitHub授权交付联网。其余阶段Planned，完成后停止。
## Core P0-7.3 — Host Claims 验收附录

Core P0-7.3.1 增量验收单列：[Recent Hook](recent-hook-acceptance.md)。25 cases 覆盖入口提交/schema、claims 拒绝、初始化早退分类、事件独立契约、readonly/mutation/no-change、handler/scanner异常、无敏感持久化、workspace isolation、32/1024 retention、late eviction、in-flight 可读、只读无 DB 写入、真实 stdio MCP→独立 CLI/restart。最终专项 25 passed / 52.06s；最终 frozen focused 190 passed / 293.43s；最终 full offline 1470 passed / 9 skipped / 6 subtests passed / 2722.77s，零失败。[回归及 skipped 原因](recent-hook-regression.json)：3 项需要显式 managed Scanner benchmark 环境，6 项需要真实 scanner binaries，不能计为 PASS。最终候选包/合规 PASS / 8.67s；临时 installed Global stdio MCP→独立只读 CLI/config preservation PASS / 51.31s。新增配置定义未变化，不通过 diagnostics 授权任何行为；Desktop/user config/active Runtime 未触碰。

新 claims 专项 27 cases：valid Bash/apply_patch 后进入现有 coordinator；required 缺失/malformed/额外字段安全诊断；readonly 不扫；mutation snapshot scope；session root mismatch；same tool_use_id 原样/跨 turn/session/tool 重放；重放 mutation 不创建 bootstrap job、不触发 baseline scanner；SessionStart/Stop 无伪造 invocation；有限哈希 guard/restart；temporary CODEX_HOME signed legacy migration/state/node_repl/user config/Hook/unknown setting preservation，setup/repair 幂等和 owned-only uninstall。新增 current MCP claims 必须来自真实 Host；验收脚本 helper 仅模拟 isolated Host，原 opaque refs 原样传递。

wheel/sdist integrity/compliance PASS；临时安装 Module origin 位于临时 venv，借用已有依赖/no-index/no-deps，无活动 Runtime 替换；原生 Codex CLI 0.160.0 正常读取临时配置。最终 frozen wheel 的 real stdio MCP + real Scanner A1/B1/A2 resolved/CLOSED/RETURN_TO_HOST，跨 workspace 原 refs 拒绝，prepare=0、Stop ALLOW_STOP、Deep NOT_REQUESTED；125.06s。[MCP](codex-host-claims-mcp-trial.json)、[安装](codex-host-claims-installed-trial.json)、[包](codex-host-claims-package.json)。

最终 frozen focused：419 passed / 849.26s（runner 850.02s），无 skipped/failed；full 最终统计及 skipped 单列见 [回归](codex-host-claims-regression.json)。最初受限测试 runner 无权访问临时 pytest dir，未形成产品结果；随后隔离 runner 正常执行。focused 初轮 334 passed/1 failed（旧 readiness properties 断言遗漏 permission_mode）；修正后专项 27 passed。全量随后发现旧 Stop properties 断言，更新可选字段预期后进一步暴露草案 wrapper 的 quiet-output 回归：reason 不得进入 rejected Stop 的 Hook 文本。最终保留 structured rejection、text 为空，专项 27 passed。最后审查把 invocation 原子绑定前移到 classification/bootstrap 之前，避免跨 session 重放先启动 baseline；顺序及兼容专项 92 passed 后重新冻结。较早 full 主动中止，不记 PASS；最终 frozen focused/full 单独记录。P0-7.2 的旧全量是4 failures后仅4专项修正，不改写成全量PASS。

最终 frozen full offline：1445 passed / 9 skipped / 6 subtests passed / 2463.32s（runner 2464.32s），零 failures。Skipped 单列：3 个需显式开启的 managed performance cases，6 个旧 real E2E 在该 runner 缺少 binaries 前提；不记 PASS。最终候选另有真实 stdio MCP + managed Scanner 验收 PASS。

未读取原 Desktop payload/transcript，历史具体拒绝字段 UNDETERMINED；不能说旧 turn/tool-use 缺失直接触发旧 validator，因为旧 validator 未要求它们。新的 diagnostics 可以在实际 Desktop 确认字段。Desktop/trust UI Pending；独立试用/Ground Truth/Maven 等仍按既有真实状态。[完整契约、限制与复测](codex-host-claims-acceptance.md)。
