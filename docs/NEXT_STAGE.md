# Next Stage — AI Triage Quality Validation & Developer Guidance

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

P0-10.1 scope only: visible feedback. Final offline regression PASS (LOCAL VERIFIED; actual visible Cursor UI Pending); local native/installed and Codex recurrence checks passed. Actual Cursor UI remains Pending; no next phase, auto repair, Scanner work or Deep Verification expansion.

See [acceptance](cursor-visible-feedback-acceptance.md) for binding, bounds, privacy, native race evidence and manual UI trial.


## P0-9.6 stop point

本轮仅 Finding/Policy → remediation execution capability 接线。旧 config.path 阻塞由本轮消除；冻结 Cursor ingress/schema/anchor/generation/lifecycle 与 P0-9.5 attribution，保留 Codex inline/Envelope/真实 proof/recurrence。

完成 focused/full、managed Scanner Cursor command fixture、Codex local MCP recurrence、package/integrity/compliance 后停止。不运行真实 Desktop、不安装活动 Runtime、不修改真实用户配置、不 commit/push。下一次用户 Desktop 只验证首次 TLS attribution 后 recent 中 policy/capability/OFFERED，不要求自动 Agent Fix/CLOSED；Cursor live continuation 仍 Pending。三位试用、独立 Ground Truth 和其他阶段保持真实 Pending/Planned。


## P0-9.5 scope / stop point

本轮仅共享 Runtime 首次风险归因。P0-9.4 的 Cursor transport/binding/lifecycle 已有用户真实 Desktop 通过证据，保持冻结；本轮 Desktop 未执行。归因成功后的现有 core policy 已有定向验证；真实 Cursor command 到 policy offer 仍被已有 config.path 接线错误阻塞，本轮不擅自修改。

本地回归完成后停止。下一次用户验收先使用可从 Git index/HEAD exact-digest 恢复的安全 tracked file，确认新 conversation 的 SessionStart scanner=false，再仅加入 TLS bypass，读取 recent 的 first_scan_attribution_*。无需 full pre repo scan。dirty old bytes 未存于 Git 时预期 inconclusive，不能承诺成功。

Cursor live continuation、部署/真实新 Desktop 试验、三位试用者、独立人工 Ground Truth 保持真实 Pending；功能修复与验证、Deep/其他阶段继续 Planned。本轮不安装活动 Runtime、不改用户配置、不 commit/push。


## P0-9.4 — Cursor Event Lifecycle + Baseline Ordering

P0-9.4 本地实现与必要验证推进；真实 Cursor 新生命周期仍待用户最小复测：新 conversation 先确认 SessionStart baseline Published/no scanner，再普通 timeout 2300→2400 一次，独立 hooks recent 应 delta=1、scanner=true、invocation=1，Stop不扫描。不得再修改已真实通过的 claims/generation/anchor/containment。

本轮不运行真实 Desktop、不安装活动 Runtime；之后停止，后续阶段仍 Planned；Cursor live continuation、三人试用和独立人工 Ground Truth保留Pending。

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

## Core P0-7.3.2 — Current delivery gate

Only the reproduced Global workspace admission/configuration verification bug and bounded diagnostics. Project C root aliases verified read-only; final focused 180 passed, candidate package integrity/compliance passed. Final frozen full offline 1498 passed / 9 skipped / 6 subtests passed, zero failures. [Final evidence](workspace-binding-regression.json). Local delivery complete; stop here. Actual Desktop mutation/scanner gate remains user scheduled after MCP reload; no setup/repair/trust reset prescribed. Incoming dirty work preserved; no commit/push, real config writes, active process replacement or later stage.

## Core P0-7.3.1 — Current delivery boundary

Only persistent recent Hook observability. Final boundary suite 25 passed, frozen focused 190 passed; final full offline 1470 passed / 9 skipped / 6 subtests passed, zero failures. Package integrity/compliance and temporary installed Global MCP→independent read-only CLI passed. [Final regression](recent-hook-regression.json). Fresh Desktop gate is user scheduled and old edits are not backfilled. No matcher/claims relaxation, Scanner/remediation/Ticket/envelope/baseline/bootstrap/Deep expansion, P0-8, commit/push or active/user-config replacement. Local delivery is complete; stop here. [Contract and Desktop steps](recent-hook-acceptance.md).

## P0-7.2 delivered

Codex Bash/PostToolUse coverage and lazy bootstrap are implemented and verified in focused tests. Full offline regression and temporary-package evidence are the remaining delivery records for this stage. Desktop validation remains user scheduled; P0-8 is not started.

## Core P0-7.1 — Codex host-owned Hook state compatibility

仅修复配置兼容性，feature/runtime-mvp / ee1bfd9c12493683cc313cb3628753a51ae124ac 不变。不 commit/push、不替换活动 Runtime、不读写真实用户 CODEX_HOME；前序 dirty 保留，PROJECT_CONTEXT 未读写，P0-8 未开始。

已确认根因：_config 将 TOML hooks.state dict 当 event list；base/global 后续重复 Hook 检查也直接遍历所有 hooks 值。按当前官方 HooksToml / HookStateToml schema，仅对 TOML 的 state 建立明确 metadata 分支；每条 state 是 object，enabled 为 bool、trusted_hash 为 string。官方未封闭 state object 的扩展字段，保留其值；未知其它 hooks dict 不获得豁免。独立 hooks.json 保持 event-only 校验。真正 event groups/handlers、command/server/tool/input/timeout/statusMessage 校验与签名 ownership 冲突检查仍 fail closed。Runtime 不使用这些 host trust values 决定自有 ownership 或修改 trust。

只建立 event-only view，不改变原 parsed document；现有 signed managed block/CAS 合并保留 TOML 原字节，uninstall 恢复原 user bytes。state 与 node_repl、用户 inline/JSON Hook、未知 top-level 设置共存；setup/repair 两次稳定且无无意义重写。两种实际定义来源仍按既有 duplicate 检查处理；state 不算 event source。[详细验收及官方来源](codex-hook-state-acceptance.md)。

新增 25 cases；focused 160 passed / 121.85s；最终 full offline：1414 passed, 9 skipped, 6 subtests passed in 1853.57s (0:30:53)（runner 1854.15s），9 skipped 单列不计 PASS。[回归](codex-hook-state-regression.json)。wheel/sdist integrity + licenses/notices compliance PASS，[package](codex-hook-state-package.json)。temporary venv 强制安装本轮 wheel，确认 module origin 在其 site-packages，借用已有依赖、无网络下载；实际 CLI setup→setup→repair→repair→status→doctor→uninstall 全 PASS，实际 Codex CLI 0.159.2 正常解析脱敏 state 且同时发现 node_repl/ai_security_runtime。[安装验收](codex-hook-state-installed-trial.json)。修复前隔离结构 fixture 为 CONFIG_INVALID，修复后 MCP/Hook CONFIGURED；不是实际 Desktop Hook trial。

现有两份产品模块仅 narrow compatibility hunks；新增 test/fixture + MANIFEST fixture include。router/remediation/Ticket/Scanner/Deep/CET 与 incoming 字节相同；[前序工作区保留审计](codex-hook-state-workspace-audit.json)。真实 Desktop 验收仍 Pending，三位试用待验收、独立 Ground Truth 未执行，未扩大本轮范围。


## Core P0-7 当前交付；其它迭代继续 Planned

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

focused：PASS: 138 passed in 811.85s (0:13:31)。

full offline：PASS: 1325 passed, 9 skipped, 6 subtests passed in 2131.43s (0:35:31)。skipped 单列不计 PASS；此前 9 skips 的 PATH/opt-in managed 条件保留，真实 Scanner 另走 SDK gate。

MCP / managed Scanner：PASS / 341.96s。[core](inline-exactness-core.json)、[legacy fallback](inline-exactness-fallback.json)、[legacy client](inline-exactness-legacy-client.json)。实际 stdio MCP + 离线 managed Semgrep/Gitleaks；Host 编辑是一次性 native fixture simulation，**不是 Desktop**。旧 P0-6 hash-verified wheel source 重现 risk absent 仍 TICKET_TARGET_NOT_EXACT/ESCALATED；新 LF/CRLF × BOM/no BOM、mixed+BOM、statement/old canonical、recurrence 取得当前 original-rule proof；邻接业务编辑在 Scanner risk absent 时仍拒绝且无 resolution。旧 refs 在 recurrence 计时后拒绝，不序列化/重建引用。正常每 cycle 2 Runtime Hook MCP、0 prepare、1独立 test Host RPC；额外状态检查 RPC 在计时后单列。每成功 cycle 仍 2 Hook SAST + 2 Hook Secret + 1 canonical rule recheck，共5真实进程 invocation；失败 envelope 在4次增量进程后拒绝、不会伪造第5次 proof。并发 focused 测试期间样本仅证明 correctness，不作性能提升结论。

wheel/sdist package integrity / licenses+notices compliance：PASS / 7.81s，[package](inline-exactness-package.json)。没有 clean install、standalone、CI 或活动替换，未请求新增这些 gate。

初轮新增 direct cases 32 passed / 1 failed：mixed EOL 改动且尺寸缩短时，诊断优先给 TARGET_RANGE_DRIFT；只修诊断分类优先级，不放宽 acceptance。下一轮 35 passed / 13 setup errors：新 module 导入 fixture 时缺少 repo fixture，补显式 fixture import，旧测试未改。修正后 48 passed（46新+2旧 inline契约）；最后再加2个合法 statement variant + scanner FAILED/UNAVAILABLE 不能关闭的 case。历史日志均保留，最终以 focused/full 为准。

Fresh Desktop 本轮 NOT_RUN，下一次仅用户自行安排加载本轮 Runtime 后，隔离 fresh chat：safe baseline → 引入唯一独立 TLS 风险及一个紧邻真空行 → Hook INLINE_PREPARED → Agent read一次并按 envelope删除风险行及该空行 → post-edit Scanner + canonical proof → CLOSED/RETURN_TO_HOST；核对 accepted_variant、outside_changed=false、原 refs逐字、prepare count0和原timing。另验证 statement-only、CRLF/BOM 原样保持，以及风险移除同时改邻接业务行仍拒绝。缺字段/stale立即停，不恢复或重建 opaque refs，不主动 build/Functional/独立扫描。

三位真实试用 Pending；Ground Truth UNREVIEWED/null；Maven PENDING_ENVIRONMENT_PREREQUISITES；Fast Host atomic bridge PENDING_HOST_ATOMIC_EDIT_BRIDGE；其它阶段 Planned。PROJECT_CONTEXT 未读写。完成既定门禁即停止。



## Core P0-6: Inline Prepared Agent Fix Ticket / Reliable Handoff

本地实现及既定门禁完成，停止本轮。

focused：PASS: 112 passed in 823.71s (0:13:43)。

full offline：PASS: 1277 passed, 9 skipped, 6 subtests passed in 2174.36s (0:36:14)。skipped 单列、不计 PASS；3 个 opt-in managed benchmark、6 个 PATH scanner 环境条件，真实 managed 引擎另走本地 SDK gate。

actual MCP + managed Scanner A/B：PASS / 69.9s；package wheel/sdist integrity + licenses/notices compliance：PASS / 4.09s / 108 Runtime source bytes checked。没有 clean install、standalone 重建、CI trigger、commit、push、活动 Runtime 替换或 Desktop E2E。

Fresh Desktop P0-6自然续行/模型看到完整Ticket、p95/p99、三位真实试用仍 Pending；Ground Truth UNREVIEWED/null；Maven PENDING_ENVIRONMENT_PREREQUISITES；Fast Host atomic bridge PENDING_HOST_ATOMIC_EDIT_BRIDGE。其它阶段继续 Planned。当前无需继续压缩 Security Context；先验证本轮 Ticket 自然交接，不能把协议减少一次 RPC 宣称模型已少12次调用。

下次人工 Core E2E（本轮未执行）：用户自行安排加载本轮 Runtime 后，新建隔离 Java 项目与 fresh Codex chat；普通安全编辑建立 baseline，再只引入 standalone always-true hostname override。确认初次 Hook 的 INLINE_PREPARED、完整两个原 refs/attestation/context/target、prepare_required=false、工具调用计数0；Agent只read该target和删除该行、保留所有其它字节。不主动扫描/prepare/Deep/build。确认post Hook真实Scanner原规则proof、matched task/grant receipt、CLOSED/RETURN_TO_HOST、计数仍0和inline cycle窗口。再引入同family核对新Episode/Ticket/scan/grant、旧ref拒绝。遇到缺失/截断/stale字段停止，不从路径重建引用；记录实际Host工具数及wall-clock，若仍恢复summary则保留失败事实。



## Core P0-5: Agent Fix Context Compression

仅Core P0-5 Agent Fix Context Compression，继续feature/runtime-mvp/ee1bfd9c12493683cc313cb3628753a51ae124ac与前序全部dirty；162文件incoming快照，P0-4 wheel SHA85576795657bba49bd1380bc1471097630e8f57cb7ed80f1de976f14b712accc只读校验/提取为本地A/B baseline，无安装。Fast Fix文件原bytes保留，PENDING_HOST_ATOMIC_EDIT_BRIDGE；不扩第二条规则、不新增Scanner/daemon/Functional/BOM/CET/Sandbox/Plus/Pro。Runtime仍不写项目源码，Host编辑。

新增test_fix_context.py 11functions/21cases；已有host orchestration及Code Mode契约测试只将smart_auto长prose断言替换为context/自动授权/不重复编辑/实扫等协议语义断言，ask_before_fix与其它旧tests保留。final focused PASS：205passed/822.16s（wrapper823.30s）；final full offline PASS：1240 passed, 9 skipped, 6 subtests passed in 1991.19s (0:33:11)（wrapper 1992.56s）；9 skipped单列BF，不计PASS。第二轮全量早期发现Code Mode旧测试要求stopReason重复完整guidance，单测1failed/4passed/21.99s；仅将该smart-auto文字断言改为精简协议语义，保留completed-edit/授权/两原refs/confirmed/Stop/ABI检查，产品代码未变。第二轮focused/full分别383.65/384.07s中止return130，不计PASS；修正后该模块5passed/19.71s。第三轮focused发现新增context把VALID AI review误判为Scanner过期，既有receipt单例1failed/3.76s；修正仅删除新增review-status条件，原grant/snapshot/source/ref与receipt校验未改。第三轮focused/full分别1139.69/1139.58s中止return130，不计PASS。随后context+receipt 47passed/1failed/316.60s为新fixture伪造VALID但缺ai_review时错误期待授权；已改为断言原TaskFix拒绝且不建立prepared，既有receipt测试原文保留。第四轮full200.13s中止return130，不计PASS。最终focused聚焦直接受影响7模块/205cases，先通过再跑full；新增仍21cases，完整1249收集/9skipped。final MCP A/B PASS/118.06s；原Fast/recurrence/fallback compatibility PASS/112.33s；package integrity/compliance PASS/7.28s，107Runtime文件bytes核对，dist/agent-context-final，无安装。初轮3failed/104passed为新测试过宽source子串及既有_fail无status断言错误，已修；诊断1failed/1passed，v2 context19passed/104.71s。后发现legacy instructions字段缺失、prepare arguments新增hint泄漏到旧verify/Deep/Stop消费者；已修正原两个args与短legacy字段。隔离诊断18passed/1failed/22.15s；失效门禁focused/full在631.58/631.65s中止return130，不计PASS；兼容复核129passed/457.00s。首轮MCP/package/Fast evidence另存initial；并行负载A/B另存concurrent，修正前串行证据另存；final与focused并行重测。产品/测试/脚本158文件冻结。

真实managed Scanner+actual stdio MCP；Host是SIMULATED_WINDOWS_NATIVE_EDIT_FIXTURE，无LLM、无sleep、offline。相同facts+guidance投影8203→4825bytes（减少41.18%），非整个Hook wire payload；final与focused并行负载，修正前串行报告另存agent-context-core-before-review-correction.json；1699bytes为新context本身，legacy不存在该schema故null。MCP主流程仍3=风险Hook/prepare执行前门禁/修复后Hook；额外Host fixture edit RPC单列1，不隐藏成0；Scanner每cycle仍3SAST+2Secret。before cycles23391.335/21004.801ms，after22553.257/22981.665ms。有限样本不证明wall改善，不声称reasoning加速或Host动作减少，固定Host双方同为1read/0search。recurrence旧ref拒绝在已测cycle结束后另作诊断，不混入比较。Runtime context构造有新增绑定/成员校验成本，Scanner/运行波动也存在；未测完整归因，不将全部差值归因模型或context CPU。初轮8203→4424byte报告早于兼容修正，不替代final；并行版119.93s只单列。

产品/测试/脚本冻结，门禁完成，本轮停止，不自行Desktop E2E。下一次由用户明确选择版本/连接：P0-4 baseline与P0-5源码分别fresh Chat、隔离同内容fixture、同模型与指令，refs仅在各自当前Chat使用；同一TLS unsafe edit→prepare→Host最小edit→real proof，不主动scan/build/test。A无context v1；B须READY+1699左右（路径长度影响）context、prepare REUSE_HOOK_CONTEXT、原refs和匹配receipt、无Deep。记录实际Host read/search/MCP以及P0-3跨Host窗，至少一对并重复才能评估LLM波动；不能将模拟数据当Desktop、不能复用跨聊天refs。Fast native仍Pending bridge，SQLi/SSRF/contextual扩展、PersistentScanner/Functional/商业权限仍Planned。

## Core P0-4: Deterministic Fast Fix Path

2026-10-05实际读取[OpenAI官方Hooks](https://learn.chatgpt.com/docs/hooks)：MCP Hook调用已连接server并遵循Hook输出协议，PostToolUse的additionalContext/continue:false提供模型可见反馈；PreToolUse updatedInput只能重写已排队工具。未发现PostToolUse响应能直接启动原生edit、检查当前Episode并原子CAS的官方契约。现有Codex Runtime integration也只输出反馈、四个metadata claims与Agent handoff，apply_patch无whole-file digest CAS参数。因此默认Codex严格保持AGENT_FIX/FAST_FIX_HOST_CAPABILITY_UNAVAILABLE；未实现、未宣称Codex machine-executable或无LLM apply。

受限Fast Fix Plan/validation与真实Scanner闭环已经在simulated Host实现；生产Codex fast apply保持HOST_CAPABILITY_UNAVAILABLE，不能把它写成已支持。新增test_fast_fix.py共44cases（18functions），最终focused PASS：392 passed in 1003.12s (0:16:43)（wrapper 1004.17s）；final full offline PASS：1219 passed, 9 skipped, 6 subtests passed in 1450.17s (0:24:10)（wrapper 1451.03s）；9 skipped单列如下BE，不计PASS。final local MCP + managed Scanner PASS/93.04s（无sleep，无model、network或Deep）；四个cycle均真实resolved/CLOSED，含Fast recurrence与篡改plan后的Agent fallback。final wheel/sdist/package integrity/compliance PASS/5.82s，106Runtime文件bytes一致，dist/fast-fix-final；未安装。首轮测试接线/文本拼接/CRLF断言修正、首次sdist缺脚本、为严格JSON防篡改中止的旧门禁均另列BE，不算PASS。

产品/测试/公开脚本已冻结，本轮门禁/记录完成，停止，不自行Desktop E2E。下一次Desktop只可验证当前标准Codex的明确Agent fallback和原安全闭环；不要期望凭plan自动执行。真正Fast Desktop试用须先有受支持Host bridge执行前authority validation+目标写/rename排他+CAS，届时再独立安排。Functional/Build/Sandbox/CET/Plus/Pro/PersistentScanner、第二类Level1规则仍Planned；三位试用/独立GroundTruth/Maven保留真实Pending状态。

## Core P0-3: AUTO_FIX Continuation Latency Observability

当前只审查六文件误操作并完成AUTO continuation可观测性。保留既有骨架，修正关联与计时语义；新增21cases，initial98passed；最终focused 348passed/782.04s；full offline 1175passed/9skipped/6subtests passed/1206.43s；本地MCP simulated Host PASS/65.10s，两Episode（direct prepare/Stop fallback）分别cycle 14353.014/15369.367ms，均真实Scanner resolved/CLOSED/RETURN_TO_HOST，functional 0、build/test/sandbox false。final wheel/sdist/package integrity/compliance PASS/4.57s，105Runtime文件bytes核对一致，独立dist/continuation-latency-final；未安装。初轮MCP/package另存initial证据，不能替代final。v1三项诊断WAIT标签冲突及中止的full如实见BD，旧断言未改。结果与误操作各文件清单见[BD](AI_TRIAGE_ACCEPTANCE.md#bd-core-p0-3-auto_fix-continuation-latency-observability)。产品/测试224文件冻结核对通过；门禁与记录完成并停止，不commit/push/替换活动Runtime。

下一次真实Desktop应明确加载此源码后，捕获当前同连接/同Episode risk→prepare→fix→resolved的timepoints、breakdown/detail/boundary，保留不重叠窗口与unknown子项；两次recurrence独立，重连未知不影响安全事实。不能用模拟driver14.35/15.37s声称真实36170ms已优化。FastFix只分析未实现，PersistentScanner未开始；Functional/Plus/Pro/Sandbox/CET/新scanner与后续阶段继续Planned，三位试用/独立GroundTruth/Maven真实状态不补PASS。


## Core P0-2.1: Cache Lifetime & Scanner Invocation Reduction

当前仅实现process preparation lifetime、Gitleaks batch诊断与Episode cycle wall-clock。新增17项合同测试+2项显式真实managed测试；两项旧object-recreation期望改为cache保留，真实Python进程重启另测MISS/新identity。最终focused485passed/774.14s、full1154passed/9skipped/6subtests passed/1558.46s；package/compliance PASS，显式真实managed新2passed/43.89s及原兼容1passed/13.89s，本地MCP三安全编辑/两Episode PASS/56.68s。串行基准及文档完成，停止本轮，不commit/push/替换活动Runtime。冷路径未改善、一般warm改善小；消除同进程对象重建丢cache与Gitleaks五目标五进程的浪费，仍保留fresh安全复扫。结果见 [BC](AI_TRIAGE_ACCEPTANCE.md#bc-core-p0-21-cache-lifetime--scanner-invocation-reduction)。

下一次Desktop需先确认instance/cache_generation与真实target数，连续3安全编辑→TLS AUTO_FIX→安全闭环→recurrence，各Episode记录remediation_cycle_wall_ms，不加阶段或把Host窗口当CPU。重连后观测UNKNOWN正确，实际重启冷MISS正确。Persistent Scanner未实施；先用稳定热连接数据与隔离/失效设计判断下一轮PoC，不自动开始。Functional/Plus/Pro/Sandbox/CET/新scanner等继续Planned，三位试用/Ground Truth/Maven真实Pending状态保留。


## Core P0-2: Scanner Hot Path Performance

当前实现为Priority A低复杂度准备复用、真实scanner分项诊断与original-rule targeted recheck。Core默认安全闭环和no Deep保持；新增25项cache/proof合同测试与1项显式真实managed性能test，最终focused406passed、full1137passed/7skipped/6subtests passed、显式managed性能test1passed，完整结果记录于 [BB](AI_TRIAGE_ACCEPTANCE.md#bb-core-p0-2-scanner-hot-path-performance)。package/compliance、managed基准、本地MCP两episode E2E及文档均已完成，停止本轮，不commit/push/替换活动Runtime。

用户Desktop baseline已真实观测约5秒scan，优化后的Desktop仍Pending。下一轮实机核对scanner_diagnostics的cache/count/scope与cold/warm区别，不把Host continuation window加Runtime内部耗时，不取消securityproof。剩余CLI调用固定成本、内容identity hashing、Git/workspace/snapshot及多dirty-file保守范围需真实项目测量；p95/p99/常开体验NOT_MEASURED。worker未实施，若将来需要先给隔离/失效设计，不开始daemon或新阶段。三位试用/独立Ground Truth/Maven环境真实状态保留；Plus/Pro/Deep/Sandbox/CET/Dashboard/新scanner继续Planned。

## Core P0-1: Hot Path Policy & Integration Hardening（2026-10-04）

当前范围为默认 Core 安全热路径、真实 timing、只迁移自有配置的 setup/repair。默认安全 resolved 后返回 Host，不自动 functional/build/test/full scan/regression/sandbox；已有 Deep MCP/API 保留显式使用。Core IMPLEMENTED，最终focused **272 passed（413.00s）**，full offline **1112 passed /6 skipped /6 subtests passed（1132.03s）**；package/compliance、本地MCP+Scanner PASS，详见 [BA](AI_TRIAGE_ACCEPTANCE.md#ba-core-p0-1-hot-path-policy--integration-hardening)。实现、既定门禁与文档完成，停止本轮；不 commit/push/替换活动 Runtime。

本地 SDK PASS 不替代 fresh Desktop 自然续行验收。当前 P0 待验证：真实 Host AUTO_FIX 到 prepare 的稳定性、真实常开延迟/p95/p99、scanner 约5s及resolved双扫描成本；不可通过删安全复扫改善数字。未 attested 自定义冲突保持 fail closed，不做破坏性 repair。三位试用/Ground Truth/真实 Maven 环境状态保留。Deep Verification/Plus/Pro/Entitlement/Dashboard/新 Scanner/Sandbox/Enterprise Gate 等继续 Planned；不安排 Desktop Functional E2E，下方历史步骤不构成当前待办。

## Deep Verification protocol correctness fix（2026-10-04）

本轮仅修 SECURITY_RECEIPT_REQUIRED_REFRESH：绑定当前 workspace/task/remediation grant/episode/resolved scan/scope，保留独立 security 事实，增加精确拒绝原因。新增27项，最终 focused **319 passed，864.01s**；full offline **1094 passed /6 skipped /6 subtests passed，1456.64s**，详见 [AZ](AI_TRIAGE_ACCEPTANCE.md#az-deep-verification-protocol-correctness-fix)。测试和记录完成，停止本轮；不 commit/push/替换活动 Runtime，不继续功能验证扩展，不安排真实 Desktop BOM/Functional E2E。前序未提交实现保留。

最新产品方向：Core 默认 Hook 只走增量安全扫描 → Finding/Policy → 必要 AUTO_FIX → 安全复扫 → 返回开发者。已有 Functional Verification/Build/Test/Sandbox 兼容保留为未来 Plus/Pro/Manual/Stop/PR/CI Deep Verification 基础设施。本轮只修协议正确性，不实施能力分层、不迁移默认指导、不删除已有能力。下方旧 AY/AX 的 Desktop 步骤是历史，不构成本轮待办。其他阶段继续 Planned；三位试用/独立 Ground Truth/真实 Maven 环境门槛保持真实状态。

## javac UTF-8 BOM compatibility（2026-10-04）

本轮只修真实 Desktop BOM 兼容，Core IMPLEMENTED；无用户源码修改、无新执行沙箱、无 CET 或功能扩展。focused107 passed（16.30s），最终 full offline **1067 passed /6 skipped /6 subtests passed（1244.51s）**，实际 BOM MCP/Scanner/JDK driver A/B PASS（102.79s）；记录与下一次 Desktop 步骤见[AY](AI_TRIAGE_ACCEPTANCE.md#ay-javac-utf-8-bom-compatibility)。最新用户实际 Host 执行链路 PASS，原 BOM compile FAIL；本次 post-fix Desktop PENDING_ACTUAL_DESKTOP。保留未提交工作，不 commit/push 或替换活动 Runtime。必要回归与文档已完成，停止本轮；其他阶段继续 Planned，不开始下一阶段。

## 功能验证器发现与宿主执行编排 v0.1（2026-10-04）

本轮Core IMPLEMENTED；Java Maven/Gradle/javac、pytest/Go/Node发现与Host固定计划/结果回传/安全功能双维度已接入。最终focused99 passed、Hook receipt兼容2 passed、完整离线full **1054 passed /6 skipped /6 subtests passed（1282.01s）**；本地SDK/JDK A/B及package/compliance PASS，见[AX](AI_TRIAGE_ACCEPTANCE.md#ax-functional-verifier-discovery--host-execution-v01)。保留上一轮未提交episode实现，不提交、不push、不部署/替换活动Runtime。当前真实clean项目仅只读检测；fresh Desktop加载本轮版本后按AX人工复验，未经新有效计划不执行命令。CET、自动continuation扩展、compiler-grade调用链、sandbox基础设施、Enterprise Gate与其它阶段继续Planned/不进入。必要回归及文档已完成，停止本阶段。

## Finding Family / Remediation Episode lifecycle（2026-10-04）

本轮只处理用户确认的 CLOSED family recurrence 无新 remediation 缺陷，Core IMPLEMENTED；最终离线回归1021 passed /6 skipped /6 subtests passed（896.06s），actual local MCP/scanner recurrence与package/compliance PASS。实现/迁移/完整测试见 [AW](AI_TRIAGE_ACCEPTANCE.md#aw-finding-family--remediation-episode-lifecycle)，每 episode 预算仍2。fresh Desktop复验仍Pending；本轮验证及文档完成后停止，未经新明确请求不 commit/push/deploy、不开始其它阶段。

fresh Codex两轮同文件 recurrence **PENDING_ACTUAL_DESKTOP**：Episode #1 scanner resolved→同family重引入→Episode #2/新引用/首次授权attempt1/旧引用拒绝。Hook automatic continuation 和 functional credential 仍为独立问题，不借本轮改 prompt/状态机；CET不引入。三位试用Pending、Ground Truth UNREVIEWED/null、质量NOT_MEASURED、Maven A/B PENDING_ENVIRONMENT_PREREQUISITES；不搭建/下载环境，不把MCP driver写成真实Desktop。其余阶段Planned。

## AUTO_FIX PostToolUse Code Mode Contract Fix v0.1（2026-10-04）

干净起点 `feature/runtime-mvp` / `50f002deff33d0946ee99c338d700b08a739e394`。最新用户真实 Desktop：缺失首安全 Hook 后危险首有效 Hook 为 SETUP_SEED / baseline_available=true / SCANNED / NEW1 / AUTO_FIX，First-run Baseline Seed、归因、AUTO检测策略 **USER_REPORTED PASS**。之后 Script failed、未prepare/未secure edit、resolved0；Host重试危险编辑导致SESSION/NEW0/ESCALATE。**PostToolUse continuation USER_REPORTED FAIL（Code Mode decision:block contract）**；Stop未进入，Desktop **NOT TESTED**，不能写Stop FAIL。readiness/lifecycle已有真实PASS，不再调查。新transport的fresh Desktop自然继续/Stop闭环 **PENDING_ACTUAL_DESKTOP**。

[当前官方 Hooks 文档](https://learn.chatgpt.com/docs/hooks#tool-calls-from-code-mode)核对于2026-10-04：PostToolUse decision:block 在已执行工具后拒绝nested Code Mode promise；continue:false把反馈作为model-visible result而不拒绝promise。只改codex_mcp_hook.py的AUTO_FIX反馈为continue:false/stopReason，systemMessage原样；固定提示前一编辑已执行、不要retry/repeat、授权的是remediation、立即prepare_task_fix，然后附原bounded guidance。无新字段、无原AUTO decision/reason。CONFIRM_REQUIRED原continue:false/stopReason主动询问并WAIT；NONE无停止；Stop仍decision:block/reason生成continuation prompt，不能机械替换。

实现 `1033abfd5c467661a2a7110442bcc410851e9bb1` 已提交推送。focused **156 passed in 383.80s (0:06:23)**；targeted **534 passed in 1007.83s (0:16:47)**；final full offline **987 passed, 6 skipped, 6 subtests passed in 1142.05s (0:19:02)**。六项skipped单列于AV，不计PASS。wheel/sdist/package/compliance、101打包文件bytes integrity、其余全部Runtime源码不变、严格离线clean安装、actual source SDK、独立新目录Windows native均PASS。新四类CI **PENDING_RERUN_AFTER_ACCOUNT_RECOVERY**，实际jobs/annotations见AV；未运行的平台不写PASS。最终docs HEAD按本文件git log核对，其docs-only CI在最终交付回复单列。

AUTO_FIX action/interaction、原task_ref/remediation_ref/grant_id与prepare/verify handoff、policy/guards/verification/state machine保持。HookCoordinator/baseline/snapshot/cooldown/single-flight/family multiset/coverage gating、Raw/脱敏/UNTRUSTED_CODE/session/hash/evidence_refs/预算保持；command hook保留。SessionStart/PostToolUse/Stop的matcher/tool/input/timeout/statusMessage exact Hook定义与起点一致；canonical SHA256 cb407a5d3e175add5d51d90c86e5fd43cb74708b770dc585eab9eca92e82eb8b仅Runtime测试摘要，不猜Host私有hash、不写信任数据库。

SDK/clean/native真实Runtime/Scanner均SETUP_SEED/NEW1/AUTO_FIX，新feedback→driver消费原Stop handoff→prepare→模拟secure edit→resolved1/SCANNER_VERIFIED_RESOLVED/CLOSED，匹配receipt无需重复explicit verify；functional prepare NOT_AVAILABLE、无run。**SYNTHETIC_SDK_NOT_DESKTOP**，不证明自然模型继续。新原生包dist/standalone-code-mode由已提交实现HEAD构建；保留旧活动包/进程。fresh步骤见[Codex使用说明](CODEX_INTEGRATION.md)：全新disposable Git fixture→setup/Local Baseline READY→正常Review & Allow→退出/重开/新Chat→safe edit→danger edit→路径A自然PostToolUse或路径B原Stop兜底→同grant prepare/secure edit/resolved1，不得Script failed或重复危险编辑；不用旧ESCALATED baseline-seed-desktop-trial。

真实Maven A/B/Linux hardened execution PENDING_ENVIRONMENT_PREREQUISITES；不安装/下载/搭环境。三位试用PENDING，独立Ground Truth UNREVIEWED/null、质量NOT_MEASURED。未改Jeepay/用户实际fixture/冻结benchmark/人工标签；Runtime无模型/目标编辑/build/Secret rotation、Scanner离线，仅官方文档与授权GitHub交付联网。Capability/Entitlement、Plus/Pro、Enterprise Gate、Deep Audit、Skill/MCP Scan、Cursor、Installer、新Scanner/rule、baseline/Stop redesign及state relaxation/duplicate retry tolerance/AUTOrenewal均不进入。完成交付后停止。

完整门禁/CI/边界见[AV](AI_TRIAGE_ACCEPTANCE.md#av-auto_fix-posttooluse-code-mode-contract-fix-v01)和[结构化记录](code-mode-acceptance.json)。以下各旧节保留历史事实，当前状态以本节与AV为准。

### 范围与待验收

本轮输出契约IMPLEMENTED且本地gates PASS。新Desktop结果PENDING_ACTUAL_DESKTOP；此前seed Desktop USER_REPORTED PASS、Stop NOT TESTED分开保存。三位试用及独立ground truth不补写通过；后续产品阶段保持Planned，停止扩展AutoContinuation。

## First-run Baseline Seed + Trust UX v0.1（2026-10-04）

干净起点 feature/runtime-mvp / `50ecaf2f4451e4cc6854651c9987ae7167a8b11c`。本轮只修 setup→首有效 Hook 的归因缺口，暂停继续扩展 Stop Guard。最新用户 disposable Desktop 真实反馈：第一条安全编辑无 Hook 记录；第二条危险 TLS 编辑首次有效 Hook 返回 BASELINE_ESTABLISHED、baseline_available=false、scanner_run=true、FULL、NEW0/NONE。这是 **USER_REPORTED FIRST_RUN_TRUST_GAP**，本次没有 AUTO_FIX，不是 Stop Guard 失败。缺失首 Hook 的 Host 底层原因未证明，不能推断用户拒绝信任。旧 readiness/lifecycle PASS 保留历史。

实现 `4915354cd6e8bef139836cb760ae6fb601d8f76a` 已提交推送；final focused **90 passed in 219.07s (0:03:39)**；targeted **524 passed in 1037.62s (0:17:17)**（最后5项测试由 focused/full覆盖）；final full offline **982 passed, 6 skipped, 6 subtests passed in 1123.35s (0:18:43)**。wheel/sdist/package/compliance、五模块包/source字节一致、严格离线clean venv、实际SDK、独立目录Windows native均PASS。新四类CI **PENDING_RERUN_AFTER_ACCOUNT_RECOVERY**，具体jobs/annotations见AU；不能把未启动四平台写PASS。最终docs HEAD按本文件git log核对，docs-only新CI在最终回复单列。

实际SDK/clean/native deliberately skip first safe Hook：SETUP_SEED、baseline_available=true、NEW1、AUTO_FIX；untracked新文件PASS；preexisting PERSISTING1/NEW0/NONE。driver消费原Stop handoff→prepare→模拟安全edit→resolved1/SCANNER_VERIFIED_RESOLVED→functional prepare NOT_AVAILABLE，无functional run。此为真实Runtime/Scanner、**SIMULATED_HOST_ONLY，不是Desktop模型证据**。fresh Desktop seed/trust/自然继续/Stop完整闭环 **PENDING_ACTUAL_DESKTOP**。步骤见[Codex使用说明](CODEX_INTEGRATION.md)，门禁和CI见[AU](AI_TRIAGE_ACCEPTANCE.md#au-first-run-baseline-seed--trust-ux-v01)。

真实Maven A/B/Linux hardened execution PENDING_ENVIRONMENT_PREREQUISITES；不安装/下载/搭环境。三位试用PENDING，独立Ground Truth UNREVIEWED/null，质量NOT_MEASURED。未改Jeepay/用户实际fixture/冻结benchmark/人工标签；Runtime无模型、目标编辑/build/Secret rotation，Scanner离线，仅官方文档与授权GitHub交付联网。Capability/Entitlement、Plus/Pro、Enterprise Gate、Deep Audit、Skill/MCP Scan、Cursor、其它Host、新AUTO_FIX rule、Functional sandbox扩展等继续Planned。完成本轮交付后停止。

当前架构/决策见ARCHITECTURE与DECISIONS首节；完整门禁/CI/实机边界见[AU](AI_TRIAGE_ACCEPTANCE.md#au-first-run-baseline-seed--trust-ux-v01)，[结构化记录](baseline-seed-acceptance.json)与[试用步骤](CODEX_INTEGRATION.md)。

### 范围与待验收

本轮IMPLEMENTED且本地gates PASS；fresh Desktop first-run trust gap修复验证PENDING_ACTUAL_DESKTOP。Auto Remediation Continuation Guard已实现，本轮仅回归，不扩展。缺失首Hook场景、正常首Hook场景、preexisting fixture分别实机记录，明确natural/Stop continuation结果；SDK/native不代替Host模型。其它产品阶段仍Planned。

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

### 范围与验收

本轮范围限定 AUTO_FIX→prepare_task_fix fallback 及指定 CLI UX。Cold-start/readiness/安装生命周期已由最新 USER_REPORTED PASS 覆盖旧 Pending。新的 Stop 实机验收 Pending；不扩 edit/verify/functional continuation，更不进入下一产品阶段。

以下章节为历史记录，最新状态以本节和 AT 为准。

## Codex Integration Productization v0.2 / Cold-start Readiness v0.3（2026-10-04）

Implementation e68cff74c97a0a7a45df2381015b5906b072a82f 已推送；本轮四类新 CI **PENDING_RERUN_AFTER_ACCOUNT_RECOVERY**，9 jobs 无 Runner/steps，实际 annotations 均为账户付款/支出限额阻止启动，不是代码 PASS 或已运行的代码失败。未改账户、workflow门槛或安全契约，四平台未执行。新 runs 见 AS.5。Windows native 已从该已提交 implementation HEAD 重建并完成实际本地 MCP/lifecycle验收，68.66s，version.json source_commit与实现HEAD一致。最终docs HEAD按PROJECT_STATE的git log核对，docs-only新CI在最终交付消息独立核实。

干净起点 feature/runtime-mvp / 022f402a7ade0ed0cf6bbfce50dccd04ed5920a1。最新用户真实 Desktop 回传：MCP Hook/equivalence、CONFIRM 主动询问/批准/拒绝、AUTO 无错误许可问题→prepare→宿主最小修复→Hook resolved1→Runtime 内部 TaskFixService.verify SCANNER_VERIFIED_RESOLVED→functional prepare 无 verifier NOT_AVAILABLE/SECURITY_VERIFIED_FUNCTION_UNKNOWN，均 **USER_REPORTED PASS**。未报告显式 verify_task_fix 或 functional run，不补写已执行。AR 的旧失败/Pending 保留历史语义，由本节最新回传覆盖当前判断。

本轮只交付 Codex 自有项目 setup/status/repair/remove、readiness/诊断及既有复核协议去重。Runtime 0.3.1 / developer-guidance-v0.3 保持，features 新增 codex_integration v0.2 / cold_start_readiness v0.3。新 **fresh Desktop cold-start PENDING_ACTUAL_DESKTOP**；未在当前聊天伪造真实启动派发。source SDK/clean/native 模拟宿主编辑不代替 Desktop。

新增 focused **59 passed**；定向 **438 passed /420.09s**，最后三项 readiness 状态/恢复由 focused 与 final full 覆盖。最终完整离线 **894 passed, 6 skipped, 6 subtests passed in 514.48s (0:08:34)**，六项 skipped 单列。wheel/sdist/七模块逐字节完整性/package/compliance/严格离线 clean（无 editable/system site，117 cached wheels）/Windows native **PASS**。实际本地 MCP + Semgrep/Gitleaks 合成冷启动不调用 get_runtime_info、不重复显式 verify，无 verifier 时不调用 functional run。门禁见 [AS 验收](AI_TRIAGE_ACCEPTANCE.md#as-codex-integration-productization-v02--cold-start-readiness-v03)、[证据](codex-product-acceptance.json)、[用户命令与 fresh trial](CODEX_INTEGRATION.md)。新 CI 推送后按实际 jobs/steps/annotations 核对，未预写通过。

### 范围与当前验收

本轮Codexlifecycle/配置安全/readinesscontract/诊断/复核去重IMPLEMENTED，本地自动化与包/native gates PASS。最新用户原AUTO/CONFIRM/functionalprepare无verifierDesktopPASS为USER_REPORTED；新setup+完全重启+无warmup首edit与SessionStart/required初始化实际Desktop PENDING_ACTUAL_DESKTOP。首次不触发而get_runtime_info后恢复为Cold-start FAIL；缺可用Host机制为HOST_LIFECYCLE_PREREQUISITE_PENDING，不能假PASS或转Windowscommandrunner。

setup→status→setupagain(unchanged)→repair(no unrelatedchange)→remove(onlyowned)→reinstall的disposable自动化已验收，普通用户实机lifecycle反馈待回传。真实MavenA/B隔离执行PENDING_ENVIRONMENT_PREREQUISITES，不搭环境；三位开发者PENDING，人工GroundTruth UNREVIEWED/null，质量NOT_MEASURED。EnforcementDecisionModel/EnterpriseGate、GitHub/GitLabgate、PolicyServer、PreToolUsehardgate、waiver、其它Host/第二AUTO、Joern/DAST/DeepAudit/watcher继续Planned。本轮提交推送/核实CI后停止。

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
## Core P0-7.3 当前边界

仅交付 Codex Global Hook Host Claims propagation/binding/diagnostics。保持旧 Core classification/快照/真实 Scanner proof；不修改 Scanner/remediation/Ticket/Functional/CET/workspace router 架构。后续阶段均保持 Planned，不开始 P0-8。

本地门禁见 [P0-7.3 验收](codex-host-claims-acceptance.md) 及其证据；实际 Desktop/trust UI 和原拒绝字段定位仍 Pending。用户自行加载候选 Runtime 后 Global `security-check repair` → review 更新后的 exact Hook → reconnect → Project C read-only / Bash edit / apply_patch TLS 隔离链路。不能把模拟 stdio Host 当 Desktop PASS，不能用新 claims 推断已认证 Host 身份。三位独立试用、Ground Truth、Maven 环境先决验收继续保持真实 Pending。
