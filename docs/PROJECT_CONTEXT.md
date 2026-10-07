# AI Security Runtime — Agent Handoff / Unified Project Context

更新：2026-10-07，R0 major milestone 后一次更新。下列结论描述实际未提交工作区；
历史验收按当时环境阅读，不等于发布包或本次真实 Desktop 全面验收。

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

## Product and Core contract

Local-first, multi-host AI Coding Security Runtime，服务个人开发者、OPC 和小团队。
Agent writes code; Runtime verifies and controls security。第一评价标准是开发者愿意
一直开着。默认路径：AI edit → normalized Host event → strict host/workspace/session
binding → filesystem snapshot reconciliation → incremental Scanner → Finding/Policy
→ necessary bounded AUTO_FIX → targeted real security re-scan → CLOSED/RETURN_TO_HOST。

Capability != Execution Timing。功能验证、javac/Maven/Gradle/pytest/go/npm、build/test、
Full Scan、Security Regression、Sandbox、Deep AI audit 不进入默认 Core Hook。
已实现的 Deep Verification MCP/API 保留兼容，只供显式深度流程；不把能力枚举当作
已发布的 Plus/Pro 套餐。重能力不可用不否定安全复扫；Core 缺证据须 UNKNOWN /
PARTIAL / INCONCLUSIVE，不伪造 SAFE，不放宽 fix authorization 或 receipt validation。

## Actual Git and persistence

Branch `feature/runtime-mvp`；HEAD 是 ee1bfd9c12493683cc313cb3628753a51ae124ac。
大量 P0 与 R0 实现仍未提交。不可仅 checkout HEAD 来恢复成果；先查 git status。
禁止 reset、整文件 restore/checkout、clean 或丢弃 stash。R0 前 560 文件快照在
`.security-runtime/r0-before`，审计见 [workspace audit](rule-program-workspace-audit.json)。
无 staged changes、commit 或 push。活动 Runtime 没有替换，真实用户 Host config 未改。

SQLite 保存 scans/findings/triage；Hook/remediation 有 workspace 隔离、OS lock、HMAC
refs/receipt、snapshot 与 Episode budget。Recent Hook diagnostics bounded、可跨进程
读取且不参与授权。Rule Program 复用这些结构，没有数据库 schema 或第二套 Finding。

## Host truth

Codex Global integration、claims/workspace binding、mutation reconciliation、normalization、
INLINE_PREPARED、Exact Edit Envelope、TLS Agent Fix、真实安全复扫、Family recurrence
已有指定 Windows Desktop 路径真实验证。Runtime 不主动调用宿主模型。prepared inline
main path prepare_task_fix=0；opaque refs 只原样传递，不能重建或跨聊天转交。
新 R0 本地 MCP simulated Host 再次通过两 Episode；不是新的 Desktop 验收。

Cursor Detection Runtime、first-scan attribution、Finding/Policy、Advisory Remediation
已有用户真实 Desktop 验证。本轮不继续深挖 UI；observed afterFileEdit/stop 正常，
postToolUse 不可靠。不安装默认 feedback hook、不创建无消费者 pending，不用
stop.followup_message。跨进程 snapshot 并发/lazy bootstrap、setup-seeded baseline、
首扫归因和 advisory transport 既有成果保留。current status 不再是整体 Cursor PARTIAL。

Claude Code/Gemini CLI/Copilot CLI仍 Planned；旧 command adapter 或 schema 枚举
不等于完整多 Host 实现。Codex CLI 真正安全 E2E、其他 trust/session/Host 路径仍 Pending。

## Rules, Findings and AI

读取 [Rule Program](RULE_PROGRAM.md)、[coverage matrix](RULE_COVERAGE_MATRIX.md)、
[manifest](../src/security_runtime/rules/capabilities.json)；不要以 YAML 数量作为质量。
程序 version 1.0.0；execution pack descriptor 1.1.0，内容 checksum 改变；Runtime 0.3.1。
language/extensions/maturity/default planning 先于 Semgrep，framework 由 typed patterns
判定，不扩大 scope 猜仓库框架。Java-only 18 variants，Java+mapper XML 19，XML-only 1，
Python-only 既有2；JavaScript zero rules 不启动 Semgrep。Secret独立。

Semgrep code patterns；Gitleaks Secrets；Trivy vuln/misconfig独立 adapters；OSV仅指定
白名单 primary failure fallback。Dependency FULL 必须满足完整 graph contract；POM
inventory/成功进程不证明 FULL/reachability。保留 primary failure、Raw 和覆盖边界。

Raw Finding 与 AI Triage 独立；AI 不删除 Raw，不提升 scanner coverage 或 release 状态。
UNTRUSTED_CODE、脱敏、budget、context_hash/session/evidence_refs 校验保持。Runtime Policy
决定优先级与授权，模型无 hide/block 权限。Scanner resolution != functional verification
!= production correctness。本轮语料由作者标注，不等于独立人工 Ground Truth。

MCP 注册仍以 mcp_server.py 为准，现有19工具：handle_hook_event/readiness/stop，
scan_diff/scan_project/get_findings，prepare_triage/submit_triage/get_triage/prepare_task_triage，
get_runtime_info/get_security_summary，prepare_task_fix/confirm_remediation/verify_task_fix，
prepare_functional_verification/run_functional_verification，generate_fix/verify。
Rule Program没有新增 MCP authority。用户任务排序号不是稳定跨请求身份。

smart_auto/ask_before_fix/report_only 保留。现有 TLS always-true HostnameVerifier
窄 fix 需要策略、完整 scanner evidence、preservation guards、bounded scope、Episode
budget 与 real re-scan。Core grade本身不授予AUTO_FIX。新八类风险只 guidance/Agent-human
fix；Secret/依赖等保护类别不能借其自动操作。Fast Fix仍需 trusted atomic Host bridge，
不把本地 simulated fast path冒充Desktop可用。

## Quality evidence and known limitations

R0 [actual corpus](rule-program-corpus.json)：71 synthetic cases，46TP/28TN/0FP/0FN。
[annotated rule gate](rule-program-rule-gate.json)覆盖全部29安装规则，独立旧 fixture gate。
框架/安全常量/参数绑定/固定可执行文件及bounded args/allowlist固定URL/containment/
parser hardening/可信stream/Secret placeholder/env/wrapper/multiple occurrences/line movement
有明确案例。Guard后重新赋值和late XML hardening已作为风险回归。
没有compiler-grade跨文件分析、任意sanitizer证明、gadget/reachability/production exploit
证明或独立人工准确率。Maturity保持2Core/8Validated，不强行毕业。

新 capability anchor统一framework variant Family，location occurrence 保持；read/write
primary + traversal related evidence。TLS bytes/Family eq-v1、Secret detector Family不变。
历史非TLS raw-rule Family未自动迁移，不偷偷retarget旧opaque refs。所有适用variants和
当前target真实执行才可absence proof；old checksum/proof不能冒充new receipt。

本轮performance仅实际单文件local diagnostic baseline；不要推出全项目p95/p99、Desktop
Host latency或大幅优化结论。Scanner invocation仍固定成本，无新的daemon/worker。
参见 [incoming](rule-program-performance-before.json) 和 [current](rule-program-performance-after.json)。

## Existing Pending / Planned

Jeepay历史：115 Raw、26 triaged、89 untriaged；依赖与代码覆盖仍有边界。不同历史审阅
优先级分布保留，Agent triage不等于人工GT或“项目安全”。三位未参与开发的试用 Pending，
独立人工Ground Truth UNREVIEWED，质量agreement/precision与p95/p99 NOT_MEASURED。
Deep receipt protocol修复、Host-native Verification Plan与BOM已有本地证据，但默认Core
不强化Functional；真实Maven A/B仍PENDING_ENVIRONMENT_PREREQUISITES，不安装/下载或
降低安全执行前提。重能力仅手工/后续Plus-Pro/Stop-PR-CI择时基础设施，未实现调度仍Planned。
Joern、compiler-grade dataflow、Persistent Scanner、广泛自动修复、商业entitlement、新Host
均未开始。远端四平台CI仍原Pending，不用本地Windows替代，未push即无新CI结论。

## Handoff and next recommendation

1. 先核对Git与本文件，保留dirty工作区；读取R0 acceptance、Rule Program和matrix。
2. 再读 rule_program/rule_coverage/rulepacks/scanners/equivalence，理解capability与engine边界。
3. 读 hook_runtime/verification，保持all-variants occurrence proof与TLS guards/opaque refs。
4. Cursor当前四事件与capabilities已经关闭probe，不再开发P0-10.1b/c/UI workaround。
5. 下一建议是扩充有标签的本地OSS/internal语料与独立复核，然后基于FP/FN毕业Core；
   不是增加YAML数量或默认授权新fix。新增Host/Plus/Deep保持后续。此次完成后停止，
   不因roadmap文字自行开始新阶段；commit/push/部署需要新的用户指令。
