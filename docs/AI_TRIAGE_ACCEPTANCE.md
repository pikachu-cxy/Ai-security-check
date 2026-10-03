# AI Finding Triage & Risk Validation v0.1 验收

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
