# AI Finding Triage & Risk Validation v0.1 验收

2026-10-01，`feature/runtime-mvp`。本轮实现已有 Scanner Finding 的证据验证与独立展示层。未增加 scanner、主动 AI 仓库审计或跨文件编译器级可达性分析。公开 Jeepay 的 OSV 在线测试使用用户本次明确授权；BYOK 验收仅访问本地 loopback 假服务器。

## A. 起始 HEAD

`47c41f4bfd41474cd9276d95999dd32bfca70d0e`。开始时分支正确、工作区干净。完整离线 baseline：308 passed、6 skipped、6 subtests passed，85.25 秒。

## B. 最终 HEAD

代码及报告在本分支提交、推送。最终提交 SHA 随交付消息记录，CI 记录补充于 AD。未操作 main。并行工作产生的 ARCHITECTURE／PROJECT_STATE／DECISIONS 等文档保留在工作区，未纳入本轮提交。

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

普通 scan 为 deterministic only。`triage --provider configured` 没有 `--allow-external-code-context` 即 fail closed，noninteractive／CI 同样生效。配置命令明确说明将发送经过限制和脱敏的代码上下文；配置本身不授权发送。所有 CI BYOK 测试仅 mock 或 loopback，不调用收费／公网模型。

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

Baseline 308 passed。初轮完整回归暴露三项旧输出／工具枚举断言，已按候选语义和新增工具修正；原不适用能力仍隐藏。当前 Triage 定向 70 passed。最终全量结果随最终回归补充于此。

安全测试包括 Secret 四个出口、注入、不授权零请求、workspace/symlink escape、伪造／越界引用、非法 JSON／schema／枚举、响应大小、timeout/HTTP 错误、API/proxy 凭证、原 Finding 不改、会话伪造／重放、Secret/context/prompt 变化、cache、batch、三种接口和进度。

## AB. Compliance

licenses --check-distribution 和 notices --check 通过。未新增第三方 runtime dependency、scanner binary 或模型 SDK；仅 Python 标准库实现 BYOK HTTP。Triage fixture 自主构造，不携带 Jeepay 代码或真实凭证。

## AC. Package Integrity

wheel/sdist build 和 check_wheel 通过，门禁显式要求四个 triage 模块；synthetic fixture 随 sdist 提供。clean wheel install／CLI help/version/licenses 验收结果及最终 standalone 记录补充于 AD。

## AD. Standalone / CI

本地 Windows 完整归档验收已通过：默认 managed scanners、原生 OSV synthetic offline CLI/MCP fallback、插件、MCP 及 Triage。新增 verify_artifact 检查 prepare/submit/get，并在四平台 CI 运行。安全会话补强后会重建并重验最终包。

## AE. 尚未解决

没有 compiler-grade 跨文件 reachability；依赖 runtime preconditions、完整 POM 图及 Secret live validity 仍需人工确认。首批真实 26 条 coding-agent 审阅不是独立人工准确率测量；其余 89 条保持未验证。未支持外部模型真实收费验收／自动扫描时调用 AI。旧 privacy.py 的未使用 generate_fix protocol 与新 Triage AIProvider 分工保持兼容。状态 key 按平台用户权限保护，不能抵御已控制同一用户账户的攻击者。原 scans/findings 不是数据库级 immutable audit log，但 Triage 不改写它们。数据库 retention／跨用户多租户服务不在本轮实现。

## AF. 下一阶段建议（未实现）

由独立人工完善 ground truth，再比较模型／prompt regression；扩展可解释反证类型；单独做 IaC context validation；研究 Joern 或 compiler-grade reachability；设计限额、retention 和更细的 provider-session provenance。继续保持 scan coverage 与 triage coverage 独立。
