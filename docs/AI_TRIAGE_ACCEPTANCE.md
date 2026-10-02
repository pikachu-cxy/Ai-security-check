# AI Finding Triage & Risk Validation v0.1 验收

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
