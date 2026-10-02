# Next Stage — AI Triage Quality Validation & Developer Guidance

## Developer Fix & Verify v0.1 — 当前状态（2026-10-02）

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

本轮实现与分发依据：`1e10b53`；起始 `0f33d26`。Windows 独立包实际 source_commit 与实现一致，SDK 取得13工具及 v0.3 契约，真实 Semgrep 组内仍存在/部分/全部规则复查结果通过；本轮测试、package、compliance 和四平台 standalone CI 均 success，详见 AJ 与 [native/CI 证据](fix-verify-native-evidence.json)。文档最终 HEAD 用 `git log -1 --format=%H -- docs/PROJECT_STATE.md` 获取；代码之后若变化须重新验收。不要自行开始 Hook；真实 UX、三位试用与独立人工质量状态不变。
