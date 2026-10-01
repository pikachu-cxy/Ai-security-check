# Next Stage — AI Triage Quality Validation & Ground Truth

更新：2026-10-02。基线：`feature/runtime-mvp` / `3d773aaaa1b95b8c7596bf32c77c4bd5eabfd399`；最终实现 `557052049c74c6d1ca4321c2d9559483a36f55d2`。**AI Finding Triage & Risk Validation v0.1 已完成；本文仅规划下一阶段，不实施新功能、标注、模型请求或 Joern。**

先读 [PROJECT_STATE](PROJECT_STATE.md)、[ARCHITECTURE](ARCHITECTURE.md)、[DECISIONS](DECISIONS.md) 和 [AI_TRIAGE_ACCEPTANCE](AI_TRIAGE_ACCEPTANCE.md)。

## 为什么先验证质量

当前 Jeepay 有 115 Raw、26 triaged，2 ACTIONABLE / 23 REVIEW / 1 LOWER_PRIORITY / 0 SUPPRESSED / 89 UNTRIAGED。独立人工标签文件仍全部 UNREVIEWED/null。现有 `scripts/jeepay_triage_benchmark.py` 通过 `host_analysis` 回放 Coding Agent 审阅 artifact，验证实际 MCP handoff、policy、cache 与 Raw 保留；不是实时调用不同模型的评测器，也不是独立人工 ground truth。

当前 BYOK 只有 mock/loopback 协议验收；invalid output rate=0 和 382 passed 不能转成“准确率”。先明确人工真值、模型误判与错误压制风险，才能判断深度数据流工具究竟解决哪些证据缺口。**下一阶段不是立即做 Joern。**

## 当前已实现与本阶段 Planned

| 已实现的 v0.1 基础 | 质量阶段尚未实现 |
| --- | --- |
| Raw / TriageRecord 分离、五类 verdict 与独立 exploitability | 版本化真实项目 ground truth schema 与独立人工 adjudication |
| EvidenceBuilder、脱敏、预算、HMAC revision、引用/hash 校验 | 完整 benchmark 源码/证据身份冻结与标注审计 |
| Agent-native MCP prepare/submit/get、session/replay 防护 | 真实多模型、重复运行及 provenance 比较 |
| 显式授权 BYOK、结构化输出、依赖 batch/cache | suppression risk、precision/agreement 的有效统计 |
| 独立 scan/triage coverage、Raw 分组和保守 policy | prompt/model regression 与人工确认的质量门槛 |
| 合成 fixtures 和真实 26 项审阅回放 | Joern Java PoC、compiler-grade dataflow |

本阶段不增加 scanner、不自动构建目标项目、不做全仓主动 AI 审计、不自动修改 priority policy 或增加 FALSE_POSITIVE 反证类型。质量实验若暴露实现缺陷，应记录独立问题、按新的修复任务处理，再复验；不能把评测脚本的结果悄悄改成 Runtime 产品行为。

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

## 八个规划阶段

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

## 质量阶段完成标准与交接

阶段完成必须同时具备：可复现 benchmark 身份；独立人工标签与分歧记录；五类 verdict/实际风险/利用条件的区别；可追溯多模型 run（或明确未运行限制）；分母完整的 precision/agreement/suppression-risk；安全边界回归；预先确立并满足的质量门槛。没有足够人工真值或真实模型结果只能交付部分测量，不宣布完成整体质量 milestone。

最小下一任务：**核实固定 Jeepay 源码身份，完成盲审试标并确定 ground truth schema/指南**。先使用既有目录与证据，新增报告尽量合并为一个质量 acceptance，不再为每次运行增加顶层总结文档。旧验收按原时点保留，原 ground truth 的 null 不在本轮填写。

新聊天从 [PROJECT_STATE](PROJECT_STATE.md) 的 Agent Handoff 开始。授权下一阶段之前，只维护这份规划；不能默认开始公网模型请求、替人工打标签、训练/调参或实现 Joern。
