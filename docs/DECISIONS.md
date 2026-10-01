# AI Security Runtime — Architecture Decisions

更新：2026-10-02。既有实现与验收依据 `feature/runtime-mvp` 的 `3d773aaaa1b95b8c7596bf32c77c4bd5eabfd399`；本轮规划基线为 `7e197443eb4f712d10bc9a61be82c4929b1569da`，加入用户确认的任务引导与来源原则。Accepted 表示已确立的决策；各项分别标明 Implemented / Planned，不因路线获批而宣称已实现。

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

**Status：Accepted 的产品决策 / Planned；用户已于 2026-10-02 确认，尚未开发。**

面向普通开发者的默认结果应回答“先做什么、为什么、下一步如何推进”。相关候选可投影成一个任务，保留原 Finding/Advisory、证据和状态的完整访问；普通/详细视图共享同一结果，不靠隐藏未完成检查制造安全印象。首轮最多展示三个推荐跟进任务，并提供完整列表入口。

建议跟进动作与 Runtime priority 是不同字段：所有结果为 REVIEW 时，可以推荐先“核查 TLS 影响”，但不能改成 ACTIONABLE、删除 Raw 或降低 release_status。VALID 应表达为“已完成 AI 审阅”，而非人工验证、复现或确定线上可利用。优先级策略如需变化，另以人工基准和独立回归证据决策；不会为匹配历史分布调整结论。

当前 workspace 的扫描定位与只读汇总为首轮 Planned；不得取全局最新记录或直接把有写入副作用的 TriageService.view 包装成纯只读。无扫描时给出下一步，不自行启动扫描。后续“继续核查”和“修复与验证”分别迭代，沿用已授予范围内的授权，源码修改、构建、联网/模型上传等超出范围的执行另行处理。

理由：当前工程验收输出要求用户理解内部枚举并编写多轮提示词，增加决策负担。可执行任务应减少用户负担，同时保持证据、未知条件和风险政策的真实含义。易用性试用与安全质量分别验收。

依据：[当前展示](../src/security_runtime/human.py)、[当前 MCP](../src/security_runtime/mcp_server.py)、[PROJECT_STATE](PROJECT_STATE.md) 的用户报告与 [NEXT_STAGE](NEXT_STAGE.md) 的已批准范围。

## ADR-014 — 证据来源与核查范围显式区分

**Status：Accepted 的来源原则；现有引用/hash 校验已实现，完整任务来源展示/宿主补充报告契约为 Planned。**

扫描器候选、Runtime 接受的 AI 审阅、宿主额外源码核查和独立人工判断具有不同证据含义。结构/引用合法不证明语义正确；静态业务调用不证明生产启用；有限依赖与词法证据不证明完整图或 reachability。展示时保留来源和未知条件，不把一种分析升级为另一种确认。

用户提供的 Jeepay 实际宿主 MCP 运行与已提交脚本回放使用不同 scan identity，分别记录，不覆盖原验收或要求匹配 verdict/priority。宿主后来读取完整调用链的报告没有作为新的 Triage packet/hash/refs 提交，不能伪装成 Runtime 已接受结论，也不能补齐 scan coverage。当前没有通用宿主补充报告导入接口，未固化 revision/artifact 的聊天报告仅作为带来源的产品输入。

理由：跨设备和跨聊天需要知道事实来自哪次运行、哪些核查尚未实施。模型审阅、宿主分析和人工真值混在一起会掩盖证据缺口，并污染质量指标。

依据：[EvidenceBuilder](../src/security_runtime/triage_evidence.py)、[TriageService](../src/security_runtime/triage.py)、[PROJECT_STATE](PROJECT_STATE.md)、[NEXT_STAGE](NEXT_STAGE.md)。

## Approved / Planned 与其它尚未实现事项

已批准路线包括开发者任务入口、继续核查、修复与验证三个产品迭代，以及独立人工质量工作；版本化 ground truth schema、人工盲审与 adjudication、不同真实模型比较、precision/agreement/suppression-risk、prompt/model regression 和质量门槛后的 Joern Java PoC，均在 NEXT_STAGE 规划。本轮只授权持久化路线及提交推送，未实施这些功能或实验。

数据库 retention/完整审计、更多自动反证、IaC AI validation、云端多租户及主动审计也没有实现；它们不属于本轮已批准产品迭代的默认开发任务。

变更这些决策时，应新增或明确 supersede ADR，写出原因、证据和行为变化；历史验收按原时点保留，不用聊天记录取代持久化决策。
