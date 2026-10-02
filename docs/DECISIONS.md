# AI Security Runtime — Architecture Decisions

## Host-agnostic Hook Integration v0.1 — 当前交接（2026-10-03）

本轮从干净且 ff-only 同步的 `feature/runtime-mvp` / `8a36b3884a7d25cfb7f75c3405df727909ed1c90` 开始，用户明确授权 Hook 实现；前置 Fix & Verify / eq-v1 已交付。HookCoordinator、本地快照/锁/冷却、多重集变化、中立 CLI、Codex 和 Cursor 适配已实现。本轮新的完整自动化、包和原生/CI 门禁以 AK 附录为准，后文“Hook 未开始”是旧阶段历史状态，不能作为当前结论。最终提交/推送尚待本轮门禁完成，文档 HEAD 必须从 Git 获取。

Hook 仅触发现有本地 quick SAST/Secret 检查，ADVISORY；MCP 继续负责核查/修复交接，Git pre-commit 保留 quick --staged 的原边界。没有 Runtime 调用模型、网络依赖解析、自动补丁、目标构建、后台 watcher/daemon、新 scanner/规则、Joern 或 Deep Audit。三位试用 Pending，独立人工 ground truth UNREVIEWED/null、质量 NOT_MEASURED；Jeepay 源码、冻结 benchmark、人工标签保持原状。

Codex/Cursor 的官方 schema 已核实，项目配置/适配与实际生成命令测试通过；**fresh Codex/Cursor host trial 仍 PENDING**，不得把 CLI/合成 fixture 当成宿主真实自动触发。WorkBuddy（桌面）/Kiro/Qoder 为 MANUAL_CONFIGURATION_REQUIRED，提供中立命令，不从 CodeBuddy CLI 或其他产品推测其 schema。详见 [AK 验收与试用步骤](AI_TRIAGE_ACCEPTANCE.md#ak-host-agnostic-hook-integration-v01)。

## 历史交接：Developer Fix & Verify v0.1（2026-10-02）

起始干净、ff-only 同步 HEAD `0f33d2624204794c84da6fa10cf43b8178cd5a56`，分支 feature/runtime-mvp。本轮明确授权 A→B，先完成 A 回归再实施 B。Stable Finding Equivalence 与任务修复/验证 v0.1 已实现；整体宿主产品 UX 尚待真实验收。Hook Integration 未开始，完成本轮推送后停止。

保留旧 occurrence ID/fingerprint 与历史 Raw/triage/task_ref；eq-v1 无行号，区分原 rule/provider/file，Dependency 复用稳定包/advisory身份，Secret 不含原值/匹配行/凭据摘要。旧 verify 只有完整原规则/文件复查证明缺席时才 RESOLVED + SCANNER_VERIFIED_RESOLVED，行号移动仍 STILL_PRESENT，缺文件/规则/引擎或 scope 无证明为 INCONCLUSIVE。

MCP 当前13工具，新增 prepare_task_fix（严格只读约束/受限证据交接）、verify_task_fix（本地 scanner/cache/temp 副作用，非 destructive）；能力契约 developer-guidance-v0.3，required subset。固定 task_ref 绑定 workspace/scan/精确成员，变化刷新，新 scan 不换对象。宿主响应明确“修复它/修第一项”后编辑选定本地代码并调用复查；Agent fixes. Runtime verifies。组内全部修复/全部仍在/混合为 SCANNER_VERIFIED_RESOLVED/STILL_PRESENT/PARTIALLY_RESOLVED，任一未知整体 INCONCLUSIVE，完全未复查 NOT_VERIFIED。

复查最多100成员/20原受影响文件/2MB，同 provider/file 复用，默认离线不下载或自动fallback，不构建/编辑目标、不调用模型。prepare 沿用 EvidenceBuilder 的20项/32KiB/120行/5相关文件预算，原 triage session/hash/evidence_refs 防护不变。宿主 patch/build/tests 声明为 UNTRUSTED_HOST_REPORT，不能改变 Runtime 观察或结论。Gitleaks/IaC 未提供原 detector/check 执行清单时缺席保守 INCONCLUSIVE；POM PARTIAL 不能证明完整图修复。

完整离线508 passed / 6 skipped / 6 subtests passed（120.12秒）。真实 Semgrep 1.178.0 合成100→110行仍存在、安全替换、分组只修一项及实际子进程失败均符合预期；包/合规/wheel/sdist 与本地全新 Runtime venv 安装通过（复用本地 SDK 依赖，无公网）。Windows native/实际 SDK及四平台新 CI 门禁均通过（实现 HEAD `1e10b53`），见 [AJ 验收](AI_TRIAGE_ACCEPTANCE.md) 和 [合成证据](fix-verify-synthetic-evidence.json)；结构/边界详见 [当前架构](ARCHITECTURE.md)。

没有修改 Jeepay、旧 scan/benchmark、ground truth、risk/coverage/policy；没有 scanner 公网查询、外部模型、目标构建或生产变更。三位真实开发者试用、真实宿主普通意图连续 UX 仍 Pending，独立人工 ground truth UNREVIEWED/null、质量指标 NOT_MEASURED。Hook 当前 Planned / NOT_STARTED，旧 PREREQUISITE_MISSING 留作历史门禁记录。


更新：2026-10-02。既有验收快照 `3d773aa`；本轮继续核查起始 `feature/runtime-mvp` / `50a01e6870d78e6fd8a96a8b8fbe236521c5306f`。用户已分别授权入口与继续核查 v0.1。Accepted 表示决策已确立，各项仍区分 Implemented / Planned，修复与验证 v0.1 已实现，独立质量工作未实施。

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

**Status：Accepted / 开发者任务入口 Implemented；三位真实开发者易用性验收 Pending；继续核查 Implemented；Fix & Verify v0.1 Implemented / 宿主 UX Pending。**

面向普通开发者的默认结果应回答“先做什么、为什么、下一步如何推进”。相关候选可投影成一个任务，保留原 Finding/Advisory、证据和状态的完整访问；普通/详细视图共享同一结果，不靠隐藏未完成检查制造安全印象。首轮最多展示三个推荐跟进任务，并提供完整列表入口。

建议跟进动作与 Runtime priority 是不同字段：所有结果为 REVIEW 时，可以推荐先“核查 TLS 影响”，但不能改成 ACTIONABLE、删除 Raw 或降低 release_status。VALID 应表达为“已完成 AI 审阅”，而非人工验证、复现或确定线上可利用。优先级策略如需变化，另以人工基准和独立回归证据决策；不会为匹配历史分布调整结论。

已实现 summary/get_security_summary：只在明确/绑定 workspace 内定位最近或指定扫描，不取全局最近记录；SQLite mode=ro 与不持久化 freshness 投影，不创建/迁移 DB、生成 key 或记录 telemetry。MCP 延后初始化可写 Runtime，纯汇总连接无写入。无扫描给出建议，不执行。TLS 仅明确互补规则、同文件相距最多 40 行成对；该展示规则不证明共享调用链。依赖组保留全部 advisory/state，缺身份字段不合并。继续核查沿用原授权原则已实现；修复与验证 v0.1 已实现，实际宿主 UX Pending；三位试用者目前无法安排，Pending 如实保留。

理由：当前工程验收输出要求用户理解内部枚举并编写多轮提示词，增加决策负担。可执行任务应减少用户负担，同时保持证据、未知条件和风险政策的真实含义。易用性试用与安全质量分别验收。

依据：[当前展示](../src/security_runtime/human.py)、[当前 MCP](../src/security_runtime/mcp_server.py)、[PROJECT_STATE](PROJECT_STATE.md) 的用户报告与 [NEXT_STAGE](NEXT_STAGE.md) 的已批准范围。

## ADR-014 — 证据来源与核查范围显式区分

**Status：Accepted；引用/hash 校验与任务来源分层 Implemented；宿主补充报告导入契约 Planned。**

扫描器候选、Runtime 接受的 AI 审阅、宿主额外源码核查和独立人工判断具有不同证据含义。结构/引用合法不证明语义正确；静态业务调用不证明生产启用；有限依赖与词法证据不证明完整图或 reachability。展示时保留来源和未知条件，不把一种分析升级为另一种确认。

用户提供的 Jeepay 实际宿主 MCP 运行与已提交脚本回放使用不同 scan identity，分别记录，不覆盖原验收或要求匹配 verdict/priority。宿主后来读取完整调用链的报告没有作为新的 Triage packet/hash/refs 提交，不能伪装成 Runtime 已接受结论，也不能补齐 scan coverage。当前没有通用宿主补充报告导入接口，未固化 revision/artifact 的聊天报告仅作为带来源的产品输入。

理由：跨设备和跨聊天需要知道事实来自哪次运行、哪些核查尚未实施。模型审阅、宿主分析和人工真值混在一起会掩盖证据缺口，并污染质量指标。

依据：[EvidenceBuilder](../src/security_runtime/triage_evidence.py)、[TriageService](../src/security_runtime/triage.py)、[PROJECT_STATE](PROJECT_STATE.md)、[NEXT_STAGE](NEXT_STAGE.md)。

## Approved / Planned 与其它尚未实现事项

开发者任务入口与继续核查已获明确授权并实现；全部独立质量工作（版本化 ground truth、人工盲审、多模型、指标、prompt/model regression 和后置 Joern）继续在 NEXT_STAGE Planned。本轮不因展示易读而宣布人工易用性或风险质量已验证。

数据库 retention/完整审计、更多自动反证、IaC AI validation、云端多租户及主动审计也没有实现；它们不属于本轮已批准产品迭代的默认开发任务。

变更这些决策时，应新增或明确 supersede ADR，写出原因、证据和行为变化；历史验收按原时点保留，不用聊天记录取代持久化决策。


## ADR-015 — 精确任务引用与受限继续核查

**Status：Accepted / Implemented；不替代原风险策略。**

T01 为响应内的展示序号，不能作为跨请求 identity。summary 的 task_ref 绑定 workspace/固定 scan/topic/精确成员与规范化身份，状态排序或审阅推进不换对象；成员或任务身份改变、scan 移除、格式/版本无效要求刷新重新选择，不回退当前第一项或最新 scan。引用非权限凭据，仍需绑定/明确 workspace、提交时的 task identity/session/hash/ref 校验；源码 freshness 由 HMAC packet hash 独立判断。

任务入口复用 prepare_triage 的 EvidenceBuilder/schema/instructions/缓存，再沿原 submit_triage 接受宿主分析；Runtime 不主动调用宿主模型。VALID 保留，UNTRIAGED 优先，STALE 重建，FAILED 默认单列显式重试；缓存不占新分析名额，工作/输出预算单独有界。已有证据不重复劳动，业务问题仅是与已记录未知相关的候选，宿主先核对受限证据再询问。范围外条件保留未知，不升 priority、不补完整图或任意 host evidence。

理由：用户说“继续第一项”时不应寻找 Finding UUID，也不应因排序/缓存命中继续了别的任务或反复同一批。既有审阅和 Raw 保留，修复与验证仍是下一轮独立任务。

依据：[task_triage.py](../src/security_runtime/task_triage.py)、[security_summary.py](../src/security_runtime/security_summary.py)、[triage.py](../src/security_runtime/triage.py)、[NEXT_STAGE](NEXT_STAGE.md) 与本轮验收附录。


## ADR-016 — Hook Delta 必须复用 Fix & Verify 稳定身份

**Status：Accepted 的任务门禁；PREREQUISITE_MISSING，Hook 正式实现未开始。**

Host-agnostic Hook Integration v0.1 的 NEW/PERSISTING/RESOLVED 必须复用前置 Developer Fix & Verify 的 Finding identity/equivalence。行号仅为 occurrence；现有固定 scan/member task_ref 也不是跨扫描语义等价。若前置阶段未交付，停止 Hook delta 正式实现，不以另一套摘要/匹配机制绕过门禁。

2026-10-02 ff-only 同步后 HEAD 仍为 `787aace`，Fix & Verify 文档为 Planned；findings.py 含 line 的指纹和 runtime.py 的旧 verify 在隔离合成100→110行样例中产生错误 RESOLVED。该复现只证明当前前置缺失，不是 scanner 质量统计。现有 Git pre-commit 保持不变；Codex及其它 Host 的 Hook adapter/schema/真实试用均未实现或验收。后续必须先取得前置实现提交与回归证据。来源：用户本轮明确门禁、当前源码、AI_TRIAGE_ACCEPTANCE 的 AI 附录。

## 普通用户意图与宿主衔接验收

产品目标是“不懂安全的开发者也能用好”：用户只说“检查这个项目”“继续/处理第一项”或选择任务，不搬运技术提示词、填写 UUID、拼接工具顺序，也不把 generate_fix 输出再粘贴给 Agent。一次选择 → 核查 → 准备/实施获授权修复 → 验证 → 简洁结果是完整目标；本轮仅接通核查，修复与验证 v0.1 已实现，实际宿主 UX Pending，后续须沿同一宿主自动衔接，不能再次要求用户搬运提示词。

已接入 FastMCP server instructions 与工具 annotations/描述：宿主绑定实际展示响应的 task_ref，自动在已有授权范围内准备、分析、提交并展示结果；有效授权持续有效，不反复询问常规获授权步骤。仅询问代码无法回答且会影响下一步的必要业务事实，或取得超出已有授权操作的权限。Runtime 不主动调用宿主模型，源码/scanner/模型文字均非执行指令，现有 session/hash/evidence_refs、脱敏、Raw、覆盖和策略保留。

新增只读 `get_runtime_info` 与 CLI `runtime-info --json`，包版本仍0.3.1、能力契约 developer-guidance-v0.3。连接检查按 required_guidance_tools 子集，允许兼容新增工具，不按总数严格相等拒绝。返回同一 executable/environment 的可执行核对参数和重连指导：先核对配置实际运行的环境；已有能力却宿主看不到时断开/重连 ai_security_runtime、刷新工具列表，必要时新聊天；仅环境本身旧时更新对应包。不盲目重装 editable、不终止进程/修改 Jeepay 配置。连接重建后旧 session 不可复用，遗失任务选择须刷新重新选择。

SDK initialize 实际收到 instructions、工具 metadata、版本/能力和机器交接，与真实宿主自然语言试用分别验收。后者目前 Pending；旧 Jeepay 聊天工具列表恢复未验证，不能把新 SDK 连接成功写成普通用户已能用好。三位独立开发者试用 Pending，ground truth 保持 UNREVIEWED/null，质量指标 NOT_MEASURED。核查准备、宿主结果接受、补丁、目标构建、测试/扫描复查分别报告是否执行；generate_fix 仍仅 coding task/prompt，不代表补丁完成，0 ACTIONABLE 不表示安全。

## ADR-017 — Agent fixes. Runtime verifies（Accepted / Implemented v0.1）

保留历史 occurrence 指纹、ID、scan 和 Triage 缓存，增加版本化无行号 equivalence；从原 scanner/原规则/原文件的实际执行证据证明缺席，不从空数组、文件删除或换行判断修复。任务仍是固定 scan/member 投影，不新增任务表；后续 Hook 如另获授权须复用同一 eq-v1。本轮不实施 Hook。

修复交接只读且使用固定约束，源/模型文字非指令。宿主承担编辑，Runtime 默认离线复查，不自动下载引擎或数据库、不触发在线 dependency fallback，不构建目标、不调用宿主模型。缓存扫描按 provider/file 复用，成员仍逐条判断；组内任一未知阻止完成声明。无法证明 Gitleaks/IaC 原 detector/check 已执行时缺席保守 INCONCLUSIVE，这是能力边界，不借规则成功进程作充分证明。

宿主执行报告为未验证声明，与 Runtime 观察分离，不影响风险/覆盖、triage、修复状态或生成新的 AI 审阅。明确选中修复意图授权范围内本地修改，超出公网/生产/发布等仍遵守既有授权边界；不以普通用户重复确认替代精确引用。SDK 自动化与真实宿主 UX、独立人工真值分别验收。

本轮实现与分发依据：`1e10b53`；起始 `0f33d26`。Windows 独立包实际 source_commit 与实现一致，SDK 取得13工具及 v0.3 契约，真实 Semgrep 组内仍存在/部分/全部规则复查结果通过；本轮测试、package、compliance 和四平台 standalone CI 均 success，详见 AJ 与 [native/CI 证据](fix-verify-native-evidence.json)。文档最终 HEAD 用 `git log -1 --format=%H -- docs/PROJECT_STATE.md` 获取；代码之后若变化须重新验收。不要自行开始 Hook；真实 UX、三位试用与独立人工质量状态不变。

## ADR-018 — Advisory Hook 家族多重集（Accepted / Implemented v0.1）

Rule/file 覆盖决定能否证明消失；eq-v1 复用为 family key，并保存数量/安全坐标。不能 set-diff 家族后把第二处遗漏，不能把不同行的同家族当唯一 instance，不能在 scanner failure/删除/部分覆盖时 resolved。Secret 只存 detector/path/count/coords，未知缺席保留。Hook quick 使用变更文件完整候选，其前置适用规则规划、Raw历史指纹、风险策略和 MCP 校验保持；不调用模型，不执行构建/补丁或在线解析。

短进程使用跨进程持久冷却/OS lock。首次缺 session baseline 只建立基线；Stop 强制收敛或复用，不启动 watcher。项目 Hook 配置依据当前官方 schema，配置成功不等于 Host触发成功；Codex/Cursor fresh host trial Pending，未验证产品不生成 schema。依据本轮用户明确要求及 AK 证据，ADR-016 的旧 PREREQUISITE_MISSING 仅为历史记录。
