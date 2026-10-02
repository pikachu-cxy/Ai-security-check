# AI Security Runtime — Project State

## Developer Fix & Verify v0.1 — 当前状态（2026-10-02）

起始干净、ff-only 同步 HEAD `0f33d2624204794c84da6fa10cf43b8178cd5a56`，分支 feature/runtime-mvp。本轮明确授权 A→B，先完成 A 回归再实施 B。Stable Finding Equivalence 与任务修复/验证 v0.1 已实现；整体宿主产品 UX 尚待真实验收。Hook Integration 未开始，完成本轮推送后停止。

保留旧 occurrence ID/fingerprint 与历史 Raw/triage/task_ref；eq-v1 无行号，区分原 rule/provider/file，Dependency 复用稳定包/advisory身份，Secret 不含原值/匹配行/凭据摘要。旧 verify 只有完整原规则/文件复查证明缺席时才 RESOLVED + SCANNER_VERIFIED_RESOLVED，行号移动仍 STILL_PRESENT，缺文件/规则/引擎或 scope 无证明为 INCONCLUSIVE。

MCP 当前13工具，新增 prepare_task_fix（严格只读约束/受限证据交接）、verify_task_fix（本地 scanner/cache/temp 副作用，非 destructive）；能力契约 developer-guidance-v0.3，required subset。固定 task_ref 绑定 workspace/scan/精确成员，变化刷新，新 scan 不换对象。宿主响应明确“修复它/修第一项”后编辑选定本地代码并调用复查；Agent fixes. Runtime verifies。组内全部修复/全部仍在/混合为 SCANNER_VERIFIED_RESOLVED/STILL_PRESENT/PARTIALLY_RESOLVED，任一未知整体 INCONCLUSIVE，完全未复查 NOT_VERIFIED。

复查最多100成员/20原受影响文件/2MB，同 provider/file 复用，默认离线不下载或自动fallback，不构建/编辑目标、不调用模型。prepare 沿用 EvidenceBuilder 的20项/32KiB/120行/5相关文件预算，原 triage session/hash/evidence_refs 防护不变。宿主 patch/build/tests 声明为 UNTRUSTED_HOST_REPORT，不能改变 Runtime 观察或结论。Gitleaks/IaC 未提供原 detector/check 执行清单时缺席保守 INCONCLUSIVE；POM PARTIAL 不能证明完整图修复。

完整离线508 passed / 6 skipped / 6 subtests passed（120.12秒）。真实 Semgrep 1.178.0 合成100→110行仍存在、安全替换、分组只修一项及实际子进程失败均符合预期；包/合规/wheel/sdist 与本地全新 Runtime venv 安装通过（复用本地 SDK 依赖，无公网）。Windows native/实际 SDK及四平台新 CI 门禁均通过（实现 HEAD `1e10b53`），见 [AJ 验收](AI_TRIAGE_ACCEPTANCE.md) 和 [合成证据](fix-verify-synthetic-evidence.json)；结构/边界详见 [当前架构](ARCHITECTURE.md)。

没有修改 Jeepay、旧 scan/benchmark、ground truth、risk/coverage/policy；没有 scanner 公网查询、外部模型、目标构建或生产变更。三位真实开发者试用、真实宿主普通意图连续 UX 仍 Pending，独立人工 ground truth UNREVIEWED/null、质量指标 NOT_MEASURED。Hook 当前 Planned / NOT_STARTED，旧 PREREQUISITE_MISSING 留作历史门禁记录。


**新电脑 / 新 Codex Chat 的第一入口。** 更新：2026-10-02（Asia/Shanghai）。先读本文，再按文末 Agent Handoff 恢复；项目知识应从 Git 中取得，不能依赖上一段聊天或原电脑的缓存。

## 当前基线与 Milestone

| 项目 | 当前记录 |
| --- | --- |
| Branch | `feature/runtime-mvp` |
| 本轮开发起始 HEAD | Fix & Verify：`0f33d2624204794c84da6fa10cf43b8178cd5a56`；历史 Hook 前置检查：`787aace817bd607efd22bc70a7bd613a5f313faa`；继续核查历史起始 `50a01e6870d78e6fd8a96a8b8fbe236521c5306f` |
| 开发者任务入口实现 HEAD | `00cbd721792ad14118f005ff1fcbb3996e5a8aa0`；第一轮 AG 验收附录 |
| Fix & Verify 实现 HEAD | `1e10b53aacf0dc0f69ad00c3126f8d8298e78989`；第三轮 AJ 验收附录 |
| 继续核查实现 HEAD | `f2cb534f27698881ead2b2f3452bc36598c6e957`；第二轮 AH 验收附录 |
| 代码及既有验收快照 | `3d773aaaa1b95b8c7596bf32c77c4bd5eabfd399` |
| Triage 最终实现 HEAD | `557052049c74c6d1ca4321c2d9559483a36f55d2` |
| 当前 milestone | **AI Finding Triage & Risk Validation v0.1 已完成实现和验收** |
| Runtime package version | `0.3.1`；不等于 Triage milestone 编号 |
| 下一阶段 | **AI Triage Quality Validation & Developer Guidance**；前两个产品迭代实现/自动化/分发 CI 通过；旧聊天实际宿主试用未通过，刷新后复验与独立开发者试用 Pending，整体质量 milestone 未完成 |
| 首个产品迭代 | **开发者任务入口 v0.1**；源码/CLI/MCP/wheel/Windows native/四组 CI 验收通过；三位真实开发者试用 Pending |
| 本轮范围 | **Developer Fix & Verify v0.1：A stable equivalence / verify hardening → B task fix handoff / bounded verification**；Hook 未开始 |

此表分别记录本轮开发起始 HEAD 与既有 Triage 代码/验收快照；本轮实现提交及分发验收见 AI_TRIAGE_ACCEPTANCE 的开发者入口附录。恢复时用 `git rev-parse HEAD` 获取 checkout 的实际最终 HEAD，用 `git log -1 --format=%H -- docs/PROJECT_STATE.md` 获取最近状态文档提交，避免把无法包含自身 SHA 的文档快照当成永远最新。若有更晚代码提交，必须重新核对状态。

第一轮入口实现 `00cbd72`，验收文档 `50a01e6`。用户随后明确授权第二轮“继续核查 v0.1”，本轮从干净、已同步的 `50a01e6` 开始；不重跑 Jeepay 在线扫描、不替人工标注、不实现修复与验证。既有历史证据保留。

最近关键提交：

| Commit | 交付内容 |
| --- | --- |
| 1e10b53 | Stable equivalence / 原规则文件执行证据 / task_fix / 宿主执行声明分离 / 13工具 / 47项新增回归 |
| f2cb534 | 绑定任务继续核查、pending/cache推进、宿主普通意图指导/版本能力恢复、45项测试 |
| 00cbd72 | workspace 只读开发者任务入口、CLI summary / MCP get_security_summary、保守合并与 34 项入口测试 |
| 602a789 | NEXT_STAGE 产品与质量路线规划 |
| 7e19744 | Triage v0.1 架构、项目状态、决策与交接持久化 |
| 3d773aa | Triage/native 最终验收与证据 |
| 5570520 | offline 阻止外部模型调用 |
| f195020 | 完整 Finding range 的 120 行预算 |
| 93ef02f | 独立 Triage、EvidenceBuilder、MCP handoff、BYOK |
| 47c41f4 / 2538e1b / 26fe636 | OSV fallback、离线测试隔离与最终平台验收 |
| 51908b4 | Trivy vuln / misconfig 能力拆分 |
| 16d390b | Rule Coverage + Java Core Rules |
| 341e1e1 | 真实进度、heartbeat、可取消的引擎工作 |

## 已完成能力与代码入口

| 能力 | 实现入口 / 状态 |
| --- | --- |
| 共用本地 Runtime | CLI / MCP / pre-commit；quick、feature、release 与 Git/非 Git 边界 |
| 能力规划 | capabilities.py、planner.py；按 Capability 选适用 provider |
| 规则覆盖 | rule_catalog.py、rulepacks.py、rule_coverage.py、sast.py；计划与真实执行证据分离 |
| Scan providers | scanners.py、osv.py、dependency_fallback.py；四个 primary adapters + on-demand OSV |
| 原候选与风险 | models.py、findings.py、risk.py；normalization/dedupe 与原 release policy |
| 独立 Triage | triage_models.py、triage.py；prepare/submit/view/run、schema/ref/hash 校验、保守 policy |
| 受限证据 | triage_evidence.py；workspace 限定、脱敏、预算、UNTRUSTED_CODE、HMAC revision |
| 模型接入 | triage_providers.py；Agent-native 交接与显式授权的 OpenAI-compatible BYOK |
| 持久化 | storage.py；scans/findings + 加法新增 triage_records/cache index |
| 展示 | human.py、cli.py；候选语义、dependency grouping、独立 scan/triage coverage |
| 开发者任务入口 | security_summary.py、ReadOnlySQLiteStore；当前 workspace 最近扫描、只读 freshness、保守任务投影、最多三项推荐/完整详细视图 |
| 继续核查 | task_triage.py；版本化 task_ref、pending-only 选择、既有审阅复用、FAILED 显式重试、宿主受限 handoff |
| MCP | mcp_server.py；当前 13 工具，新增 prepare_task_triage；复用 submit_triage 和既有 session/hash/引用校验 |
| 进度/诊断 | progress.py、cli_progress.py、diagnostics.py、processes.py；stderr、heartbeat、限长脱敏错误 |
| 工具与分发 | toolchain.py、engines.py、licensing.py；wheel/sdist、PyInstaller onedir、四平台 CI |

具体行为与真实限制见 [ARCHITECTURE](ARCHITECTURE.md)，已确立决策见 [DECISIONS](DECISIONS.md)。

## 当前 Providers / Scanners

| Capability | Primary | Fallback / 说明 |
| --- | --- | --- |
| CODE_SAST | Semgrep 1.178.0 | 默认 first-party 规则；零规则为 NOT_COVERED |
| SECRET_SCAN | Gitleaks 8.30.0 | 独立成功；Trivy 失败不牵连 |
| DEPENDENCY_VULN | trivy-vuln / Trivy 0.74.0 | OSV-Scanner 2.6.0；仅白名单失败触发 |
| IAC_MISCONFIG | trivy-misconfig / Trivy 0.74.0 | 独立 scope/process，不准备 vuln DB |
| AI Triage | AgentNativeProvider；OpenAICompatibleProvider | 普通 scan 不调用；不是额外 Scanner |

`tools install --all` 仅准备三个主引擎，OSV 按需或显式安装。doctor 只读且 OSV 非强制就绪项。Dependency EXECUTED 要 SUCCESS + FULL coverage contract；SUCCESS/PARTIAL 仍 PARTIAL，不能只看进程状态。

MCP 当前十三个工具：`scan_diff`、`scan_project`、`get_findings`、`generate_fix`、`verify`、`prepare_triage`、`submit_triage`、`get_triage`、`get_security_summary`、`prepare_task_triage`、`get_runtime_info`、`prepare_task_fix`、`verify_task_fix`。新汇总在绑定/明确 workspace 内定位最近扫描，支持显式 scan_id 和 details；旧工具仍没有 `scan_id="latest"` 别名。`generate_fix` 是确定性任务，`verify` 是原 scanner 复查；Triage 是独立的风险审阅。

CLI：`security-check summary --path <project>`；加 `--details` 展开所有任务和逐 Finding/Advisory/AI 信息，加 `--json` 获取同一投影。未提供 path 时使用已绑定 workspace 或安全识别到的当前项目；MCP 未绑定且未明确 workspace 时拒绝取全局最近扫描。无记录仅返回 NEEDS_SCAN 和建议，不启动扫描。汇总经 SQLite mode=ro 读取，不创建 schema/state/HMAC key、不持久化 STALE、不调用 scanner/模型、不收集目标环境变量或凭据值。为核对已有审阅 freshness 可读取现有预算内的脱敏证据；继续核查使用任务引用进入已有受限证据流程，Runtime 不主动调用宿主模型。

## Java Rule Coverage

规则包 `ai-security-core 1.1.0`，checksum：

`52188177327841e4d0c8c517cbccd86f0503a1623c0cf6adf103fbbc2e9ec742`

Java 22 条（21 AST + 1 MyBatis XML），12 个类别，7 search / 15 taint；Python 2 条；全部默认规则 BETA。规则有 25 positive / 28 negative fixtures，质量门禁校验 catalog、metadata 与实际预期匹配。

Jeepay：650 个项目文件；Java 22/22/22 规则、548 Java/XML SAST 文件实际执行；JavaScript 10 文件、0 规则 NOT_COVERED；CODE_SAST=PARTIAL。有限 search/taint 不等价于 compiler-grade 跨文件 reachability。详情：[JAVA_RULES_ACCEPTANCE](JAVA_RULES_ACCEPTANCE.md)、[RULE_COVERAGE](RULE_COVERAGE.md)。

## Jeepay 已提交 Dogfood 基线与后续宿主报告

### 已提交的 native scan 与脚本化 MCP 回放

扫描时间：2026-10-01。保存的 scan ID：`f5224162-0624-416f-8472-0f0474e7fd58`。使用实际安装 CLI/scanners；公开 Jeepay 的依赖元数据在线解析/查询已获当次用户授权。本轮没有重新扫描、调用公网模型或修改证据。

| 原候选 | 数量 | 最新 scan capability |
| --- | ---: | --- |
| Semgrep code | 4 | CODE_SAST PARTIAL（Java 已执行，JS 未覆盖） |
| Gitleaks Secret | 9 | SECRET_SCAN EXECUTED |
| OSV dependency | 88 | DEPENDENCY_VULN PARTIAL |
| Trivy IaC | 14 | IAC_MISCONFIG EXECUTED |
| **Raw 总数** | **115** | **整体 scan coverage PARTIAL** |

Trivy vuln 为 FAILED / MAVEN_RATE_LIMITED，自动回退 OSV SUCCESS / PARTIAL。10/10 POM 有库存输出：177 package occurrences、135 个不同 ecosystem/name/version 组合，但有未知版本、内部模块解析不足及未证明完整 parent/property/传递/test 依赖图。成功返回 88 advisory 不是完整图证明，未提升 FULL。依赖显示为 28 个 package/version/ecosystem/manifest 组，原 88 项保留。

同一 native Raw Result 经真实 SDK stdio MCP prepare/submit/get，以及 Windows frozen Runtime 复验：

| Triage 状态 / 优先级 | 数量 |
| --- | ---: |
| 已 triaged | **26** |
| ACTIONABLE | **2** |
| REVIEW | **23** |
| LOWER_PRIORITY | **1** |
| SUPPRESSED | **0** |
| UNTRIAGED | **89** |
| FAILED / STALE | 0 / 0 |

101 项 eligible（code/secret/dependency）。26 项为 4 code + 9 Secret + 13 dependency（3 CRITICAL + 原序前 10 HIGH）；剩余 75 dependency + 14 IaC = 89 UNTRIAGED。IaC 独立分类为 5 HARDENING / 9 BEST_PRACTICE，不是 AI 判定。

Verdict：2 CONFIRMED（局部 TLS bypass 安装证据）、1 LIKELY（Java Secret 候选）、22 NEEDS_REVIEW（MD5/配置/依赖）、1 UNLIKELY（文档候选）、0 FALSE_POSITIVE。两条 TLS ACTIONABLE 保留生产调用/攻击位置未知；MD5 的支付签名用途及依赖利用条件尚需确认。没有删除或压制任何真实 Raw Finding。

**这些是 Coding Agent 审阅 artifact 的脚本化 MCP 回放，不是独立人工 ground truth，也不是公网模型质量测试。** `jeepay-human-ground-truth.json` 的 26 项 human_label/reviewer 均 null、status=UNREVIEWED；合成 fixture 标签也不能替代真实项目人工真值。invalid output rate=0 只说明此次结构/引用交接通过，不是准确率。第二次本地 MCP 回放 26 cache hits。

证据：[真实 native scan](jeepay-osv-online-evidence.json)、[MCP triage](jeepay-triage-evidence.json)、[frozen MCP triage](jeepay-frozen-triage-evidence.json)、[人工标注入口](jeepay-human-ground-truth.json)、[native BYOK loopback](triage-native-byok-evidence.json)。原 capture 含原电脑 workspace，只有 branch=master，**没有明确 Jeepay commit SHA**；跨设备复现必须补核对应源码版本，不能猜测一致。

### 用户提供的后续实际宿主 MCP 验收（与历史回放分开）

报告来源：2026-10-02 用户在当前聊天粘贴的 Jeepay 宿主 Codex 验收与随后只读核查回复。固定 scan ID：`99ca7566-4a6f-4818-b447-38646072457b`。**此段保留第一轮时点的用户报告。第二轮对同一已保存 scan 只读复用有效审阅的实际 SDK 验收见 AH；没有重跑原 scanner/宿主模型，也未补原源码 revision/独立 ground truth。**

| 状态 | 报告数量 |
| --- | ---: |
| Raw / eligible | 115 / 101 |
| VALID triaged | 26（4 code + 9 Secret + 13 dependency） |
| ACTIONABLE / REVIEW | **0 / 26** |
| LOWER_PRIORITY / SUPPRESSED | 0 / 0 |
| FAILED / STALE | 0 / 0 |
| UNTRIAGED | 89（75 eligible dependency + 14 不 eligible IaC） |

该宿主轮次追加处理 9 Secret + 13 dependency，报告 cache hits=0，保留先前 4 code。整体 scan、CODE_SAST、DEPENDENCY_VULN 为 PARTIAL；SECRET_SCAN、IAC_MISCONFIG 为 EXECUTED。Dependency 保留 Trivy MAVEN_RATE_LIMITED 失败与 OSV fallback 的部分覆盖；AI Triage 未提升 coverage。与历史的 2 ACTIONABLE / 23 REVIEW / 1 LOWER_PRIORITY 分布不同，不能为匹配旧输出调整新判断。

宿主随后额外读取 Jeepay 源码，报告 YsfHttpUtil 的校验绕过实现位于云闪付渠道下单、关单、退款和补单查询的请求链中；生产渠道、部署版本、信任配置和代理条件仍未知。这是**宿主补充只读核查**，没有在本轮作为新 evidence_refs/context_hash 提交 Runtime。它不是 Runtime 自动调用链分析、人工 ground truth、已执行补丁或修复验收。

产品反馈：用户需要多轮验收提示词才能取得可执行任务。将两条 TLS 候选合为一个跟进任务、Agent 先查仓库能够回答的问题、只询问必要业务事实，应成为后续产品流程；Secret 不询问原值，依赖信息缺失时不编造升级版本。当前优先级维持原结果，0 ACTIONABLE 不表示安全。

## 当前验收依据与文档导航

四份主文档各司其职：本文恢复项目状态；ARCHITECTURE 描述当前实现；DECISIONS 记录决策；NEXT_STAGE 规划未来工作。其它 acceptance 与 JSON/TXT 保留为阶段验收和证据，不要求每次恢复全部阅读，也不新增重复总结文件。

| 阅读目的 | 文档 |
| --- | --- |
| 最新 milestone 与完整验收 | [AI_TRIAGE_ACCEPTANCE](AI_TRIAGE_ACCEPTANCE.md) |
| 最新统计、测试/分发/CI 摘要 | [triage-delivery-evidence.json](triage-delivery-evidence.json) |
| Java 规则与执行覆盖 | [JAVA_RULES_ACCEPTANCE](JAVA_RULES_ACCEPTANCE.md)、[RULE_COVERAGE](RULE_COVERAGE.md) |
| Dependency fallback、在线/离线边界 | [OSV_DEPENDENCY_FALLBACK](OSV_DEPENDENCY_FALLBACK.md) |
| Trivy 独立能力 | [TRIVY_CAPABILITY_DECOUPLING](TRIVY_CAPABILITY_DECOUPLING.md) |
| 进度、失败语义与集成历史 | [CLI_PROGRESS_ACCEPTANCE](CLI_PROGRESS_ACCEPTANCE.md)、[REAL_PROJECT_DIAGNOSTICS](REAL_PROJECT_DIAGNOSTICS.md)、[DEVELOPER_ALPHA_ACCEPTANCE](DEVELOPER_ALPHA_ACCEPTANCE.md) |
| 扩展/分发/许可 | [EXTENDING](EXTENDING.md)、[distribution README](../distribution/README.md)、[LICENSING](../LICENSING.md) |

既有实现 `5570520` 的 382 passed / 6 skipped / 6 subtests（90.60 秒）、74 项 Triage 定向、native BYOK loopback 及 CI 属于历史验收。第一轮从同步后的干净工作区重跑基线：382 passed / 6 skipped / 6 subtests（125.57 秒）；新增 34 项开发者入口测试，最终全量离线 **416 passed、6 skipped、6 subtests passed**（93.83 秒）。wheel/sdist、新模块分发门禁、独立安装、licenses/notices 通过；已有 Jeepay 记录的真实 CLI/JSON/MCP 只读验收产生 54 个任务，保留全部 115 Raw，数据库/key 文件字节不变。没有新扫描或模型请求。第二轮基线416 passed（97.78秒），新增45项，最终461 passed / 6 skipped / 6 subtests（152.30秒）；新模块wheel/sdist/全新venv安装、Windows native/实际SDK交接通过。当前实现CI状态见 AH；实际宿主自然语言试用/旧聊天工具恢复/三位开发者均Pending，skipped不计通过。

## 已知限制与不可误读的状态

- `human.render_triage` 与任务入口现在使用“已完成 AI 审阅”；VALID 只表示记录通过 Runtime 校验，非人工验证、复现或线上可利用。建议跟进任务不修改 Runtime priority；0 ACTIONABLE 不表示安全。普通视图最多三项，完整详细列表和 Raw 入口仍可获得。
- 无 Joern、compiler-grade 跨文件 dataflow、完整 dependency reachability、主动 AI 全仓审计；版本命中、有限词法搜索与文件位置不能证明可利用性或误报。
- 实际公网 BYOK 模型效果/兼容性、不同模型一致性、triage precision 与 suppression risk 未测；独立人工标注未完成，不能宣布“99% 准确率”或“零漏报”。
- Raw 始终保留；SUPPRESSED 仅影响独立显示优先级。原 RiskEngine 不随 triage 自动解禁。
- Secret 匹配行、相邻字面量与回显有脱敏，但任意未知 Secret 不能获得完整检测保证。宿主模型可能联网，Agent-native 不代表全程本地推理；外部 BYOK 每次显式授权，原在线依赖授权不能推定为模型源码上传授权。
- Evidence 依赖对应 workspace/文件仍存在；失效或不可读取变 STALE。跨设备绝对根路径和本地 HMAC key 不同，ID/cache 不保证可复用；provider 的 host-managed 标签也不是精确模型版本证明。
- prepare 不再先截断后查缓存；最多检查 1000 个候选，缓存不占新分析名额，packet/证据错误合计最多 20。任务入口保留当前 VALID，优先 UNTRIAGED、其次 STALE；FAILED 默认单列，retry_failed=true 才重试。115 候选不意味着一次 triage 全覆盖。
- 新 verify 可选 primary/fallback origins；位置移动按 eq-v1 仍存在，缺文件 INCONCLUSIVE，离线依赖图不足不判 resolved。Gitleaks/IaC 原 detector 执行清单不足时缺席 INCONCLUSIVE；扫描复查不等于生产安全。
- scans/findings 不是数据库级 immutable audit log；Triage 先批次校验，再逐记录提交，没有整批事务、retention 或多租户隔离。旧 MCP 工具未绑定时不提供 workspace 隔离；新汇总即使未绑定也必须明确 workspace，不能读取全局最近记录。
- 程序未自动执行目标项目构建。scanner plugins 是受信任 Python 代码；进程 timeout/快照不是 OS sandbox。原 WorkBuddy 版本的 UI 路径与真实连接限制见历史验收，不因 SDK 测试而宣称全部客户端自动可用。
- `privacy.py` 的旧 LocalContextProvider/AIProvider.generate_fix 没有接入新 Triage。State 与 managed tool DATA_DIR 分开，不静默搬移数据库。

## 下一阶段

用户已分别授权第一轮入口及第二轮 **继续核查 v0.1**。详细边界见 [NEXT_STAGE](NEXT_STAGE.md)。独立人工质量工作仍未实施，修复与验证 v0.1 已实现；原 ground truth 仍 UNREVIEWED/null。

产品迭代顺序：

1. **开发者任务入口 v0.1 — Implemented，自动化及分发/四组 CI 验收通过 / 人工易用性 Pending**：新增 get_security_summary，当前共十三个工具；来源与完整列表保留。用户明确目前无法安排三位未参与开发的试用者，因此不声称这一验收已通过。
2. **继续核查 v0.1 — Implemented / 自动化/原生/四组 CI 通过 / 旧聊天实际试用未通过，刷新后复验 Pending**：summary 任务自带 task_ref/continuation；宿主使用本次显示项的引用，不按 T01 重新索引。prepare_task_triage → 宿主受限分析 → submit_triage；有效审阅保留，过期重建，失败显式重试，必要业务问题仅为候选提示。用户实际两句试用的调用记录仅有 get_triage，继续轮没有工具调用；不能把聊天中的修复草案计为任务交接成功。同一配置程序的新离线 SDK 连接确认能力存在，疑似旧连接/工具列表，具体原因及宿主刷新未验证。见 [试用记录](jeepay-host-task-trial.json) 与 AH。
3. **Developer Fix & Verify v0.1 — Implemented / 宿主 UX Pending**：结构化只读交接、宿主编辑、bounded 原规则等价复查；见本文当前状态。

独立人工质量工作协同推进：冻结 Jeepay benchmark 身份、人工盲审与 ground truth schema、五类 verdict 标准、Agent-native/BYOK 模型比较、suppression risk、precision/agreement 与 prompt/model regression。没有人工审阅者时保持 UNREVIEWED；模型不得自填人工真值。易用性用三位未参与开发的开发者试用观察，不能换算为安全准确率。

前两个产品迭代已获授权并实现；首个未开展的质量任务仍是固定源码身份与独立人工试标。Raw、TriagePolicy、RiskEngine、覆盖契约和上传/执行授权边界保持完整。任务入口交付不表示整体质量 milestone 完成；Joern Java PoC 仍后置。

## Hook Integration 前置检查历史（2026-10-02，已由本轮前置交付更新）

该旧任务假设 Developer Fix & Verify v0.1 已完成，要求复用其不依赖 occurrence 行号的 Finding identity；若缺少则停止正式 Hook delta 实现。当时干净工作区执行 ff-only 同步后，远端/本机仍为 `787aace817bd607efd22bc70a7bd613a5f313faa`，没有新的 Fix & Verify 提交。该时点文档将修复与验证标为 Planned，findings.py 的代码指纹含 line，runtime.py 的旧 verify 按 fingerprint 判消失。本轮已修正该缺陷并交付前置，但未开始 Hook。

隔离合成 scanner 复现：同一规则/文件/代码仅从100行移到110行，fingerprint 改变，旧 verify 返回 RESOLVED；预期 STILL_PRESENT。不是实际 Semgrep 或业务修复验收。完整离线 baseline 为 **461 passed / 6 skipped / 6 subtests passed，108.77秒**。本轮仅记录门禁；不另建 identity、不实现 Coordinator/delta/host Hook 配置，不修改现有 pre-commit。恢复时先核对前置阶段的真实提交和行号移动回归，不能直接跳到 Hook 开发。详情见 AI_TRIAGE_ACCEPTANCE 的 AI 附录。

## Agent Handoff

1. 在新电脑取得该仓库。新 clone 可用 `git clone --branch feature/runtime-mvp https://github.com/pikachu-cxy/Ai-security-check.git`。已有 checkout 先 `git status`；有本地改动先保留并处理，勿覆盖。切到 `feature/runtime-mvp` 后 `git pull --ff-only origin feature/runtime-mvp`，不 merge/rebase main。
2. 依次读取 **PROJECT_STATE.md → ARCHITECTURE.md → DECISIONS.md → NEXT_STAGE.md → AI_TRIAGE_ACCEPTANCE.md**；再读 JAVA_RULES_ACCEPTANCE.md 与 OSV_DEPENDENCY_FALLBACK.md。只在相关问题需要时展开其它历史 acceptance/证据。
3. 执行 `git status`、`git branch --show-current`、`git log -10 --oneline`、`git rev-parse HEAD`，确认当前版本。以当前代码和最新 acceptance 校准本文的快照，区分已实现与计划。
4. 根据任务阅读 `src/security_runtime/runtime.py`、`models.py`、`scanners.py`、`osv.py`、`dependency_fallback.py`、`rule_coverage.py`，以及四个 `triage*.py`、`mcp_server.py`、`storage.py` 和对应 tests。不要凭旧 README 或 Capability 枚举预留项宣称已支持。
5. 按 README 的当前安装说明恢复运行环境，先使用 `security-check doctor --path <project>` / `tools status`。Git 不会恢复用户 state/tools、API key 或 Jeepay 源码；在新 workspace 扫描会产生本地 identity，不能直接套用旧 scan ID。需要重放固定 benchmark 时先确认源码版本与输入摘要；不要自动启动在线依赖查询或模型上传。
6. **开发者任务入口 v0.1 已实现，人工易用性试用仍 Pending**。恢复后先使用 summary/get_security_summary 按 workspace 检查记录；“继续第一项”使用当次响应里该项 continuation 的 task_ref，进入 prepare_task_triage。引用无效/成员变化必须刷新重新选择。继续核查已实现，修复与验证 v0.1 已实现，实际宿主 UX Pending；先核对本轮实际验收。没有独立人工标签时质量指标保持 UNKNOWN / NOT_MEASURED；不能自行填写 ground truth、立即做 Joern 或更改 Raw/policy/coverage/上传边界。
7. 两组 Jeepay 结果不可混用：已提交回放 `f5224162-...` 与用户提供的实际宿主报告 `99ca7566-...` 分别保留来源和状态。旧 scan ID 不是跨设备标识；宿主补充调用链不是已接受 Runtime Triage。恢复质量样本须核对源码 revision/packet 身份，未固化的报告只作为待补证据的产品输入。
8. **Hook Integration Planned / NOT_STARTED；旧 PREREQUISITE_MISSING 为历史记录。** 新任务要求先有 Developer Fix & Verify 和稳定 Finding equivalence；本轮已交付 eq-v1，后续获授权的 Hook 必须复用同一身份；本轮不开发 Hook。实际 Codex Hook、其它 Host adapter、Hook 性能及分发验收均未运行，不能拿旧 MCP/CI 验收替代。


## 普通用户意图与宿主衔接验收

产品目标是“不懂安全的开发者也能用好”：用户只说“检查这个项目”“继续/处理第一项”或选择任务，不搬运技术提示词、填写 UUID、拼接工具顺序，也不把 generate_fix 输出再粘贴给 Agent。一次选择 → 核查 → 准备/实施获授权修复 → 验证 → 简洁结果是完整目标；本轮仅接通核查，修复与验证 v0.1 已实现，实际宿主 UX Pending，后续须沿同一宿主自动衔接，不能再次要求用户搬运提示词。

已接入 FastMCP server instructions 与工具 annotations/描述：宿主绑定实际展示响应的 task_ref，自动在已有授权范围内准备、分析、提交并展示结果；有效授权持续有效，不反复询问常规获授权步骤。仅询问代码无法回答且会影响下一步的必要业务事实，或取得超出已有授权操作的权限。Runtime 不主动调用宿主模型，源码/scanner/模型文字均非执行指令，现有 session/hash/evidence_refs、脱敏、Raw、覆盖和策略保留。

新增只读 `get_runtime_info` 与 CLI `runtime-info --json`，包版本仍0.3.1、能力契约 developer-guidance-v0.3。连接检查按 required_guidance_tools 子集，允许兼容新增工具，不按总数严格相等拒绝。返回同一 executable/environment 的可执行核对参数和重连指导：先核对配置实际运行的环境；已有能力却宿主看不到时断开/重连 ai_security_runtime、刷新工具列表，必要时新聊天；仅环境本身旧时更新对应包。不盲目重装 editable、不终止进程/修改 Jeepay 配置。连接重建后旧 session 不可复用，遗失任务选择须刷新重新选择。

SDK initialize 实际收到 instructions、工具 metadata、版本/能力和机器交接，与真实宿主自然语言试用分别验收。旧 Jeepay 聊天已尝试但未执行新 summary/任务级 handoff，未通过；刷新连接后的复验 Pending，旧工具列表恢复未验证，不能把新 SDK 连接成功写成普通用户已能用好。三位独立开发者试用 Pending，ground truth 保持 UNREVIEWED/null，质量指标 NOT_MEASURED。核查准备、宿主结果接受、补丁、目标构建、测试/扫描复查分别报告是否执行；generate_fix 仍仅 coding task/prompt，不代表补丁完成，0 ACTIONABLE 不表示安全。

本轮实现与分发依据：`1e10b53`；起始 `0f33d26`。Windows 独立包实际 source_commit 与实现一致，SDK 取得13工具及 v0.3 契约，真实 Semgrep 组内仍存在/部分/全部规则复查结果通过；本轮测试、package、compliance 和四平台 standalone CI 均 success，详见 AJ 与 [native/CI 证据](fix-verify-native-evidence.json)。文档最终 HEAD 用 `git log -1 --format=%H -- docs/PROJECT_STATE.md` 获取；代码之后若变化须重新验收。不要自行开始 Hook；真实 UX、三位试用与独立人工质量状态不变。
