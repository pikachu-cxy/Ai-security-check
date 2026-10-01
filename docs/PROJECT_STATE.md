# AI Security Runtime — Project State

**新电脑 / 新 Codex Chat 的第一入口。** 更新：2026-10-02（Asia/Shanghai）。先读本文，再按文末 Agent Handoff 恢复；项目知识应从 Git 中取得，不能依赖上一段聊天或原电脑的缓存。

## 当前基线与 Milestone

| 项目 | 当前记录 |
| --- | --- |
| Branch | `feature/runtime-mvp` |
| 本轮起始 / 规划基线 HEAD | `7e197443eb4f712d10bc9a61be82c4929b1569da` |
| 代码及既有验收快照 | `3d773aaaa1b95b8c7596bf32c77c4bd5eabfd399` |
| Triage 最终实现 HEAD | `557052049c74c6d1ca4321c2d9559483a36f55d2` |
| 当前 milestone | **AI Finding Triage & Risk Validation v0.1 已完成实现和验收** |
| Runtime package version | `0.3.1`；不等于 Triage milestone 编号 |
| 下一阶段 | **AI Triage Quality Validation & Developer Guidance**；用户已确认路线，尚未实施 |
| 首个产品迭代 | **开发者任务入口 v0.1**；待明确开发任务授权 |
| 本轮范围 | 更新既有四份主文档并提交推送 `feature/runtime-mvp`，无源码开发 |

此表分别记录本轮规划起始 HEAD、既有代码/验收快照与实现提交。包含本文的文档提交是规划基线的后继；恢复时用 `git rev-parse HEAD` 获取 checkout 的实际最终 HEAD，用 `git log -1 --format=%H -- docs/PROJECT_STATE.md` 获取最近状态文档提交，避免把无法包含自身 SHA 的文档快照当成永远最新。若有更晚代码提交，必须重新核对状态。

上一轮 `7e19744` 已将四份主文档按 v0.1 重写并推送；此前以 `47c41f4` 为基线、把 triage 当 WIP 的草稿已失效。本轮从干净工作区开始，根据用户确认加入开发者任务引导路线及后续宿主报告；保留既有实现/验收，不重新扫描、不替人工标注、不改源码。

最近关键提交：

| Commit | 交付内容 |
| --- | --- |
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
| MCP | mcp_server.py；当前 8 工具，session/hash/引用校验与 workspace binding |
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

MCP 当前工具：`scan_diff`、`scan_project`、`get_findings`、`generate_fix`、`verify`、`prepare_triage`、`submit_triage`、`get_triage`。`generate_fix` 是确定性任务，`verify` 是原 scanner 复查；Triage 是独立的风险审阅。当前没有 workspace 结果汇总/开发者任务工具，MCP 也没有最新扫描入口或 `latest` 别名；后文规划不能当成已新增工具。

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

报告来源：2026-10-02 用户在当前聊天粘贴的 Jeepay 宿主 Codex 验收与随后只读核查回复。固定 scan ID：`99ca7566-4a6f-4818-b447-38646072457b`。**本轮未在 Jeepay 宿主直接重跑 MCP，也未固化该运行的机器可核验 artifact、Runtime/Jeepay revision 和 packet 摘要；以下是用户提供的报告，不替换上述已提交的历史证据。**

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

最终实现 `5570520` 的既有验收：全量离线 **382 passed、6 skipped、6 subtests passed**（90.60 秒），Triage 定向 **74 passed**；规则门禁、合规、wheel/sdist、clean install、Windows native archive 与 BYOK loopback 通过。报告记录同一实现 SHA 的 Runtime tests / Compliance / Package integrity / 四平台 Standalone CI 成功，链接保留在 AI_TRIAGE_ACCEPTANCE。skipped 不计为通过。本轮仅校对文档/源码/证据及 Git 差异，不冒充重跑这些验收。

## 已知限制与不可误读的状态

- 默认 `human.render_triage` 当前仍使用“已验证”称呼有效 AI 记录；VALID 仅表示分析记录通过 Runtime 校验，不表示人工验证、复现或线上可利用。开发者任务入口尚未实现，后续迭代将修正表达并提供普通/详细视图。
- 无 Joern、compiler-grade 跨文件 dataflow、完整 dependency reachability、主动 AI 全仓审计；版本命中、有限词法搜索与文件位置不能证明可利用性或误报。
- 实际公网 BYOK 模型效果/兼容性、不同模型一致性、triage precision 与 suppression risk 未测；独立人工标注未完成，不能宣布“99% 准确率”或“零漏报”。
- Raw 始终保留；SUPPRESSED 仅影响独立显示优先级。原 RiskEngine 不随 triage 自动解禁。
- Secret 匹配行、相邻字面量与回显有脱敏，但任意未知 Secret 不能获得完整检测保证。宿主模型可能联网，Agent-native 不代表全程本地推理；外部 BYOK 每次显式授权，原在线依赖授权不能推定为模型源码上传授权。
- Evidence 依赖对应 workspace/文件仍存在；失效或不可读取变 STALE。跨设备绝对根路径和本地 HMAC key 不同，ID/cache 不保证可复用；provider 的 host-managed 标签也不是精确模型版本证明。
- 当前按排序结果先取 limit，再查 cache；重复默认批次可能优先命中既有项，继续未验证项应明确选择 finding IDs/筛选条件。单批最多 20，115 候选不意味着一次 triage 全覆盖。
- `verify` 只枚举 primary adapters，OSV-only Finding 一般 UNKNOWN；位置变化/文件删除不能替代业务修复验证。
- scans/findings 不是数据库级 immutable audit log；Triage 先批次校验，再逐记录提交，没有整批事务、retention 或多租户隔离。未绑定 MCP 也不提供 workspace 隔离。
- 程序未自动执行目标项目构建。scanner plugins 是受信任 Python 代码；进程 timeout/快照不是 OS sandbox。原 WorkBuddy 版本的 UI 路径与真实连接限制见历史验收，不因 SDK 测试而宣称全部客户端自动可用。
- `privacy.py` 的旧 LocalContextProvider/AIProvider.generate_fix 没有接入新 Triage。State 与 managed tool DATA_DIR 分开，不静默搬移数据库。

## 下一阶段

用户于 2026-10-02 确认 **AI Triage Quality Validation & Developer Guidance** 路线，详细范围与验收见 [NEXT_STAGE](NEXT_STAGE.md)。**本次确认授权路线持久化、commit + push；没有授权本轮源码开发。所有新增能力均为 Planned。**

产品迭代顺序：

1. **开发者任务入口 v0.1**：当前 workspace 的扫描定位、纯只读汇总、保守任务合并、普通/详细视图、准确状态与来源、明确下一步。建议新 MCP 名称 `get_security_summary` 尚未实现；当前仍八个工具。
2. **继续核查**：引导宿主推进待分析项、补充受限证据，先查代码能回答的问题，再询问必要业务事实；处理重复批次/cache 推进问题。
3. **修复与验证**：准备可审阅补丁、兼容性说明与验证计划，执行已获授权的操作；现有 generate_fix / verify 不等于该完整流程。

独立人工质量工作协同推进：冻结 Jeepay benchmark 身份、人工盲审与 ground truth schema、五类 verdict 标准、Agent-native/BYOK 模型比较、suppression risk、precision/agreement 与 prompt/model regression。没有人工审阅者时保持 UNREVIEWED；模型不得自填人工真值。易用性用三位未参与开发的开发者试用观察，不能换算为安全准确率。

首个待授权产品开发任务是任务入口；首个质量任务是核实固定源码身份与独立人工试标。Raw、TriagePolicy、RiskEngine、覆盖契约和上传/执行授权边界保持完整。任务入口交付不表示整体质量 milestone 完成；Joern Java PoC 仍须在质量稳定且有明确证据增益后单独评估。

## Agent Handoff

1. 在新电脑取得该仓库。新 clone 可用 `git clone --branch feature/runtime-mvp https://github.com/pikachu-cxy/Ai-security-check.git`。已有 checkout 先 `git status`；有本地改动先保留并处理，勿覆盖。切到 `feature/runtime-mvp` 后 `git pull --ff-only origin feature/runtime-mvp`，不 merge/rebase main。
2. 依次读取 **PROJECT_STATE.md → ARCHITECTURE.md → DECISIONS.md → NEXT_STAGE.md → AI_TRIAGE_ACCEPTANCE.md**；再读 JAVA_RULES_ACCEPTANCE.md 与 OSV_DEPENDENCY_FALLBACK.md。只在相关问题需要时展开其它历史 acceptance/证据。
3. 执行 `git status`、`git branch --show-current`、`git log -10 --oneline`、`git rev-parse HEAD`，确认当前版本。以当前代码和最新 acceptance 校准本文的快照，区分已实现与计划。
4. 根据任务阅读 `src/security_runtime/runtime.py`、`models.py`、`scanners.py`、`osv.py`、`dependency_fallback.py`、`rule_coverage.py`，以及四个 `triage*.py`、`mcp_server.py`、`storage.py` 和对应 tests。不要凭旧 README 或 Capability 枚举预留项宣称已支持。
5. 按 README 的当前安装说明恢复运行环境，先使用 `security-check doctor --path <project>` / `tools status`。Git 不会恢复用户 state/tools、API key 或 Jeepay 源码；在新 workspace 扫描会产生本地 identity，不能直接套用旧 scan ID。需要重放固定 benchmark 时先确认源码版本与输入摘要；不要自动启动在线依赖查询或模型上传。
6. 恢复后的首个待授权产品任务是 **开发者任务入口 v0.1**，同步质量工作是固定身份与独立人工 Ground Truth。先按 NEXT_STAGE 区分已批准路线与尚未实施功能，再接收明确开发任务；本次“确认”只授权文档持久化及推送。不能自行重写 v0.1、实现后两轮或立即做 Joern。没有独立人工标签时，质量指标保持 UNKNOWN / NOT_MEASURED；保留全部 Raw、scan/triage coverage 与安全边界。
7. 两组 Jeepay 结果不可混用：已提交回放 `f5224162-...` 与用户提供的实际宿主报告 `99ca7566-...` 分别保留来源和状态。旧 scan ID 不是跨设备标识；宿主补充调用链不是已接受 Runtime Triage。恢复质量样本须核对源码 revision/packet 身份，未固化的报告只作为待补证据的产品输入。
