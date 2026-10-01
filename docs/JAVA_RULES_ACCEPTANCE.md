# Rule Coverage + Java Core Rules v0.1 验收（A–AB）

## A–D. HEAD、变更与版本

起始 HEAD：`341e1e18bca1c082f456eb7d5b6fb68b3240070b`，feature/runtime-mvp，开始时工作区干净；baseline 183 passed、6 skipped、5 subtests。
此阶段最终 HEAD 随交付提交列表提供。本阶段独立提交；main 不修改、merge 或 rebase。
变更包括 rule_catalog.py、rule_coverage.py、rulepacks.py、scanners.py、sast.py、runtime.py、models.py、
human.py、mcp_server.py、cli_progress.py、target.py、catalog.json 和规则/fixture；新增质量门禁、benchmark、文档。
CI、package-data、sdist manifest、wheel 检查、notices 和对应测试同步更新。
规则包 ai-security-core **1.1.0**；checksum `52188177327841e4d0c8c517cbccd86f0503a1623c0cf6adf103fbbc2e9ec742`。

## E. Rule Coverage 与前置计划

TargetProfile → Rule Catalog → Applicable Rules/Files → SAST Plan → Engine preparation/execution。
正式 SASTRulePlan 记录 pack 身份、版本、checksum、语言、适用规则及文件；Coverage 含 per_language 的
available/selected/executed_rules、类别、frameworks、状态、target/scanned files、distinct 总计及有效 scope。
执行证据使用单次引擎输出的 time.rules 与 paths.scanned；errors、skipped rules 或缺失证据降低覆盖。
不重跑 Semgrep、不复制扫描源码。零规则不准备、不启动引擎，ScannerRun 和 CODE_SAST 为 NOT_COVERED。
覆盖按本次 scope 计算，不宣称复杂跨文件 SAST。

## F. Rule Catalog

`rules/catalog.json` 是正式能力目录，RuleRecord 交叉校验 YAML：rule_id、language、engine_languages、category、
CWE、severity、confidence、maturity、framework、pack/version、references、provenance、mode、path、extension、fixture。
唯一 ID、合法语言、必需 metadata、引用和 provenance 均 fail closed。所有新增规则独立编写，FIRST_PARTY、Apache-2.0；
没有导入、改写或下载 Registry/Community/商业规则。参考 CWE、JDK/MyBatis API 及 Semgrep DSL 文档，链接见 RULE_COVERAGE.md。

## G–J. 数量

Java 22 条（21 Java AST + 1 MyBatis mapper XML），Python 2 条；Java 12 个 catalog 漏洞类别。
Java search 7 条、taint 15 条。
全部默认规则 BETA，无 STABLE 宣称；危险 Script/Groovy/SpEL 未加入默认包。

## K–N. Fixture / lint / rule tests

全部 pack 正例 25、反例 28；每条都有两者。
`python scripts/test_rules.py` PASS：metadata/catalog lint、Semgrep 加载和精确 expected finding 集合均通过。
覆盖固定命令/allowlist、PreparedStatement、JdbcTemplate/LDAP 绑定参数、固定 URL/文件路径、安全 XML 配置、
默认 TLS verifier、SecureRandom 与非安全 Random 等反例。Windows 门禁明确使用 UTF-8，运行时 selected YAML 为安全转义文本。
没有测试的 default rule 不能通过质量门禁，CI 必跑。

## O–P. 零规则与 mixed-language

Case A：Java + JS、仅 Python user rules → Semgrep ensure 0、invocation 0，CODE_SAST/ScannerRun NOT_COVERED。
Case B：Java 有规则、JS 无规则 → engine 只收到 App.java，Java EXECUTED、JS NOT_COVERED、CODE_SAST PARTIAL。
Case C：Java + JS 两者有 explicit user rules → 两个源文件进入范围，CODE_SAST EXECUTED。
另测 exit 0 缺 time.rules → FAILED coverage；UNAVAILABLE 和 NOT_COVERED 严格区分。

## Q–R. Jeepay coverage 与 findings

真实项目：`C:\Users\Administrator\Downloads\jeepay-master\jeepay-master`，实际运行 `security-check scan --mode release`。
650 个 project files；Java 源文件 512；Java/XML SAST scope 548，JS/Vue/YAML/Markdown 等 102 文件未送入 Semgrep。
Java available/selected/executed = 22/22/22，实际扫描 548 文件，Java EXECUTED。
JavaScript 0 规则、10 文件 NOT_COVERED，CODE_SAST PARTIAL。
Semgrep 耗时 40450 ms，发现 4 个问题。
对比用户给定 baseline 36.9 秒、0 findings、约零 Java/JS 规则：本轮执行有效规则，并非空转。
不要求更快；最终记录期间另有 pytest/build 活动，耗时不可用于严格微基准比较。
首条 progress <1 秒，heartbeat 持续，完成/失败及时输出。Trivy Maven 429 未绕过，分离/fallback 属后续独立阶段。

## S–T. 逐条质量标注

| Rule | File : line | Severity / confidence | Review |
|---|---|---|---|
| ai-security.java.weak-digest | jeepay-core/src/main/java/com/jeequan/jeepay/core/utils/JeepayKit.java:100 | MEDIUM / MEDIUM | NEEDS_REVIEW |
| ai-security.java.weak-digest | jeepay-payment/src/main/java/com/jeequan/jeepay/pay/channel/xxpay/XxpayKit.java:63 | MEDIUM / MEDIUM | NEEDS_REVIEW |
| ai-security.java.trust-all-hostname | jeepay-payment/src/main/java/com/jeequan/jeepay/pay/channel/ysfpay/utils/YsfHttpUtil.java:314 | HIGH / HIGH | LIKELY_TRUE_POSITIVE |
| ai-security.java.trust-all-certificates | jeepay-payment/src/main/java/com/jeequan/jeepay/pay/channel/ysfpay/utils/YsfHttpUtil.java:326 | HIGH / HIGH | LIKELY_TRUE_POSITIVE |

两项 HIGH 均逐条看过危险方法及实际安装调用：X509TrustManager.checkServerTrusted 空方法、HostnameVerifier.verify 无条件 true；
SSLContext.init 与 https.setHostnameVerifier 真实使用它们，标 LIKELY_TRUE_POSITIVE。
全部两项 MEDIUM 都查看了局部上下文；仅 MD5 helper 不足以证明可利用漏洞，均标 NEEDS_REVIEW。
没有将不确定 finding 标为 TP；该标注是人工 benchmark 注释，不是 AI Triage 或正式风险验证。
详细逐条上下文和 reasoning 在 jeepay-rule-benchmark.json.manual_review。

## U–V. 独立 benchmark 与 FP

隔离临时目录中的 Spring REST 和 JDBC 两套自建 Java 样本，各检出 4 个明确漏洞，安全方法无额外报警。
benchmark 记录真实 rule IDs、位置与统一 Finding。质量门禁同样要求 actual == expected，拒绝安全样本额外匹配。
Jeepay 4 个匹配没有出现几十/几百条报警风暴；尚不能从一项目推断广泛 FP 率。
弱摘要用途、MyBatis identifier allowlist、其他 XML 安全配置及复杂路径校验仍需局部/人工审查。

## W–Y. Human / JSON / MCP

human 中文说明规则包、每语言状态、规则和文件数，并明确“匹配结果不代表没有漏洞”。
完整 human stdout/stderr 见 jeepay-rule-stdout.txt / jeepay-rule-stderr.txt。
JSON benchmark stdout 可直接 json.loads，包含 rule_coverage、英文枚举、原 Rule Context。
MCP 精简去掉大 scope_files 列表，保留规则/文件计数、状态、pack/checksum、IDs 和 Finding technical_details；
示例见 rule-mcp-evidence.json。现有五工具和官方 stdio self-test 验收保持通过，未引入 CLI progress stdout。
Finding 保留 rule_id、pack/version、category、CWE、confidence、maturity、engine、原 severity、NOT_VALIDATED，
不把规则匹配当作最终风险证明；Runtime RiskEngine 仍单独聚合总风险。

## Z. 回归 / 分发

全量 pytest：229 passed、6 skipped、5 subtests，82.36 秒；新增 rule coverage suite 46 cases。
后续 MCP 精简改动的 46 cases 单独复验通过。此前 progress/heartbeat/取消/diagnostics/non-Git/Alpha 约束保留。
Rule gate、licenses --check-distribution、generate_notices --check、wheel/sdist build、check_wheel、clean venv 安装通过。
Alpha acceptance 脚本通过。Windows 独立程序构建、archive/MCP 及实际引擎扫描验收；最终跨平台 CI 随交付报告。

## AA–AB. 限制与下一阶段

未覆盖 TransformerFactory/SchemaFactory XXE、HttpClient/WebClient/OkHttp、ScriptEngine/Groovy/SpEL、
复杂跨文件数据流、IDOR/authorization、业务/资金逻辑和完整 sanitization。详情见 RULE_COVERAGE.md。
下一步按用户新附件完成 Trivy capability decoupling 和 OSV fallback，独立提交；
Evidence Builder + Joern + AI Risk Validation 仅列建议，当前不实现 AI。
