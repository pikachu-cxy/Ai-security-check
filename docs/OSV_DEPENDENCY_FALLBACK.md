# Trivy Capability Decoupling + OSV Dependency Fallback 验收

2026-10-01。本报告补充 [Java Rules / Rule Coverage A–AB 验收](JAVA_RULES_ACCEPTANCE.md)。规则阶段与 Trivy 解耦阶段分别已提交为 `16d390b`、`51908b4`，两阶段四组 CI 均通过。所有开发及推送仅在 `feature/runtime-mvp`。

## A. Trivy capability 拆分

`trivy-vuln` 只执行 `--scanners vuln`，负责 DEPENDENCY_VULN；`trivy-misconfig` 只执行 `--scanners misconfig`，负责 IAC_MISCONFIG。两个 ScannerRun 均记录 provider=`trivy` 及实际 capabilities。共享引擎准备事务串行，实际扫描独立并发。IaC 不准备漏洞数据库，其快照只有计划中的 Dockerfile／Terraform／YAML 文件。

## B. Secret provider 语义

默认 SECRET_SCAN 由 Gitleaks 提供。未保留默认 Trivy secret 进程，依赖进程失败不会把已成功的 Gitleaks 降为 PARTIAL。IaC EXECUTED 仅表示本次计划中的本地 Trivy 检查成功，不证明云上真实配置安全。

## C. OSV 固定版本

[官方 OSV-Scanner 2.6.0](https://github.com/google/osv-scanner/releases/tag/v2.6.0)。原生 release binary 固定版本及 SHA-256，支持 Windows x64、Linux x64、macOS x64／arm64。使用现有 HTTPS 下载、大小限制、校验、原子安装、版本探测及 managed binary 重验机制。

| 平台 | 官方 asset | SHA-256 |
| --- | --- | --- |
| Windows x64 | osv-scanner_windows_amd64.exe | e0ed7644118b717b028c249ee9d3515024e55e8510747ca08906eb96765354d6 |
| Linux x64 | osv-scanner_linux_amd64 | ca69b3d3cd08f889a49dc0a383122f71cc528b83803671df5fd874d97485b108 |
| macOS x64 | osv-scanner_darwin_amd64 | 60c5296637e977b28eeda5c7f13573e447659a632922737f94d11fa7e30ad6ca |
| macOS arm64 | osv-scanner_darwin_arm64 | 98c460dcd37de25819babd757d04542045b6243113e209edcd4d89fedb0256b4 |

## D. 许可证／分发

[固定版本官方 LICENSE](https://github.com/google/osv-scanner/blob/v2.6.0/LICENSE) 为 Apache-2.0。仓库保存 LICENSE、归属 NOTICE 和 LicenseMetadata，THIRD_PARTY_NOTICES 已更新。wheel／standalone 只携带 Runtime 适配代码与声明，第三方 OSV 二进制单独按需下载，不捆绑。分发检查仍禁止未经声明的引擎二进制。

## E. ToolManager 与 Doctor

OSV 沿用 EXPLICIT → MANAGED → compatible SYSTEM → AUTO_INSTALL，显式变量为 `SECURITY_RUNTIME_OSV_SCANNER_PATH`。`tools status` 显示 `ON_DEMAND / FALLBACK` 及真实本地 engine 状态。doctor 只读，不下载、不要求 OSV READY；verbose 单独显示可选 provider。`tools install --all` 只准备三个默认主引擎；`tools install osv-scanner` 为显式安装操作。

## F. 回退矩阵

| 主 provider 结果／诊断 | 自动回退 |
| --- | --- |
| SUCCESS、NOT_APPLICABLE、NOT_COVERED、SKIPPED | 否 |
| MAVEN_RATE_LIMITED | 是 |
| NETWORK_TIMEOUT、DNS_RESOLUTION_FAILED、PROXY_CONNECTION_FAILED | 是 |
| HTTP_5XX、DEPENDENCY_RESOLUTION_FAILED | 是 |
| ENGINE_UNAVAILABLE／UNAVAILABLE、缺少漏洞数据库 | 是 |
| OFFLINE_MODE | 可尝试本地 provider；仍禁止下载或在线查询 |
| CHECKSUM_MISMATCH、SECURITY_BOUNDARY_VIOLATION、非法路径 | 否 |
| CONFIG_CORRUPTED、SCANNER_OUTPUT_OR_CONFIG_ERROR、INVARIANT_VIOLATION | 否 |
| TLS_ERROR、未知错误、HTTP 401／403／404、过程超时／超量 | 否；直接保留真实错误 |

策略为 `should_fallback()`，仅失败／不可用／超时状态且符合明确错误白名单时考虑回退。fallback 不参与普通主计划，也不递归回退。

## G. Capability Coverage Contract

DEPENDENCY_VULN 至少有一个 SUCCESS 且 FULL 的 provider，就为 EXECUTED。主失败保留在历史，不单独导致 PARTIAL。一个成功但 PARTIAL 的 provider 只建立 PARTIAL；都不能执行／失败则为 UNAVAILABLE／FAILED。整体完成状态按最终能力契约聚合，不按所有历史 provider 都成功聚合。

OSV `--all-packages` 的 source inventory 必须覆盖全部计划锁文件，无解析警告、无未知包版本、无未支持清单，才满足 FULL。POM／requirements／go.mod 不是完整图的证明，保守 PARTIAL。Maven 测试依赖和完整 parent／property／传递图未获证明。[上游支持范围说明](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/)记录了 Maven 测试依赖限制。未知严重性保留 UNKNOWN 与原始 CVSS 向量，未伪造评分。

## H. Trivy SUCCESS 路径

主 provider 成功时不准备、不下载、不运行 OSV。自动测试检查 invocation count 为 0。完整归档验收先运行健康主引擎样例，并确认没有因此新建 OSV 安装，再通过显式验收步骤准备 OSV。

## I. Maven 429 → 回退成功路径

自动测试用明确的 MAVEN_RATE_LIMITED 主失败，验证 fallback 一次启动；FULL 成功为 EXECUTED，PARTIAL 成功为 PARTIAL。真实原生 CLI／MCP 验收使用显式缺失 Trivy、合成 npm 锁文件、原生 OSV 2.6.0、本地编写的测试漏洞库及 loopback 代理禁网，证明本地 FULL 库存范围契约与 provider 切换可执行。

这不是 Jeepay 在线成功记录，也不证明合成测试漏洞库包含现实世界全部漏洞。[原生离线记录](osv-offline-native-evidence.json)、[CLI／MCP 记录](osv-cli-mcp-evidence.json)、[冻结程序记录](osv-standalone-evidence.json)均明确标注 synthetic fixture。

## J. 主失败 → fallback 失败

保留两个 provider 的独立 ScannerRun、诊断及覆盖状态。失败／不可用 fallback 不使依赖能力虚假成功；其他已完成能力的 findings 保留。沿用 ErrorDiagnostic、网络分类、来源 host、重试建议和 proxy configured 状态。原始大段 stderr 不进入 MCP；少量 native 解析警告经脱敏限长后可作为覆盖不足说明。

## K. Offline 与安全边界

OSV 未安装：离线 ensure 返回 UNAVAILABLE／OFFLINE_MODE，零下载、零 scanner invocation。引擎已存在但本地 ecosystem 数据缺失：零在线查询。已有引擎和数据：`--offline --no-resolve`，不加 download-offline 参数。2.6.0 实际缓存为 `<data-dir>/data/osv/osv-scalibr/<ecosystem>/all.zip`；与旧文档的 `osv-scanner` namespace 不同，已通过真实原生执行验证。

只复制验证过的依赖清单快照；不复制源码、目标 OSV 配置或目标构建工具。显式空 Runtime 配置、lockfile 插件限定、`--no-call-analysis=all`，不执行 mvn／gradle／npm／pip／go 构建，不改 Maven settings，不自动加 mirror。显式 POM local parent 越出快照直接拒绝；隐式 root parent 文件系统查找在快照内关闭，保留 PARTIAL 说明。Trivy 离线也加 `--offline-scan`，不把未解析完整图标成 FULL。

## L. Human 输出

先显示最终能力成功与当前 OSV provider；FULL 回退后不在普通结果中展开大段主失败，verbose 可查看保留的主诊断。PARTIAL 清楚说明依赖图未获完整证明，仍显示未完成能力及重试信息。代码安全的 NOT_COVERED／PARTIAL 语义保持原规则阶段实现。

## M. JSON

`capability_results` 表示最终能力状态；`capability_details` 含 active_provider、provider_role、coverage、coverage_notes、primary_provider、primary_status、primary_error_code。ScannerRun 含 provider、capabilities、provider_role、coverage_contract、覆盖说明及独立诊断。roles 明确支持 PRIMARY／FALLBACK／SUPPLEMENTAL／USER_PROVIDED。

## N. MCP

返回相同 provider／coverage 元数据及统一 findings。实际 SDK stdio 初始化与 scan_project 回退验收通过；stdout 为协议流，进度不进入 MCP stdout／stderr。

## O. Progress

FALLBACK_SELECTED → FALLBACK_PREPARING → ENGINE_PREPARING／READY → FALLBACK_RUNNING → FALLBACK_COMPLETED／FAILED。使用现有 stderr renderer 和 heartbeat，包含实际版本／耗时／finding 数及诊断，不制造百分比。CLI JSON stdout 纯净；`--no-progress` 下 stderr 为空。原生 installed CLI 和 Windows frozen CLI 都验证通过。

## P. Jeepay 真实结果

规则阶段：650 项目文件，22 适用 Java 规则，548 SAST 文件，40.5 秒，4 个代码 findings；Java EXECUTED／JavaScript NOT_COVERED／CODE_SAST PARTIAL。未覆盖的 JS／Vue 等 102 文件不进入 SAST。

拆分后的真实独立执行：Trivy vuln FAILED／MAVEN_RATE_LIMITED，2,899 ms；Trivy IaC SUCCESS，1,221 ms，14 findings；Gitleaks SUCCESS，2,650 ms，9 findings。SECRET_SCAN 和 IAC_MISCONFIG 独立 EXECUTED。[真实记录](trivy-decoupling-evidence.json)。IaC 是尚未验证的 scanner finding，不宣称云上可利用。

**Jeepay OSV 在线验收尚未执行。** 自动审批拒绝了该动作，理由为未确认向 deps.dev／OSV.dev 发送这个真实项目依赖信息的授权。已请求用户仅针对本轮在线依赖查询批准，收到答复前保持该步骤待验收。没有用 mock、离线测试或扫描器安装结果冒充真实在线成功。

## Q. Finding normalize／dedupe

统一 category=dependency，保存 package、installed_version／package_version、ecosystem、manifest、OSV ID／CVE aliases、规范 vulnerability ID、严重性与 source。稳定 fingerprint 由 ecosystem／package／version／canonical ID／manifest 构成，并隔离不同 workspace。具有 CVE alias 的 OSV 和 Trivy 同一漏洞可合并 scanner_sources；不同包／版本／manifest 不合并；合并保留较高严重性及 alias 集合。统一通过 FindingNormalizer／deduplicate／RiskEngine。

## R. 测试结果

完整回归：308 passed、6 skipped、6 subtests passed（85.76 秒）；后续仅补全 installed_version 别名及 CVSS 向量保留，并重新运行相关测试。专门回退／分发／合规测试 80 项通过。规则门禁 24 条规则：25 positive／28 negative，lint 与真实 Semgrep fixture 均通过，checksum 与原规则阶段相同。原 Alpha SDK acceptance 通过。

覆盖用户 33 类验收：能力失败隔离；健康主 provider 零回退；Maven／网络／不可用触发与完整性禁止；FULL／PARTIAL／双失败／离线；按需安装、doctor、tools status；四平台固定配置与 checksum；超时、输出限制、网络来源和 proxy 脱敏；normalize、别名去重；progress／JSON／MCP 元数据与流隔离；原 Maven 诊断、Rule Coverage、Java 规则、Alpha、wheel、合规及独立包。真实 Jeepay 在线验收单列于 P，仍待授权。

## S. CI／standalone／compliance

已有规则及解耦提交的 Runtime tests、Compliance、Package integrity、四平台 Standalone artifacts 全部成功。OSV 阶段四平台工作流新增 `verify_artifact.py --full --osv-fallback`：健康 primary 未下载 OSV，显式准备后使用真实冻结程序运行 synthetic offline CLI／MCP fallback。本地 Windows 完整归档验收（含干净引擎准备、真实 primary 样例、原生 OSV 离线回退、外部插件、MCP）已通过，规则范围与零规则不启动引擎也通过；wheel／sdist 构建、wheel 完整性、干净环境安装、licenses --check-distribution、notices --check 均通过。OSV 最终提交的 CI 结果随后补充，未在推送前宣称跨平台已通过。

## T. 尚未解决

真实 Jeepay OSV 在线回退仍待明确外传授权；不会绕过自动审批拒绝。POM 完整传递／测试依赖图未被证明，原生成功仍可能 PARTIAL；不强行等价。缓存数据新鲜度和未支持 manifest 格式会影响覆盖，未引入包管理器执行。CVSS 向量保留但未新增评分计算器。未知 native 解析诊断保守降低 FULL，不自动修改镜像／settings。Syft／Grype／KICS 等不在本轮范围。
