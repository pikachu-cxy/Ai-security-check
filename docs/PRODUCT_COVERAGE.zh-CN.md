# 0.3.9 产品语言与检测覆盖

更新日期：2026-10-22。适用于 0.3.9 正式版及规则包 `ai-security-core 1.3.2`。本页描述已交付默认能力；不把扫描引擎自身支持的全部语言、宿主 AI 能阅读的语言或历史合成测试当作产品检测覆盖。

## 代码规则覆盖

| 语言 / 文件 | 默认启用 / 已安装规则 | 已覆盖的规则方向与框架示例 |
| --- | --- | --- |
| Java `.java` | 26 / 34 | SQL 注入、命令注入、SSRF、路径及文件读写、XXE、反序列化、TLS、Servlet XSS、Spring CSRF；包含部分 JDK、Spring、MyBatis、JPA / Hibernate、Apache HttpClient / Commons Exec API |
| Python `.py` | 16 / 16 | 命令执行、eval、SQL 注入、SSRF、路径处理、pickle / YAML 反序列化、TLS 校验关闭、Flask debug、Django CSRF / 弱密码哈希、HTML / 模板注入、JWT 签名关闭、lxml XXE |
| JavaScript `.js` / `.jsx` | 6 / 6，与 TypeScript 共用 | 部分 Express / Node.js 输入到 SQL、Shell、外部 HTTP、路径及文件读写的规则 |
| TypeScript `.ts` / `.tsx` | 与 JavaScript 共用上述 6 条 | 使用相同执行规则，按语言分别报告覆盖；不重复计算为另外 6 条独立规则 |
| MyBatis Mapper `.xml` | 已计入 Java 规则 | 仅适用的 MyBatis SQL 映射规则，不代表通用 XML 或全部模板语言检查 |
| Vue `.vue` | 无对应默认 SAST 规则 | 混合 JS / Vue 项目不能因 `.js` 已扫描而将 `.vue` 也标为已覆盖 |
| Go、PHP、C / C++、C#、Ruby、Rust 等 | 无自带对应 SAST 规则 | 可由宿主 Agent 做有界代码分析，但不能声称已执行这些语言的产品代码规则 |

合计 **56 条独立已安装规则，48 条默认启用**。Java 的 8 条历史实验规则默认关闭，不计入默认覆盖。规则条数不是漏洞类型数、准确率或完整 OWASP Top 10 覆盖证明。上述框架仅覆盖已建模 API 与输入形态，不等于支持所有框架版本、任意包装函数或跨文件调用链。

## 密钥、依赖与代码分析分别看

**密钥检查**：Gitleaks 按其检测模式检查实际纳入的文本文件，不依赖上述 Java / Python / JS 语言规则；发现密钥模式不等于该文件拥有 SAST 覆盖，也不保证识别全部自定义凭据。

**依赖漏洞检查**：当前产品接纳下列依赖输入，由 Trivy 及适用时的 OSV 回退路径处理，实际覆盖取决于识别到的包名、版本、生态和有效漏洞数据：

| 生态 | 当前识别的清单 / 锁文件 |
| --- | --- |
| Python | `requirements.txt`、`pyproject.toml`、`poetry.lock`、`Pipfile.lock` |
| JavaScript / TypeScript | `package.json`、`package-lock.json`、`yarn.lock`、`pnpm-lock.yaml` |
| Java / Gradle JVM 项目 | `pom.xml`、`build.gradle`、`build.gradle.kts`、`gradle.lockfile`、`buildscript-gradle.lockfile` |
| Go | `go.mod`、`go.sum` |

识别文件名不保证提取出完整依赖图。动态、未固定或无法解析的版本保留缺口；声明版本不等于实际安装版本，锁文件也不能单凭存在就证明完整传递依赖覆盖。当前未把 `composer.lock`、`Cargo.lock`、`Gemfile.lock`、`.csproj` 等纳入产品这套依赖输入清单，不因底层工具可能识别它们就宣传已接入。

**宿主 Agent 关联分析**：在任务范围与交付预算内读取代码、调用关系和防护，可能涉及其他语言；这是 AI 分析证据，不是为未覆盖语言增加扫描规则，也不建立生产可利用性或无漏洞证明。

## 如何读一次实际结果

区分“检测到语言”“可用规则”“选中规则”“实际执行规则”和“实际扫描文件”。组件 `READY`、文件能读取、静态零发现或 AI 给出建议，都不能替代本次实际覆盖记录。被排除、过大、二进制、解析失败、未支持类型或组件失败应保留为未覆盖 / 部分覆盖。

依据：[`catalog.json`](../src/security_runtime/rules/catalog.json)、[`capabilities.json`](../src/security_runtime/rules/capabilities.json)、[规则范围规划](../src/security_runtime/rule_coverage.py)、[依赖输入清单](../src/security_runtime/dependency_inputs.py)。[历史规则质量矩阵](design/RULE_COVERAGE_MATRIX.md)保存历史样本与准确率限制，不作为当前语言和条数目录。用户版说明见[文档站支持范围](../website/reference/support.md#语言覆盖)。
