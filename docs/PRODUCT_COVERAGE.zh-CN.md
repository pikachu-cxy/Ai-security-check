# 0.3.9 产品语言与检测覆盖

更新日期：2026-10-26。适用于当前源码及规则包 `ai-security-core 1.6.0`；已发布的 0.3.9 安装包仍以包内版本为准。本页描述当前源码默认能力；不把扫描引擎自身支持的全部语言、宿主 AI 能阅读的语言或历史合成测试当作产品检测覆盖。

默认运行模式为 AI 开发任务审计：启动不要求产品比较基线 A、不主动盘点或扫描项目；任务首次编辑前建立 B，结束封存 C，检查完整实际净变化及必要关联影响。不同编辑来源、任务时间窗重叠和作者未知不会单独降低新结果覆盖；会话权限和工作区隔离不变。组件及漏洞数据准备状态、真实源码缺口、失败和版本不一致分别如实报告。历史 A 与旧任务结果保留兼容读取，不将旧 PARTIAL 批量升级为 FULL。

## 代码规则覆盖

| 语言 / 文件 | 默认启用 / 已安装规则 | 已覆盖的规则方向与框架示例 |
| --- | --- | --- |
| Java `.java` | 26 / 34 | SQL 注入、命令注入、SSRF、路径及文件读写、XXE、反序列化、TLS、Servlet XSS、Spring CSRF；包含部分 JDK、Spring、MyBatis、JPA / Hibernate、Apache HttpClient / Commons Exec API |
| Python `.py` | 18 / 18 | 命令执行、eval / exec、SQL 注入、SSRF、路径处理、pickle / YAML 反序列化、TLS 校验关闭、Flask debug、Django CSRF / 弱密码哈希、HTML / 模板注入、Flask 直接返回格式化字符串、JWT 签名关闭、lxml XXE |
| JavaScript `.js` / `.jsx` | 9 / 9，与 TypeScript 共用 | 部分 Express / Node.js 输入到 SQL、Shell、外部 HTTP、路径及文件读写；补充 location 到 DOM HTML、HTTPS 校验关闭；请求输入到 eval / Function / vm 代码参数 |
| TypeScript `.ts` / `.tsx` | 与 JavaScript 共用上述 9 条 | 使用相同执行规则，按语言分别报告覆盖；不重复计算为另外 9 条独立规则 |
| MyBatis Mapper `.xml` | 已计入 Java 规则 | 仅适用的 MyBatis SQL 映射规则，不代表通用 XML 或全部模板语言检查 |
| Vue `.vue` | 脚本复用 JS/TS 规则，不增加独立条数 | 提取顶层 script / script setup 的 JS/TS，映射原文件位置；模板、样式、外链脚本未覆盖，整体最多部分覆盖 |
| Go `.go` | 4 / 4 | 部分 net/http 输入到 Shell、文件读取、HTTP 请求，以及 crypto/tls 校验关闭 |
| PHP `.php` | 6 / 6 | 超全局输入到命令、mysqli SQL、eval、unserialize、include/require、HTML 输出 |
| C / C++、C#、Ruby、Rust 等 | 无自带对应 SAST 规则 | 可由宿主 Agent 做有界代码分析，但不能声称已执行这些语言的产品代码规则 |

合计 **71 条独立已安装规则，63 条默认启用**。Java 的 8 条历史实验规则默认关闭，不计入默认覆盖。规则条数不是漏洞类型数、准确率或完整 OWASP Top 10 覆盖证明。上述框架仅覆盖已建模 API 与输入形态，不等于支持所有框架版本、任意包装函数或跨文件调用链。

上表只统计 `ai-security-core` YAML 规则。feature/release 另启用 `ai-security-go-sql 1.0.0` 的 1 条原生 Go SQL 规则：同包直接调用及已确定类型的方法，最多两条调用边，识别 `net/http` 输入进入 `database/sql` 查询文本。只分析已捕获的目标及上下文，限 64 文件、2 MB、100000 步和 3 秒软预算；quick 不启用。未解析调用、语法或超预算均保留缺口，不代表全程序覆盖。

`1.4.1` 调整 PHP 四段数值重建的命令注入防护识别，并对内置 Python 命令/eval 告警增加本地常量证明过滤。不能证明安全时保留原告警。验证结果见 [本轮基准报告](design/BOUNDED_GO_SQL_BENCHMARK_2026-10-22.zh-CN.md)。

`1.4.2` 补充 Python `exec` 和 SQL 字典传播，并识别函数内新建 ConfigParser 的固定选项，以及同时验证首尾引号、排除内部同类引号、失败立即退出的精确字符串字面量防护。模型以标准 Python 字符串和 ConfigParser 语义为前提，不解析外部包装函数、运行时替换或自定义字符串子类。固定基准的原真阳性保留，详见 [Python 第二轮基准](design/PYTHON_RULE_QUALITY_2026-10-22.zh-CN.md)。

`1.4.3` 在 SQL 规则中识别局部 ConfigParser 相邻 `set/get` 的同一 section、同一键传播；不把整个配置对象的所有键视为污点。固定 Python 子集由 19 TP / 3 FP / 26 FN 改善为 20 TP / 3 FP / 25 FN，原有真阳性逐项保留。跨文件范围、扫描预算和规则数量不变，详见 [Python 第三轮基准](design/PYTHON_RULE_QUALITY_ROUND3_2026-10-22.zh-CN.md)。


`1.5.0` 增加 Python 显式 shell 命令槽与 JS/TS 代码执行污点规则；显式 Express Request 处理器补充 SQL、命令和删除路径来源。JS/TS 局部赋值、拼接、覆盖及参数绑定使用 Semgrep 污点语义，不新增跨文件调用图。引擎提供路径时只保留有界脱敏位置；未提供则标明路径不可用，不编造传播链。未知函数返回值不由新代码执行规则自动传播。

`1.6.0` 增加 Flask 路由直接返回格式化字符串的局部 XSS 规则，识别部分字符串切分和可逆编码；字典 / JSON、显式纯文本响应、已知 HTML 转义与模板返回不属于该直接字符串模型。未知帮助函数不会自动传播，间接响应构造仍有缺口。原有显式 shell 规则补充一类相邻列表 append/pop/index 传播。内置产品对完整路径或完整 HTML 操作数做本地常量证明；只证明文件名固定、而导入路径前缀未知时，不抑制原告警。原始 YAML 候选与过滤后的产品结果分别验收。

Vue 投影限制为每文件 512 KiB、每次 64 文件及 4 MiB 输入；两个 script 独立分析，不连通数据流。无法提取、超预算或引擎失败均保留缺口；模板始终未覆盖。用户规则包含路径 include/exclude 时暂不投影 Vue，并说明原因，以免影子文件改变路径限制；普通 JS/TS 和无路径限制的本地 Vue 规则仍可使用。

上述 YAML 数量不含已有 Java/Python 原生有界分析：默认各启用 SQL、路径两类规则；也不含 JS/TS 动态代码词法候选。原生候选、污点证据和真实可利用性分别认定。

原生 `ai-security-bounded-dataflow 1.5.0` 维持原有默认范围：Python 路径检测要求已解析的跨文件调用，或精确的 `io.open/codecs.open`。文件内 `pathlib.Path.read_text/read_bytes` 仍为实验性能力；部件替换和绝对后段覆盖前段的语义尚不足以支持默认推广，需先补精确模型和安全负例。原有跨文件深度、文件 / 字节 / 步数上限与 feature 3 秒 / release 30 秒软预算不变，Python 命令数据流仍默认关闭。

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

本地规则配置、此次新增 API 模型与验证方法见[内置规则与本地规则](guides/LOCAL_RULES_AND_COVERAGE.zh-CN.md)。

Vue 的本次支持用于发现脚本候选；内置和本地 SAST 规则的零发现暂不作为自动确认修复的依据，复查保留不确定状态。完整模板/脚本组合语义尚未建立。

本轮实现、固定基准结果与耗时见 [JS/TS、Python 与 Vue 质量验证](design/WEB_PYTHON_VUE_RULE_QUALITY_2026-10-22.zh-CN.md)。
