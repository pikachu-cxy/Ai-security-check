# 支持状态与验证边界

**版本范围：0.3.9 正式版 发行包及对应源码。** 发行与校验入口见[下载页](../downloads.md)。版本、构建身份、CI 验证和桌面手工验收分别认定；下表中的原生发行验收以本次工作流记录为准，不沿用历史版本结论。

## 系统与宿主

| 组合 | 当前说明 |
| --- | --- |
| Windows x64 + Codex | 独立 Windows 原生完整包及 CI 验收；Codex 为主要使用路径，CI 合成宿主不等于桌面实操 |
| Windows x64 + Cursor | 提供 `install cursor` 完整接入，包含用户级 MCP、Skill、Hook 和常规工具白名单；桌面验证范围见下文 |
| macOS Apple Silicon | 独立 `macos-arm64` 原生构建与验收；桌面真机验收仍待独立完成 |
| macOS Intel | 独立 `macos-x64` 原生构建与验收；不以 ARM 结果代替 Intel，桌面真机验收仍待完成 |

macOS 自动安装会识别两种架构；手动完整包则需选择对应芯片，不以 Rosetta 作为默认兼容策略。Windows 机器可以提交代码并触发 macOS runner 构建，但不能在本机直接运行 macOS 原生可执行文件来证明兼容。

当前不发布 Linux 完整包。WorkBuddy 提供项目级 MCP，其他客户端按通用 stdio MCP 条件接入，不因此具备原生编辑事件或完整桌面验收。各入口见[选择编辑器](../guide/quickstart.md#choose-editor)。

0.3.9 三平台包来自同一版本和同一发布提交，当前更新记录与 CI 证据见[下载页](../downloads.md)，源码身份及校验值以 Release 的 `release-manifest.json` 和 `SHA256SUMS.txt` 为准。源码证据脱敏规则共用一套实现，平台差异在构建、系统接入和扫描组件运行环境。原生 CI 通过不等于苹果签名、公证、真实桌面操作或全部项目兼容性通过。

0.3.9 发行包中的指导去重、文件范围扫描与结果核验复用使用共用核心逻辑；MCP 阶段通知由支持进度令牌的宿主显示，缺少该能力仍返回相同的最终结果。本次 Windows/macOS 原生构建结果分别记录，Codex/Cursor 桌面验收仍单独记录。

## macOS 安装与验证 {#macos-installation}

[Codex](../guide/editors/codex.md#macos)和 [Cursor](../guide/editors/cursor.md#macos) 的 Mac 安装直接写在各自页面。自动安装使用独立发行 `macos-trial-v0.3.9.3`，准备固定版本 Python 与产品包，与 0.3.9 原生完整包分别记录。

Apple Silicon 和 Intel 由[本次 Mac CI](https://github.com/pikachu-cxy/Ai-security-check/actions/workflows/macos-trial.yml)分别验证首次安装、构建核对、Cursor / Codex 配置及重复安装。这是隔离用户目录中的安装验收，检查组件采用明确离线状态，不宣称已运行全部扫描器。

真实用户电脑的系统策略、终端粘贴提醒、编辑器桌面连接及组件实际检查仍需分别确认；当前没有 Apple Developer ID 签名或公证保证。已有所选编辑器的连接可能切换到此次版本，影响与切回方法均在对应编辑器页说明。

## Cursor 接入与桌面验证

Cursor 的完整接入入口为 `install cursor`，Windows 使用完整包，macOS 可选择独立环境试用入口或芯片对应的原生完整包。安装器配置用户级 MCP、配套 Skill、编辑事件 Hook 和常规工具白名单，并启动检查组件准备。安装后需重启 Cursor，在实际项目中完成连接核对和一次小任务检查。

**验证范围**：已有 Windows 本地单根工作区的有限桌面记录，以及安装、MCP 和 Hook 的自动化检查。当前 0.3.9 的完整桌面流程、不同模型和免确认体验仍需独立验收；macOS 桌面也不能以原生 CI 结果代替实机记录。远程与多根工作区未列为已支持范围。

“完整接入”描述安装内容，不代表所有系统、Cursor 版本和模型的桌面流程均已通过验收。操作步骤见 [Cursor 安装与使用](../guide/editors/cursor.md)，工程记录见 [Cursor 接入与验收](https://github.com/pikachu-cxy/Ai-security-check/blob/feature/runtime-mvp/docs/guides/CURSOR_INSTALL_AND_TEST.zh-CN.md)。

## 监控与证据交付

0.3.9 的一键聊天用量关联目前适配 Codex 本机日志；Cursor 等宿主没有真实 usage 适配时，token 保持未知。监控停止、失败或从源码交付移除，不阻断核心功能。聊天总量不能当作纯扫描 token。

新任务完整保存脱敏长行，超过响应大小时分片；文件、任务与传输总预算继续有效。旧前像已截断、正文不可读或脱敏语义无法确认时保留明确缺口。

## 检查范围

### 语言覆盖 {#语言覆盖}

0.3.9 自带规则包 `ai-security-core 1.3.2`，共 **56 条独立规则，48 条默认启用**。以下是已交付规则范围，不代表某种语言或框架的全部安全问题均能检测：

| 语言 / 文件 | 默认启用 / 已安装 | 规则方向与适用示例 |
| --- | --- | --- |
| Java `.java` | 26 / 34 | SQL、命令注入、SSRF、路径 / 文件读写、XXE、反序列化、TLS、Servlet XSS、Spring CSRF；部分 JDK、Spring、MyBatis、JPA / Hibernate、Apache API |
| Python `.py` | 16 / 16 | 命令执行、eval、SQL、SSRF、路径、pickle / YAML、TLS、Flask debug、Django CSRF / 弱密码哈希、HTML / 模板、JWT、lxml XXE |
| JavaScript `.js` / `.jsx` | 6 / 6 | 部分 Express / Node.js 输入到 SQL、Shell、外部 HTTP、路径和文件读写的规则 |
| TypeScript `.ts` / `.tsx` | 与 JS 共用上述 6 条 | 分语言记录实际执行，不另计 6 条独立规则 |
| MyBatis Mapper `.xml` | 计入 Java | 仅适用的 MyBatis SQL 映射规则，不是通用 XML 覆盖 |
| Vue `.vue` | 无对应默认 SAST 规则 | `.js` 已扫描不能代表 `.vue` 已覆盖 |
| Go、PHP、C / C++、C#、Ruby、Rust 等 | 无自带对应 SAST 规则 | 宿主 AI 可分析代码，但不能据此声称已执行产品语言规则 |

Java 的 8 条历史实验规则默认关闭。JS / TS 共用规则只计一次；条数不表示准确率或完整 OWASP Top 10 覆盖。框架名称仅说明部分已建模 API，不覆盖任意包装函数、所有版本或完整跨文件调用链。

### 密钥、依赖与 AI 分析

- **密钥检查**：Gitleaks 按检测模式检查纳入范围的文本文件，不依赖代码语言规则；不保证识别全部自定义凭据。
- **依赖检查**：Python 的 `requirements.txt` / `pyproject.toml` / `poetry.lock` / `Pipfile.lock`；JS / TS 的 `package.json` / npm、Yarn、pnpm 锁文件；Java / Gradle 的 `pom.xml`、Gradle 构建与锁文件；Go 的 `go.mod` / `go.sum`。实际结果依赖引擎、包版本提取和有效漏洞数据。
- **其他依赖生态**：当前产品依赖输入清单未包含 Composer、Cargo、Bundler、.NET 清单，不把底层工具自身支持当作本产品已接入。
- **关联分析**：宿主 Agent 在有界上下文内复核代码、防护与触发条件；能阅读其他语言不等于这些语言已有 SAST 规则。

Go 的依赖清单识别不等于 Go 代码检查；识别清单也不保证完整传递依赖或实际安装版本已确认。动态、未固定或解析失败的版本应保留缺口。

### 一次检查实际覆盖多少

结果应区分检测到的语言、可用 / 选中 / 实际执行规则及实际扫描文件。只发现扩展名、组件就绪、零发现或 AI 建议都不能代替执行证据。混合语言项目中，不支持的文件仍需明确列出。

0.3.9 会核对 Semgrep 实际执行身份，并分别报告工具缺失、OSV 数据库缺失、漏洞数据过期或更新时间未知。组件就绪和数据有效不代表所有项目文件已被检查；诊断与处理见[组件准备](../guide/installation.md#手动准备组件)。

大文件、二进制、不支持类型、不可读路径与失败组件按实际诊断保留覆盖边界。零发现不是安全证明。

完整依据见[当前产品覆盖说明](https://github.com/pikachu-cxy/Ai-security-check/blob/feature/runtime-mvp/docs/PRODUCT_COVERAGE.zh-CN.md)、[规则目录](https://github.com/pikachu-cxy/Ai-security-check/blob/feature/runtime-mvp/src/security_runtime/rules/catalog.json)及[宿主支持状态](https://github.com/pikachu-cxy/Ai-security-check/blob/feature/runtime-mvp/docs/HOST_SUPPORT.md)。[历史规则质量矩阵](https://github.com/pikachu-cxy/Ai-security-check/blob/feature/runtime-mvp/docs/design/RULE_COVERAGE_MATRIX.md)仅用于了解历史样本与准确率限制。
