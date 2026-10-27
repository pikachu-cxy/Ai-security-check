# 当前源码的检测覆盖

更新日期：2026-10-27。当前源码默认使用 OpenGrep 1.32.0；已发布安装包以包内版本为准。

默认开发检查只记录涉及路径，开发收尾时合并检查，不建立全项目基线。扫描器与 AI 发现统一持久化，同一问题保留来源，以 AI 复核意见形成判断，修复复查沿原风险记录进行。

## 代码规则覆盖

`rules/` 已替换为 `opengrep/opengrep-rules` 的固定快照 `f1d2b562b414783763fd02a6ed2736eaed622efa`，包含 1,934 个执行 YAML 文件、2,007 条规则。上游规则原文及许可证保留，执行时按路径限定规则 ID，避免不同目录的同名规则冲突。用户自定义规则目录仍支持，保留自定义 ID。

按实际文件语言选择规则；多语言规则只计一次。支持的文件映射和实际执行记录决定本次覆盖，不用规则数量推断准确率或完整覆盖。独立的原生辅助分析器保留，不属于已替换的旧 YAML 规则包。历史 Semgrep 结果继续可读，默认不安装、不调用 Semgrep。

上游规则许可为 LGPL-2.1 与 Commons Clause，随包保留 LICENSE。规则来源和逐文件校验见 [导入记录](../src/security_runtime/opengrep_rules.json)。

## 密钥、依赖与代码分析分别看

**密钥检查**：Gitleaks 按其检测模式检查实际纳入的文本文件，不依赖上述 Java / Python / JS 语言规则；发现密钥模式不等于该文件拥有 SAST 覆盖，也不保证识别全部自定义凭据。

**依赖漏洞检查**：当前产品接纳下列依赖输入，由 Trivy 扫描，默认关闭 OSV 自动备用扫描。同目录的 `package.json` 和 `package-lock.json` 作为一个 npm 依赖单元，以锁文件的扫描结果判断完成状态。离线模式和已关闭的数据库内容指纹不会单独导致“部分完成”；真实扫描错误、未识别的输入及漏洞数据不可用或过期仍会提示。

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

依据：[上游快照](../src/security_runtime/opengrep_rules.json)、[规则范围规划](../src/security_runtime/rule_coverage.py)、[依赖输入清单](../src/security_runtime/dependency_inputs.py)。[历史规则质量矩阵](design/RULE_COVERAGE_MATRIX.md)保存历史样本与准确率限制，不作为当前语言和条数目录。用户版说明见[文档站支持范围](../website/reference/support.md#语言覆盖)。

本地规则配置、此次新增 API 模型与验证方法见[内置规则与本地规则](guides/LOCAL_RULES_AND_COVERAGE.zh-CN.md)。

Vue 的本次支持用于发现脚本候选；内置和本地 SAST 规则的零发现暂不作为自动确认修复的依据，复查保留不确定状态。完整模板/脚本组合语义尚未建立。
