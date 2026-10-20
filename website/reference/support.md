# 支持状态与验证边界

**版本范围：0.3.8 Developer Alpha 发行包及对应源码。** 发行与校验入口见[下载页](../downloads.md)。版本、构建身份、CI 验证和桌面手工验收分别认定；下表中的原生发行验收描述对应本次已发布的 0.3.8，不沿用历史版本结论。

## 系统与宿主

| 组合 | 当前说明 |
| --- | --- |
| Windows x64 + Codex | 独立 Windows 原生完整包及 CI 验收；Codex 为主要使用路径，CI 合成宿主不等于桌面实操 |
| Windows x64 + Cursor | 提供 `install cursor` 完整接入，包含用户级 MCP、Skill、Hook 和常规工具白名单；桌面验证范围见下文 |
| macOS Apple Silicon | 独立 `macos-arm64` 原生构建与验收；桌面真机验收仍待独立完成 |
| macOS Intel | 独立 `macos-x64` 原生构建与验收；不以 ARM 结果代替 Intel，桌面真机验收仍待完成 |
| Linux | 当前不作为公开发行的受支持目标 |

macOS 两种架构使用对应的原生完整包，不以 Rosetta 作为默认兼容策略。Windows 机器可以提交代码并触发 macOS runner 构建，但不能在本机直接运行 macOS 原生可执行文件来证明兼容。

0.3.8 三平台包来自同一版本和同一发布提交，当前更新记录与 CI 证据见[下载页](../downloads.md)，源码身份及校验值以 Release 的 `release-manifest.json` 和 `SHA256SUMS.txt` 为准。源码证据脱敏规则共用一套实现，平台差异在构建、系统接入和扫描组件运行环境。原生 CI 通过不等于苹果签名、公证、真实桌面操作或全部项目兼容性通过。

0.3.8 发行包中的指导去重、文件范围扫描与结果核验复用使用共用核心逻辑；MCP 阶段通知由支持进度令牌的宿主显示，缺少该能力仍返回相同的最终结果。本次 Windows/macOS 原生构建已有各自的 CI 记录，Codex/Cursor 桌面验收仍单独记录。

## Mac 独立环境安装试用

[Mac 试用入口](../guide/macos-trial.md)面向本地 Cursor / Codex，使用独立预发行 `macos-trial-v0.3.8.1`，自动准备固定版本 Python 与产品包。它与上表 0.3.8 原生完整包分开记录；原完整包的验收结果不能代替这条新安装路径的验收。

当前真实 M 系列 Mac 的浏览器下载、首次安装、桌面连接与检查体验仍待用户试用确认。该路径没有 Apple Developer ID 签名或公证保证。已有所选编辑器的全局连接可能更新为试用版本，具体影响、状态验证和切回步骤见试用页。

## Cursor 接入与桌面验证

Cursor 的完整接入入口为 `install cursor`，Windows 使用完整包，macOS 可选择独立环境试用入口或芯片对应的原生完整包。安装器配置用户级 MCP、配套 Skill、编辑事件 Hook 和常规工具白名单，并启动检查组件准备。安装后需重启 Cursor，在实际项目中完成连接核对和一次小任务检查。

**验证范围**：已有 Windows 本地单根工作区的有限桌面记录，以及安装、MCP 和 Hook 的自动化检查。当前 0.3.8 的完整桌面流程、不同模型和免确认体验仍需独立验收；macOS 桌面也不能以原生 CI 结果代替实机记录。远程与多根工作区未列为已支持范围。

“完整接入”描述安装内容，不代表所有系统、Cursor 版本和模型的桌面流程均已通过验收。操作步骤见 [Cursor 安装与使用](../guide/editors/cursor.md)，工程记录见 [Cursor 接入与验收](https://github.com/pikachu-cxy/Ai-security-check/blob/feature/runtime-mvp/docs/guides/CURSOR_INSTALL_AND_TEST.zh-CN.md)。

## 检查范围

- 代码检查：Java、Python、JavaScript / TypeScript 的已安装规则子集。
- 密钥检查：已安装检查组件支持的模式与当前实际纳入的文件。
- 依赖检查：可识别清单、生态与版本，结果依赖检查组件和漏洞数据的可用性。
- 关联分析：在有界上下文内，由宿主 Agent 阅读代码并复核防护与触发条件。

不能因为依赖工具能够识别某种生态，就宣称该语言具备完整 SAST 规则。Go、PHP 等未提供对应规则覆盖的路径，不作为完整代码检查支持宣传。

大文件、二进制、不支持类型、不可读路径与失败组件按实际诊断保留覆盖边界。零发现不是安全证明。

完整工程信息见 [规则覆盖矩阵](https://github.com/pikachu-cxy/Ai-security-check/blob/feature/runtime-mvp/docs/design/RULE_COVERAGE_MATRIX.md)、[宿主支持状态](https://github.com/pikachu-cxy/Ai-security-check/blob/feature/runtime-mvp/docs/HOST_SUPPORT.md)。
