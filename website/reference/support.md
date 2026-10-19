# 支持状态与验证边界

**版本范围：0.3.6 Developer Alpha 发行包及对应源码。** 版本、构建身份、CI 验证和桌面手工验收分别认定，不把历史版本的结果直接套用到新包。

## 系统与宿主

| 组合 | 当前说明 |
| --- | --- |
| Windows x64 + Codex | Windows 原生完整包 CI 验收通过；Codex 为主要使用路径，CI 合成宿主不等于桌面实操 |
| Windows x64 + Cursor | 有连接器与接入指南；本次版本仍需独立 Cursor 桌面验收 |
| macOS Apple Silicon | `macos-arm64` 原生完整包 CI 验收通过；桌面真机验收仍待独立完成 |
| macOS Intel | `macos-x64` 原生完整包 CI 验收通过；不是用 ARM 结果代替 Intel，桌面真机验收仍待完成 |
| Linux | 当前不作为公开发行的受支持目标 |

macOS 两种架构使用对应的原生完整包，不以 Rosetta 作为默认兼容策略。Windows 机器可以提交代码并触发 macOS runner 构建，但不能在本机直接运行 macOS 原生可执行文件来证明兼容。

原始版本标签与 Windows 包对应源码 `b4fa0ab086866f5db5c59b8f5f74ec180ed43f23`，[原始发布验收](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/39231001213)通过后公开 v0.3.6。Mac 兼容修订保留 Windows 原安装行为和公开资产，另对 Intel 与 Apple Silicon 构建验收；完成状态和实际源码以[下载页](../downloads.md)、发行清单的 `artifact_source_commits` 及 `macos-refresh.json` 为准。原生 CI 通过不等于苹果签名、公证、真实桌面操作或全部项目兼容性通过。

## 检查范围

- 代码检查：Java、Python、JavaScript / TypeScript 的已安装规则子集。
- 密钥检查：已安装检查组件支持的模式与当前实际纳入的文件。
- 依赖检查：可识别清单、生态与版本，结果依赖检查组件和漏洞数据的可用性。
- 关联分析：在有界上下文内，由宿主 Agent 阅读代码并复核防护与触发条件。

不能因为依赖工具能够识别某种生态，就宣称该语言具备完整 SAST 规则。Go、PHP 等未提供对应规则覆盖的路径，不作为完整代码检查支持宣传。

大文件、二进制、不支持类型、不可读路径与失败组件按实际诊断保留覆盖边界。零发现不是安全证明。

完整工程信息见 [规则覆盖矩阵](https://github.com/pikachu-cxy/Ai-security-check/blob/feature/runtime-mvp/docs/design/RULE_COVERAGE_MATRIX.md)、[宿主支持状态](https://github.com/pikachu-cxy/Ai-security-check/blob/feature/runtime-mvp/docs/HOST_SUPPORT.md)。
