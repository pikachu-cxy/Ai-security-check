# 支持状态与验证边界

**版本范围：0.3.6 开发源码。** 版本、构建身份、CI 验证和桌面手工验收分别认定，不把历史版本的结果直接套用到新包。

## 系统与宿主

| 组合 | 当前说明 |
| --- | --- |
| Windows x64 + Codex | 当前主要使用与手工验收路径；本次候选包另行进行包级验证 |
| Windows x64 + Cursor | 有连接器与接入指南；本次版本仍需独立 Cursor 桌面验收 |
| macOS Apple Silicon | 原生 CI 构建目标为 `macos-arm64`；当前构建、验证、真机验收分别记录 |
| macOS Intel | 原生 CI 构建目标为 `macos-x64`；不能用 ARM 构建成功代替 Intel 验收 |
| Linux | 当前不作为公开发行的受支持目标 |

macOS 两种架构使用对应的原生完整包，不以 Rosetta 作为默认兼容策略。Windows 机器可以提交代码并触发 macOS runner 构建，但不能在本机直接运行 macOS 原生可执行文件来证明兼容。

本次文档搭建时，默认分支提交 `c526cdd` 的三个 CI 目标均完成了打包，但在旧版 Skill 校验处失败，产物未上传。因此不能宣称三个平台发布已通过；校验修正后的 CI 结果及后续真机验收仍需单独确认。

## 检查范围

- 代码检查：Java、Python、JavaScript / TypeScript 的已安装规则子集。
- 密钥检查：已安装检查组件支持的模式与当前实际纳入的文件。
- 依赖检查：可识别清单、生态与版本，结果依赖检查组件和漏洞数据的可用性。
- 关联分析：在有界上下文内，由宿主 Agent 阅读代码并复核防护与触发条件。

不能因为依赖工具能够识别某种生态，就宣称该语言具备完整 SAST 规则。Go、PHP 等未提供对应规则覆盖的路径，不作为完整代码检查支持宣传。

大文件、二进制、不支持类型、不可读路径与失败组件按实际诊断保留覆盖边界。零发现不是安全证明。

完整工程信息见 [规则覆盖矩阵](https://github.com/pikachu-cxy/Ai-security-check/blob/feature/runtime-mvp/docs/design/RULE_COVERAGE_MATRIX.md)、[宿主支持状态](https://github.com/pikachu-cxy/Ai-security-check/blob/feature/runtime-mvp/docs/HOST_SUPPORT.md)。
