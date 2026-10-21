# 下载与安装

选择编辑器后，按同一页面中的 Windows 或 macOS 步骤安装，再重启并验证连接。

| 你使用的系统 | 安装入口 | 是否需要额外环境 |
| --- | --- | --- |
| Windows x64 | [Codex](./guide/editors/codex.md#windows) / [Cursor](./guide/editors/cursor.md#windows)：下载下面的完整包 | 不要求另装 Python 或 Node.js |
| macOS · Apple Silicon 或 Intel | [Codex](./guide/editors/codex.md#macos) / [Cursor](./guide/editors/cursor.md#macos)：一条命令自动安装 | 自动准备专用 Python，无需 Git、Homebrew 或环境配置 |

WorkBuddy 和其他 MCP 客户端按[对应接入指南](./guide/quickstart.md#choose-editor)配置。项目检查与示例练习需要 Git；安装 Runtime 本身不要求 Git。

## Windows 完整包 {#windows}

当前为 **0.3.9 Developer Alpha**。下载包与配套 SHA256，核对后完整解压并保留整个 `security-check` 文件夹。

| 平台 | 安装包 | 校验 |
| --- | --- | --- |
| Windows x64 | [下载 ZIP](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.9/ai-security-runtime-v0.3.9-windows-x64.zip) | [SHA256](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.9/ai-security-runtime-v0.3.9-windows-x64.zip.sha256) |

在下载目录的 PowerShell 中对照摘要：

```powershell
Get-FileHash .\ai-security-runtime-v0.3.9-windows-x64.zip -Algorithm SHA256
Get-Content .\ai-security-runtime-v0.3.9-windows-x64.zip.sha256
```

然后按 [Codex 安装](./guide/editors/codex.md#windows)或 [Cursor 安装](./guide/editors/cursor.md#windows)执行一条安装命令。从 0.3.8 升级时重新下载完整包和配套校验文件，并核对实际 `build_id`。

## Mac 安装

Codex / Cursor 用户直接在对应编辑器页查看 Mac 命令，无需先下载下方的完整包，也无需预装 Python。安装器会自动识别芯片并准备专用环境。

当前自动安装使用独立发行 [macos-trial-v0.3.9.2](https://github.com/pikachu-cxy/Ai-security-check/releases/tag/macos-trial-v0.3.9.2)。它与完整包的程序路径、来源提交和构建身份分别记录，已有所选编辑器的连接可能更新。真实用户 Mac 的系统策略、桌面连接和组件检查仍需实际验证，详见[支持状态](./reference/support.md#macos-installation)。

粘贴时遇到系统提醒，先按[提醒原因与处理方式](./reference/faq.md#macos-paste)核对原文。

### 需要手动完整包？ {#macos-packages}

仅在选择手动完整包或其他 MCP 接入方式时下载。M 系列选择 Apple Silicon，Intel Mac 选择 Intel；核验并完整解压，保留执行权限和整个目录。

| 芯片 | 完整安装包 | 校验 |
| --- | --- | --- |
| Apple Silicon | [下载 tar.gz](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.9/ai-security-runtime-v0.3.9-macos-arm64.tar.gz) | [SHA256](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.9/ai-security-runtime-v0.3.9-macos-arm64.tar.gz.sha256) |
| Intel | [下载 tar.gz](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.9/ai-security-runtime-v0.3.9-macos-x64.tar.gz) | [SHA256](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.9/ai-security-runtime-v0.3.9-macos-x64.tar.gz.sha256) |

在包与 `.sha256` 文件所在目录执行，Intel 将文件名中的 `macos-arm64` 换成 `macos-x64`：

```sh
shasum -a 256 -c ai-security-runtime-v0.3.9-macos-arm64.tar.gz.sha256
```

当前没有 Apple Developer ID 签名与公证保证。原完整包出现 Python 动态库或系统策略错误时，保留报错并查看[Mac 首次启动排查](./guide/installation.md#macos-首次启动)。

## 安装后还要做什么？

完全退出并重启编辑器，按[安装验证](./guide/verify.md)核对真实连接、构建、组件和项目路径，然后做[独立 Demo](./guide/demo.md)。摘要匹配只证明下载内容一致，不代表项目已通过安全检查。

## 构建与验收记录 {#build-details}

**0.3.9 完整包**：[Release](https://github.com/pikachu-cxy/Ai-security-check/releases/tag/v0.3.9) 使用同一源码提交 [`6ceaf31`](https://github.com/pikachu-cxy/Ai-security-check/commit/6ceaf31c1324fbc22fb13729a4558563699c455e) 生成三平台包。公开资产须通过 Windows/macOS 回归、合规、包完整性和三平台原生验收；状态见[本次发行流程](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/39584810380)。

[完整 SHA256 清单](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.9/SHA256SUMS.txt) · [发行清单](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.9/release-manifest.json) · [验收证据 ZIP](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.9/ai-security-runtime-v0.3.9-release-evidence.zip)

**Mac 自动安装**：独立发行 [macos-trial-v0.3.9.2](https://github.com/pikachu-cxy/Ai-security-check/releases/tag/macos-trial-v0.3.9.2)，Runtime 版本 0.3.9，来源提交同为 `6ceaf31`，产品构建 ID 为 `b079afc2d928f2ccdcdc117350b72ba75f58a373993ff31d34322835e1d981d5`。两种架构已分别通过首次安装、构建身份、Codex / Cursor 接入及重复安装的合成验收，见[Mac 安装流水线](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/39584786148)。该合成验收不替代实际桌面、系统首次下载或全部扫描组件验证。

本版增加[一键监控与导出报告](./guide/context-cost.md)，并修复完整脱敏长行的保存和分片交付。完整包与自动安装的来源提交、构建 ID 和校验值分别核对，不混用。

### 历史 0.3.8 记录


::: details 查看发行身份与工程证据
**0.3.8 完整包**：[Release](https://github.com/pikachu-cxy/Ai-security-check/releases/tag/v0.3.8) 于 2026-10-20 替换更新，Windows、Apple Silicon、Intel 包对应同一源码提交 [`8d5d9a6`](https://github.com/pikachu-cxy/Ai-security-check/commit/8d5d9a694529c7d29cb1fa79c6843ea0763576a9)。当前 Windows 构建 ID 为 `7abf1b6e2d587bd87d5d577122ef71c51288f6c46f75ffdddaf40f7cc24e309d`，其他平台以发行清单为准。

[完整 SHA256 清单](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.8/SHA256SUMS.txt) · [发行清单](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.8/release-manifest.json) · [验收证据 ZIP](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.8/ai-security-runtime-v0.3.8-release-evidence.zip) · [原生构建与验收](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/39398870803)

该次完整包更新复用 204 项相关定向测试，文档打包契约另有 13 项通过；Windows 包完整性检查和对应原生验收已有记录。检查范围包括启动、组件准备、样例扫描、MCP、受管 Skill 及隔离安装生命周期，合成场景不能替代真实桌面记录。

**Mac 自动安装**：Runtime 版本 0.3.8，发行 `macos-trial-v0.3.8.1`，来源提交 [`9b65b6e`](https://github.com/pikachu-cxy/Ai-security-check/commit/9b65b6e0d9dfb5cb3a5b362063d5e699192fc4b0)，产品构建 ID `a2a3f8a9d5dc95a631cab30630a2900673df91ac82e21c086ca33d01a66b8caa`。

[Mac 安装流水线](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/39407281204)中，两种芯片各有 61 项定向测试通过，并完成 Cursor / Codex 的首次安装、构建身份和重复安装验收。该验收使用离线组件状态与发布下载的本地传输夹具，不等于用户桌面连接、系统首次下载提示或全部扫描器已运行。

完整包与自动安装分别记录，不混用构建 ID 或 SHA256。产品更新内容见[版本与进展](./reference/changelog.md)，上下文优化见[上下文开销说明](./guide/context-cost.md)。
:::
