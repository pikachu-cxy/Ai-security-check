# 下载与安装

::: info 当前检测能力
默认使用 OpenGrep 按已安装规则包选择语言规则，配合原生有界分析、Gitleaks 密钥检查和 Trivy 依赖检查。覆盖以本次实际执行的文件与规则为准。 [查看检测范围 →](./reference/support.md#语言覆盖)
:::

选择编辑器后，按同一页面中的 Windows 或 macOS 步骤安装，再重启并验证连接。

| 你使用的系统 | 安装入口 | 是否需要额外环境 |
| --- | --- | --- |
| Windows x64 | [Codex](./guide/editors/codex.md#windows) / [Cursor](./guide/editors/cursor.md#windows)：一条 PowerShell 命令自动安装 | 不要求另装 Python 或 Node.js |
| macOS · Apple Silicon 或 Intel | [Codex](./guide/editors/codex.md#macos) / [Cursor](./guide/editors/cursor.md#macos)：下载下方对应芯片的正式版完整包；自动安装另列 | 完整包自带 Python，自动安装准备专用 Python |

WorkBuddy 和其他 MCP 客户端按[对应接入指南](./guide/quickstart.md#choose-editor)配置。项目检查与示例练习需要 Git；安装 Runtime 本身不要求 Git。

## Windows 安装 {#windows}

推荐使用 [Codex](./guide/editors/codex.md#windows) / [Cursor](./guide/editors/cursor.md#windows) 页面的一条 PowerShell 命令，自动完成下载、校验和解压。以下完整包用于手动安装或离线分发。

当前为 **0.3.11 正式版**。下载包与配套 SHA256，核对后完整解压并保留整个 `security-check` 文件夹。

| 平台 | 安装包 | 校验 |
| --- | --- | --- |
| Windows x64 | [下载 ZIP](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.11/ai-security-runtime-v0.3.11-windows-x64.zip) | [SHA256](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.11/ai-security-runtime-v0.3.11-windows-x64.zip.sha256) |

在下载目录的 PowerShell 中对照摘要：

```powershell
Get-FileHash .\ai-security-runtime-v0.3.11-windows-x64.zip -Algorithm SHA256
Get-Content .\ai-security-runtime-v0.3.11-windows-x64.zip.sha256
```

完整解压后，在能看到 `security-check` 文件夹的目录执行 `.\security-check\security-check.exe install codex`（Cursor 将 `codex` 改成 `cursor`）。旧版本升级或从源码开发版切换时，下载本页完整包和配套校验文件，重启编辑器后核对实际程序路径、来源提交与 `build_id`。

## Mac 安装

正式版完整包见[下方三平台发行的 Mac 下载](#macos-packages)。以下自动安装命令仍使用独立试用发行，与正式版完整包分别核对来源。

正式版完整包无需预装 Python，按下方命令安装。另有 Codex / Cursor 的自动安装入口，安装器会识别芯片并准备专用环境。

当前自动安装使用独立发行 [macos-trial-v0.3.11](https://github.com/pikachu-cxy/Ai-security-check/releases/tag/macos-trial-v0.3.11)。它与完整包的程序路径、来源提交和构建身份分别记录，已有所选编辑器的连接可能更新。真实用户 Mac 的系统策略、桌面连接和组件检查仍需实际验证，详见[支持状态](./reference/support.md#macos-installation)。

粘贴时遇到系统提醒，先按[提醒原因与处理方式](./reference/faq.md#macos-paste)核对原文。

### Mac 原生完整包 {#macos-packages}

需要原生完整包时，M 系列选择 Apple Silicon，Intel Mac 选择 Intel；核验并完整解压，保留执行权限和整个目录。原生完整包和独立环境自动安装都是可选入口，请选择一种并使用对应的程序路径。

| 芯片 | 完整安装包 | 校验 |
| --- | --- | --- |
| Apple Silicon | [下载 tar.gz](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.11/ai-security-runtime-v0.3.11-macos-arm64.tar.gz) | [SHA256](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.11/ai-security-runtime-v0.3.11-macos-arm64.tar.gz.sha256) |
| Intel | [下载 tar.gz](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.11/ai-security-runtime-v0.3.11-macos-x64.tar.gz) | [SHA256](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.11/ai-security-runtime-v0.3.11-macos-x64.tar.gz.sha256) |

在包与 `.sha256` 文件所在目录执行，Intel 将文件名中的 `macos-arm64` 换成 `macos-x64`：

```sh
shasum -a 256 -c ai-security-runtime-v0.3.11-macos-arm64.tar.gz.sha256
tar -xzf ai-security-runtime-v0.3.11-macos-arm64.tar.gz
./security-check/security-check install codex
# Cursor 用户将上一行的 codex 替换为 cursor
```

当前没有 Apple Developer ID 签名与公证保证。原完整包出现 Python 动态库或系统策略错误时，保留报错并查看[Mac 首次启动排查](./guide/installation.md#macos-首次启动)。

## 安装后还要做什么？

完全退出并重启编辑器，按[安装验证](./guide/verify.md)核对真实连接、构建、组件和项目路径，然后做[独立 Demo](./guide/demo.md)。摘要匹配只证明下载内容一致，不代表项目已通过安全检查。

## 构建与验收记录 {#build-details}

**0.3.11 正式版完整包**：2026-10-30 公开发布，[Release](https://github.com/pikachu-cxy/Ai-security-check/releases/tag/v0.3.11) 的三平台包均对应源码提交 [v0.3.11](https://github.com/pikachu-cxy/Ai-security-check/tree/v0.3.11)。[本次成功的发行流程](https://github.com/pikachu-cxy/Ai-security-check/actions/workflows/release.yml)完成当前改动相关的 Windows/macOS 定向回归、合规、包完整性与三平台原生验收，未重复执行全库回归。以配套发行清单、校验值和验收证据为准，不沿用更早候选构建的记录。

[完整 SHA256 清单](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.11/SHA256SUMS.txt) · [发行清单](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.11/release-manifest.json) · [验收证据 ZIP](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.11/ai-security-runtime-v0.3.11-release-evidence.zip)

**Mac 自动安装**：独立发行 [macos-trial-v0.3.11](https://github.com/pikachu-cxy/Ai-security-check/releases/tag/macos-trial-v0.3.11)，Runtime 版本 0.3.11。两种架构分别验证首次安装、构建身份、Codex / Cursor 接入及重复安装，状态见[Mac 安装流水线](https://github.com/pikachu-cxy/Ai-security-check/actions/workflows/macos-trial.yml)。该合成验收不替代实际桌面、系统首次下载或全部扫描组件验证。

本版包含[一键监控与导出报告](./guide/context-cost.md)、完整脱敏长行保存与分片交付、OpenGrep 默认代码检查、记录文件的轻量开发检查和跨编辑器风险统计，以及更明确的组件与漏洞数据诊断。完整包与自动安装的来源提交、构建 ID 和校验值分别核对，不混用。

### 历史版本

旧版本的发布、构建与验收记录见[版本与进展](./reference/changelog.md)。本页安装入口统一使用当前 0.3.11，旧版本记录不作为当前下载或安装依据。
