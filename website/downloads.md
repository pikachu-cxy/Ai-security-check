# 下载与安装

**许可提示：** 请以下载包内对应版本的许可为准。仓库新许可不追溯改变已经发布的安装包。参见[许可说明](./reference/legal)。

当前正式版为 **0.3.14**。自动安装脚本与手动下载使用同一份原生完整包，无需另装 Python。

## 按编辑器安装 {#install}

[Codex](./guide/editors/codex.md) · [Cursor](./guide/editors/cursor.md) · [WorkBuddy](./guide/editors/workbuddy.md)

**WorkBuddy 重启后，需要在 MCP 管理界面手动勾选 `ai-security-runtime` 的服务信任并启用连接。**

## 正式完整包 {#windows}

| 系统 | 下载 | 校验 |
| --- | --- | --- |
| Windows x64 | [zip](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.14/ai-security-runtime-v0.3.14-windows-x64.zip) | [SHA256](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.14/ai-security-runtime-v0.3.14-windows-x64.zip.sha256) |
| Mac Apple Silicon | [tar.gz](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.14/ai-security-runtime-v0.3.14-macos-arm64.tar.gz) | [SHA256](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.14/ai-security-runtime-v0.3.14-macos-arm64.tar.gz.sha256) |
| Mac Intel | [tar.gz](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.14/ai-security-runtime-v0.3.14-macos-x64.tar.gz) | [SHA256](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.14/ai-security-runtime-v0.3.14-macos-x64.tar.gz.sha256) |

下载包和配套 SHA256，核验后完整解压并保留整个 `security-check` 文件夹。GitHub 的 “Source code” 是源码，不是安装包。

```powershell
Get-FileHash .\ai-security-runtime-v0.3.14-windows-x64.zip -Algorithm SHA256
Get-Content .\ai-security-runtime-v0.3.14-windows-x64.zip.sha256
```

## macOS 自动安装 {#macos}

[Codex](./guide/editors/codex.md#macos) 和 [Cursor](./guide/editors/cursor.md#macos) 页面提供安装命令。脚本识别芯片，下载对应的 0.3.14 完整包。

### macOS 手动安装 {#macos-packages}

```sh
# Apple Silicon
shasum -a 256 -c ai-security-runtime-v0.3.14-macos-arm64.tar.gz.sha256
tar -xzf ai-security-runtime-v0.3.14-macos-arm64.tar.gz
./security-check/security-check install codex
```

Intel 请选择 `macos-x64`。Cursor 将最后的 `codex` 改为 `cursor`；WorkBuddy 按[全局配置说明](./guide/editors/workbuddy.md)接入。

## 来源与验收范围 {#build-details}

本次复用已完成的本地回归和用户确认通过的 WorkBuddy 桌面验收。发布流水线验证三平台新安装包、精简后的 MCP 连接和 Windows 长路径配置，不重复全量本地测试。具体结果以配套验收证据为准。

[Release](https://github.com/pikachu-cxy/Ai-security-check/releases/tag/v0.3.14) · [SHA256SUMS.txt](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.14/SHA256SUMS.txt) · [release-manifest.json](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.14/release-manifest.json) · [Evidence ZIP](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.14/ai-security-runtime-v0.3.14-release-evidence.zip)

[支持状态](./reference/support.md) · [版本说明](./reference/changelog.md)
