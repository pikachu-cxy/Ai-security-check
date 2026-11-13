# 在 WorkBuddy 中安装与使用

0.3.14 完整包支持 Windows x64、Mac Apple Silicon 和 Mac Intel。安装配置用户级 MCP、Skill 和四个 Hook，并准备检查组件。

## 推荐安装

把安装请求复制到本机 WorkBuddy 聊天。

<InstallRequest editor="workbuddy" />

## Windows {#windows}

在普通 PowerShell 5.1 或更新版本中运行。脚本下载并校验正式完整包。

```powershell
& ([scriptblock]::Create([Text.Encoding]::UTF8.GetString((Invoke-WebRequest -UseBasicParsing 'https://pikachu-cxy.github.io/Ai-security-check/install/windows.ps1').RawContentStream.ToArray()))) -Editor workbuddy
```

## macOS {#macos}

在终端运行。脚本自动识别芯片并校验对应的完整包。

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://pikachu-cxy.github.io/Ai-security-check/install/macos.sh | bash -s -- workbuddy
```

## 手动安装完整包

从[下载页](../../downloads.md)下载对应系统的完整包和 SHA256 文件。核验后完整解压，在 `security-check` 文件夹的上一级目录执行对应命令。

::: code-group
```powershell [Windows]
.\security-check\security-check.exe install workbuddy
```

```sh [macOS]
./security-check/security-check install workbuddy
```
:::

## 重启并验证

完全退出并重新打开 WorkBuddy，在客户端的 MCP 设置中检查 `ai-security-runtime` 服务并审核信任提示。新开聊天，请 Agent 查询实际连接的版本、构建号和检查组件准备状态。遇到旧项目级配置冲突时，按诊断处理并保留原配置。

[安装排查](../verify.md) · [日常工作流程](../workflow.md) · [支持范围](../../reference/support.md)
