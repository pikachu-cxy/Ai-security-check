# 在 Codex 中使用

在本地 Codex 中接入后，你可以照常让 AI 修改项目，并在任务结果里查看本次改动的安全问题。安装器会一起配置 MCP 服务、配套使用指引和编辑事件检查。

## 1. 准备完整包

从[下载页](../../downloads.md)选择 Windows x64 或对应芯片的 macOS 包，核对 SHA256 并完整解压。在能看到 `security-check` 文件夹的目录打开终端。

## 2. 执行一条安装命令

::: code-group
```powershell [Windows]
.\security-check\security-check.exe install codex
```

```sh [macOS]
./security-check/security-check install codex
```
:::

这条命令会安装到当前用户的稳定目录、配置 Codex 并自动开始准备检查组件。首次准备需要联网；安装进程返回后，组件仍可能在后台下载。查看进度是可选操作，见[高级命令](../installation.md#查看准备进度)。

如果由 Codex 帮你安装，完成当前安装任务后再重启它；安装期间不要同时编辑 Codex 配置。

::: details 想让 Codex 代你下载和安装？
<InstallRequest />
:::

::: info macOS 出现“未知开发者”？
当前包的签名与公证限制及处理方法见[macOS 首次启动](../installation.md#macos-首次启动)。先核对来源和摘要，再按系统的单个应用批准流程处理。
:::

## 3. 确认安装成功

完全退出并重新打开 Codex，在实际项目的新聊天中发送：

```text
请确认 AI Security Runtime 已连接，并检查版本、配套使用指引和检查组件状态。
不要扫描或修改项目；如果有未完成项，请告诉我下一步。
```

**成功时应看到**：服务调用成功，实际版本与所装包一致，组件准备完成，配套使用指引可用。若提示未连接、下载中或组件失败，按[安装验证与排查](../verify.md)处理。

## 4. 开始使用

```text
请给当前项目的文件导出功能增加输入校验，保持现有接口。
完成后检查这次改动；如果发现安全问题，先说明位置、影响和修复建议。
```

你可以先阅读结果，再决定修复哪一项。同一范围已经批准的修复无需重新授权；后续复查应继续对应原问题。

[试一个完整 Demo →](../demo.md) · [安装参数与升级](../installation.md)
