# 快速开始

默认完整接入，不需要选择“MCP 版”或“完整版”。如果不希望自动配置 Skill 和 Hook，请走[手动 MCP](./mcp.md)。

## 1. 获取匹配的完整包

先看[下载与构建状态](../downloads.md)，选择 Windows x64、macOS Intel 或 macOS Apple Silicon。保留解压后的整个 `security-check` 目录，不要只取一个可执行文件。

完整包内置运行时 Python，不要求另装 Python、pip 或 Node.js。首次检查组件准备仍需联网。当前 Developer Alpha 已通过三平台原生 CI；macOS 真机与 Cursor 桌面验收仍待独立完成，不作为稳定兼容性保证。

## 2. 完全退出 Codex，执行完整接入

在**解压目录**打开终端。

### Windows PowerShell

```powershell
.\security-check\security-check.exe install codex
if ($LASTEXITCODE -ne 0) { throw '接入未完成，请保留诊断' }
.\security-check\security-check.exe preparation watch
```

### macOS 终端

以下为 Developer Alpha 完整包安装命令；需使用对应架构包，并保留系统提示与诊断，不要为安装而关闭系统安全保护。

```sh
./security-check/security-check install codex
./security-check/security-check preparation watch
```

接入会安装到当前用户的稳定目录、写入配套宿主配置并启动组件准备。已有配置冲突、权限或下载失败应按输出处理，不要重复覆盖配置。

## 3. 确认准备与连接

`preparation watch` 观察准备进度，`preparation status` 查询当前状态。下载完成仅代表组件可用，不代表任何项目已经检查。

重新打开 Codex，在实际 Git 项目的新聊天中发送：

> 请只核对已连接的 ai_security_runtime 的版本、构建身份、v3 任务工具及 task-result-delivery-v1 能力，不扫描、不修改代码。

当前源码路径应具备 `task-review-plan-v3`、`task-result-delivery-v1` 及配套任务工具。相同版本号不一定是相同构建，请一并核对 `build_id` 和配套 Skill；不要把旧发行包与新 Skill 混用。

## 4. 正常提出开发需求

在项目内正常让 Agent 开发。编辑前建立任务基线，编辑后进行检查和关联复核。出现风险时再明确选择处置；仅询问修复影响不授权编辑。

[详细安装与升级](./installation.md) · [风险处置](./risk-handling.md) · [排查问题](../reference/faq.md)
