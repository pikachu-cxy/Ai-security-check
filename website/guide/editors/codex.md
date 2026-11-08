---
description: 在 Windows 或 Mac 上安装 AI Security Runtime，接入 Codex，验证连接并完成第一个小任务。
---

# 在 Codex 中安装与使用

当前正式完整包为 **0.3.14**。接入后，照常在本地 Codex 聊天里提出开发需求，即可查看本次改动的安全检查结果，发现问题后再决定是否修复。本页从安装到第一次检查，适用于本地单根 Git 工作区。

## 1. 安装到这台电脑

安装会配置用户级 MCP 连接、配套 Skill 和 Hook，并自动开始准备检查组件。首次需要联网；安装期间不会扫描或修改业务项目。选择你的系统，只执行对应的一条命令。

### Windows {#windows}

在普通 **PowerShell（5.1 或更新版本）** 中执行这一条命令，可在任意目录运行。适用于 Windows x64，自动下载 **0.3.14 正式完整包**、核验 SHA256、解压并接入 Codex，无需手动下载解压，也无需另装 Python、Node.js 或 Git。

```powershell
& ([scriptblock]::Create([Text.Encoding]::UTF8.GetString((Invoke-WebRequest -UseBasicParsing 'https://pikachu-cxy.github.io/Ai-security-check/install/windows.ps1').RawContentStream.ToArray()))) -Editor codex
```

可先[查看安装脚本](https://pikachu-cxy.github.io/Ai-security-check/install/windows.ps1)。安装到用户目录，不需要管理员权限。请先结束正在运行的检查；已有产品连接可能更新，配置冲突时会停止并保留诊断。下载失败或校验不一致时不会运行下载的程序，处理报错后可重试同一命令。

安装完成后，终端会给出查询准备进度的完整命令；下载包保存在 `%LOCALAPPDATA%\AI-Security-Runtime-downloads`，已安装程序位于 `%LOCALAPPDATA%\ASR`。

::: details 手动下载与安装（备用）
从[下载页](../../downloads.md#windows)下载完整包及配套 SHA256，校验并完整解压，在能看到 `security-check` 文件夹的目录执行：

```powershell
.\security-check\security-check.exe install codex
```
:::


### macOS {#macos}

在 Mac 的“终端”中执行下面这一条命令。安装器自动识别 **M 系列（Apple Silicon）或 Intel**，下载并校验 0.3.14 原生完整包，**无需预装 Python、Git、Homebrew 或配置环境变量**。

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://pikachu-cxy.github.io/Ai-security-check/install/macos.sh | bash -s -- codex
```

可先[查看安装脚本](https://pikachu-cxy.github.io/Ai-security-check/install/macos.sh)及[脚本 SHA256](https://pikachu-cxy.github.io/Ai-security-check/install/macos.sh.sha256)。文档部署直接同步仓库维护的最新脚本。程序保存在 `~/.local/share/AI-Security-Runtime-install`，请保留该目录；从任何终端目录都可以运行上面的命令。

<!--@include: ../../.vitepress/snippets/macos-paste.md-->

安装入口与手动下载使用同一份 **v0.3.14 正式完整包**，无需另装 Python。已有 Codex 连接可能更新，请先结束正在运行的检查。当前没有 Apple Developer ID 签名或公证保证，系统策略问题按[支持说明](../../reference/support.md#macos-installation)处理。

::: details 手动安装 macOS 完整包（备用）
从[下载页](../../downloads.md#macos-packages)选择芯片对应的包，核验 SHA256 并完整解压后运行：

```sh
./security-check/security-check install codex
```
:::

### 希望让助手代为安装？

复制下面的**安装请求到本地 Codex 聊天**，由助手按本页下载、校验并接入。自然语言请求用于聊天，Shell 命令用于终端，选择一种方式即可。

<InstallRequest editor="codex" />

## 2. 重启并确认安装成功

完全退出并重新打开 Codex，在本地项目中开始新聊天。按宿主提示审核连接和 Hook 信任。

<!--@include: ../../.vitepress/snippets/check-install.md-->

首次组件下载可能在后台继续。仍在准备时，按[准备进度](../installation.md#查看准备进度)查询；不需要再执行第二条安装命令。遇到调用失败或路径不符，见[安装验证与排查](../verify.md)。

如果由 Codex 帮你安装，先等当前安装任务结束，再完全退出并重启它。

## 3. 做一个独立的小任务

<!--@include: ../../.vitepress/snippets/editor-demo.md-->

## 遇到安装问题

| 你看到的情况 | 下一步 |
| --- | --- |
| Mac 阻止粘贴命令 | 核对提醒的原文，按[粘贴提醒说明](../../reference/faq.md#macos-paste)处理 |
| 下载失败、校验不一致或安装中断 | 保留失败阶段和具体报错；处理网络或诊断后可重试同一条命令 |
| 安装结束但组件未就绪 | 查看[准备进度](../installation.md#查看准备进度)，分别记录下载中、失败和数据过期项 |
| 重启后未连接或版本仍旧 | 核对服务启用状态、实际启动错误和 `build_id`，按[连接排查](../verify.md#connection)处理 |

需要帮助时，按[反馈模板](../../reference/faq.md#report)提供脱敏后的系统、芯片、编辑器版本、安装方式和失败阶段。

[日常怎么用](../workflow.md) · [仅 MCP 接入](../mcp.md) · [升级与卸载](../installation.md#卸载与重新安装)

## 重连与历史结果

完成小任务后保留原检查，在同一聊天恢复连接时只读该检查和风险处置，不重新扫描。会话凭证由 Hook 提供；用户不需填写，Agent 不得猜测。默认扫描本次记录文件，关联业务逻辑由 Agent 按需复核。

## CLI 与可选分析

Codex CLI 和 Cursor CLI 已按各自原生 Hook 协议适配；需要客户端版本支持并启用相应事件，实际 CLI 仍须端到端验收。Codex 桌面与使用同一 `~/.codex` 的 CLI 共用安装，自定义 `CODEX_HOME` 或另一用户需单独配置。Cursor 的 Shell 事后事件不等同于跨进程常驻文件监听，未知路径不能保证补齐。Claude Code 与 Qoder CLI 暂列后续计划。

扫描容量、Agent 复核、业务逻辑审计与 Stop 开关见[自定义配置](../configuration.md)。
