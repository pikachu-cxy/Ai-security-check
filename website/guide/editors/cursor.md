---
description: 在 Windows 或 Mac 上安装 AI Security Runtime，接入 Cursor，验证连接并完成第一个小任务。
---

# 在 Cursor 中安装与使用

接入后，照常在 Cursor 的 Agent 聊天里提出开发需求，即可查看本次改动的安全检查结果，发现问题后再决定是否修复。本页从安装到第一次检查，适用于本地单根 Git 工作区。

## 1. 安装到这台电脑

安装会配置用户级 MCP 连接、配套 Skill 和 Hook，并自动开始准备检查组件。首次需要联网；安装期间不会扫描或修改业务项目。选择你的系统，只执行对应的一条命令。

### Windows {#windows}

从[下载页](../../downloads.md#windows)下载 Windows x64 完整包和配套 SHA256，核对后完整解压。保留整个 `security-check` 文件夹，在能看到该文件夹的目录打开 PowerShell：

```powershell
.\security-check\security-check.exe install cursor
```

完整包自带运行环境，不要求另装 Python 或 Node.js。找不到程序时，先核对解压层级和终端所在目录。

### macOS {#macos}

在 Mac 的“终端”中执行下面这一条命令。安装器自动识别 **M 系列（Apple Silicon）或 Intel**，下载并校验专用 Python 与产品包，**无需预装 Python、Git、Homebrew 或配置环境变量**。

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://pikachu-cxy.github.io/Ai-security-check/install/macos.sh | bash -s -- cursor
```

可先[查看安装脚本](https://pikachu-cxy.github.io/Ai-security-check/install/macos.sh)。程序保存在 `~/.local/share/AI-Security-Runtime-macos-trial`，请保留该目录；从任何终端目录都可以运行上面的命令。

<!--@include: ../../.vitepress/snippets/macos-paste.md-->

::: details Mac 当前版本与已有安装
这条命令使用独立发行 [macos-trial-v0.3.9.2](https://github.com/pikachu-cxy/Ai-security-check/releases/tag/macos-trial-v0.3.9.2)，Runtime 版本为 0.3.9。Apple Silicon 和 Intel 的安装、构建身份及重复安装由本次 Mac CI 分别核验；真实用户电脑上的系统策略、Cursor 桌面连接和检查体验仍需实际确认，尚无 Apple Developer ID 签名或公证保证。详见[支持状态](../../reference/support.md#macos-installation)。

已有 Cursor 连接、Skill 和 Hook 可能更新到本次版本。请先结束正在运行的检查任务，安装期间不要同时编辑配置。安装器按现有归属与冲突规则保护其他服务和用户修改。

如需切回原完整包，使用原已验证包重新执行 `install cursor`，再重启 Cursor 并核对实际构建。若原包本来就被系统拒绝，仍可能启动失败，不能仅凭执行过命令就认定已恢复。
:::

::: details 继续使用 macOS 完整包
从[完整包下载](../../downloads.md#macos-packages)选择对应芯片的包并核验，完整解压后，在能看到 `security-check` 文件夹的目录执行：

```sh
./security-check/security-check install cursor
```

完整包与上面的自动安装入口不同，查询时请使用[对应的程序路径](../installation.md#runtime-path)。若出现 Python 动态库被系统策略拒绝，可尝试上面的自动安装方式，保留具体报错。
:::

### 希望让助手代为安装？

复制下面的**安装请求到 Cursor 的 Agent 聊天**，由助手按本页下载、校验并接入。自然语言请求用于聊天，Shell 命令用于终端，选择一种方式即可。

<InstallRequest editor="cursor" />

## 2. 重启并确认安装成功

完全退出并重新打开 Cursor，在本地项目中开始新聊天。按宿主提示审核连接和 Hook 信任。

<!--@include: ../../.vitepress/snippets/check-install.md-->

首次组件下载可能在后台继续。仍在准备时，按[准备进度](../installation.md#查看准备进度)查询；不需要再执行第二条安装命令。遇到调用失败或路径不符，见[安装验证与排查](../verify.md)。

常规状态与任务检查使用精确工具白名单，实际是否免确认仍受 Cursor 运行模式和团队策略约束。修复需要你的明确同意。

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

[日常怎么用](../workflow.md) · [仅 MCP 接入](../mcp.md) · [安装参数与升级](../installation.md)
