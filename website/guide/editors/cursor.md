# 在 Cursor 中使用

在 Cursor 的 Agent 聊天中接入 AI Security Runtime 后，你可以照常让 AI 修改代码，并查看本次改动的安全检查结果。发现问题时，先看位置、影响和建议，再决定是否修复。

Windows 使用 0.3.8 完整包；Mac Apple Silicon 和 Intel 用户可尝试新的[独立环境安装](../macos-trial.md)，无需预装 Python、Git 或 Homebrew。下面的一条安装命令会一起配置 MCP、配套使用指引和编辑事件检查。先在本地单根 Git 工作区使用，具体平台与桌面验证状态见[支持说明](../../reference/support.md#cursor-接入与桌面验证)。

## 1. 执行一条安装命令

**Windows**：从[下载页](../../downloads.md)获取完整包并核对 SHA256，完整解压并保留整个 `security-check` 文件夹。

**Mac**：先阅读[独立环境试用范围](../macos-trial.md)。尚未完成真实 M 系列 Mac 桌面验收；已有 Cursor 连接可能切换到本次试用版本。

Windows 在能看到 `security-check` 文件夹的目录打开 PowerShell；Mac 直接打开“终端”。选择对应的一条命令：

::: code-group
```powershell [Windows]
.\security-check\security-check.exe install cursor
```

```sh [macOS · 独立环境试用]
curl --proto '=https' --tlsv1.2 -fsSL https://pikachu-cxy.github.io/Ai-security-check/install/macos.sh | bash -s -- cursor
```
:::

Mac 试用安装器会自动识别两种芯片，校验下载并准备独立运行环境。它不会扫描或修改业务项目。安装后的状态查询与反馈见 [Mac 试用指南](../macos-trial.md)。

想让 Cursor 代你下载和安装？复制下方请求，粘贴到本机 Cursor 的 Agent 聊天即可：

<InstallRequest editor="cursor" />

安装器会将程序放到当前用户的稳定目录，并自动开始准备检查组件和漏洞数据。安装进程返回后，首次下载可能仍在后台进行；查询进度是可选操作，Mac 试用版见[状态查询](../macos-trial.md#_2-重启编辑器-确认真的能用)，Windows 完整包见[准备进度](../installation.md#查看准备进度)，不必再执行一条准备命令。

常规检查与状态查询会配置到精确工具白名单，是否弹出确认仍取决于 Cursor 的运行模式和团队策略。独立扫描、执行收尾检查及修复操作保留原有确认要求；分析修复影响不等于批准修改。

从旧版本升级时，使用所选安装方式重新接入，再重启 Cursor 并核对真实版本。仅更新源码不会更新已安装的程序和配置。只希望手动调用工具时，可选择[仅 MCP 接入](../mcp.md)。

::: details 继续使用 macOS 完整包
0.3.8 的 macOS 完整包仍可从[下载页](../../downloads.md)获取。M 系列芯片选择 `macos-arm64`，Intel 选择 `macos-x64`；核验并完整解压后执行 `./security-check/security-check install cursor`。完整包与试用版的程序路径不同。若系统拒绝加载包内 Python，可改用上面的独立环境试用入口，具体说明见[首次启动排查](../installation.md#macos-首次启动)。
:::

## 2. 确认连接与准备状态

完全退出并重新打开 Cursor，打开一个本地 Git 项目，在 MCP 工具设置中确认 AI Security Runtime 服务已启用。在 Agent 聊天中发送：

```text
请只检查 AI Security Runtime 的安装状态：是否已连接，实际版本是否与安装包一致，
检查组件是否准备完成、是否有失败或仍在下载的项目，以及当前绑定的项目路径。
不要扫描或修改项目；无法确认的部分明确列出，未就绪时告诉我下一步。
```

**成功时应看到**：工具调用成功，项目路径正确，组件准备完成。只看到 MCP 条目还不够；接下来用一个小任务确认检查结果能回到聊天中。详见[安装验证](../verify.md)。

## 3. 试一次开发任务

在独立的示例项目中新建 Agent 聊天，发送：

```text
请新建 labels.py，实现 normalize_label(text)，去除首尾空格并转为小写。
完成后检查本次改动，说明检查范围和结果；发现风险时先解释，不自动修复。
无需安装业务依赖。
```

你应看到文件创建结果，以及针对本次改动的检查状态。有风险时应说明位置、影响和建议；没有发现时也应说明覆盖范围。如果没有检查结果或检查未完成，保留具体诊断，按[安装验证](../verify.md)排查。

## 4. 继续使用与练习

日常直接在 Agent 聊天中提出开发需求即可。需要检查整个项目时，明确说明项目和范围；需要修复时，选择具体问题并批准对应修改，修复后继续复查原问题。

接下来可以完成[第一个使用 Demo](../demo.md)，或用[测试用例](../playground.md)练习发现风险、分析影响和批准修复。不同系统、模型和远程工作区的适用范围统一见[支持状态](../../reference/support.md#cursor-接入与桌面验证)。

[准备进度与高级命令](../installation.md#查看准备进度) · [常见问题](../../reference/faq.md)
