# 在 Cursor 中使用

Cursor 接入目前面向 **Windows x64、本地单根工作区的测试版**。先确认安装包来源与接入方式，再在隔离示例项目中试用。

::: warning 先确认你拿到的包
下面的 `install cursor` 请使用 0.3.8 完整发行包，下载入口见[下载页](../../downloads.md)。命令入口、连接配置和实际桌面任务验收分别认定，当前仍需独立 Cursor 桌面验收。仅需工具连接时可参考[手动 MCP 配置](../mcp.md)，但这不包含自动任务检查。详细记录见[Cursor 接入状态](https://github.com/pikachu-cxy/Ai-security-check/blob/feature/runtime-mvp/docs/guides/CURSOR_INSTALL_AND_TEST.zh-CN.md)。
:::

## 1. 执行一条安装命令

从[下载页](../../downloads.md)选择对应平台的完整包并核对 SHA256。Mac 的 M 系列芯片选择 `macos-arm64`，Intel 芯片选择 `macos-x64`；完整解压并保留整个 `security-check` 文件夹，不要只复制可执行文件。

在能看到 `security-check` 文件夹的目录，打开 PowerShell（Windows）或终端（macOS），执行对应命令：

::: code-group
```powershell [Windows]
.\security-check\security-check.exe install cursor
```

```sh [macOS · Intel / Apple Silicon]
./security-check/security-check install cursor
```
:::

macOS 两种芯片使用相同的安装命令，但安装包不能混用。首次启动若遇到“未知开发者”、系统策略拒绝或执行权限问题，请按 [macOS 首次启动](../installation.md#macos-首次启动)处理，不要全局关闭系统保护。提供安装步骤不代表 Cursor 的 macOS 桌面流程已经验收通过。

安装器会配置用户级 MCP、编辑事件检查和配套使用指引，并自动开始准备检查组件。常规任务检查会加入精确工具白名单；团队策略仍可能要求确认。

源码中的白名单现已补齐指导读取、已有扫描结果的复核与查询、修复影响分析和收尾状态查询。
影响分析不会批准修复；独立项目/差异扫描、执行收尾检查及修复操作仍保留确认要求。
这次补齐已包含在 0.3.8 发行包中；从旧版本升级后需再次安装或修复接入，使受管白名单生效。
仅拉取源码不会更新已安装产品的配置。Cursor 的运行模式和团队策略仍决定实际是否弹出确认。

## 2. 确认连接与准备状态

完全退出并重新打开 Cursor，打开一个本地 Git 项目，在 MCP 工具设置中确认 AI Security Runtime 服务已启用。在 Agent 聊天中发送：

```text
请检查 AI Security Runtime 的连接、版本和检查组件状态。
确认当前项目路径正确；不要扫描或修改项目，未就绪时说明下一步。
```

**成功时应看到**：工具调用成功，项目路径正确，组件准备完成。只看到 MCP 条目还不够；接下来用一个小任务确认检查结果能回到聊天中。详见[安装验证](../verify.md)。

## 3. 在示例项目中使用

完成[使用 Demo](../demo.md)，再按[测试用例](../playground.md)观察风险说明和修复复查。如果聊天没有返回检查结果，保留实际诊断；不要把“配置已写入”当成自动检查已生效。

当前测试版的真实桌面验证范围、不同模型和免确认效果分别记录。macOS、远程、多根工作区和其他入口尚需独立验收，不能沿用本地 Windows 的结论。

[准备进度与高级命令](../installation.md#查看准备进度) · [常见问题](../../reference/faq.md)
