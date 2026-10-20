# 在 Cursor 中使用

Cursor 接入目前面向 **Windows x64、本地单根工作区的测试版**。先确认安装包来源与接入方式，再在隔离示例项目中试用。

::: warning 先确认你拿到的包
公开 v0.3.6 包与 Cursor 自动接入候选不是同一交付。下面的 `install cursor` 需要支持该入口的完整候选包；本页不提供尚未发布的下载链接。只有公开包时，可参考[手动 MCP 配置](../mcp.md)，但这不包含自动任务检查。候选与桌面验收记录见[Cursor 接入状态](https://github.com/pikachu-cxy/Ai-security-check/blob/feature/runtime-mvp/docs/guides/CURSOR_INSTALL_AND_TEST.zh-CN.md)。
:::

## 1. 执行一条安装命令

核对候选包摘要、完整解压后，在能看到 `security-check` 文件夹的目录执行：

```powershell
.\security-check\security-check.exe install cursor
```

安装器会配置用户级 MCP、编辑事件检查和配套使用指引，并自动开始准备检查组件。常规任务检查会加入精确工具白名单；团队策略仍可能要求确认。

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
