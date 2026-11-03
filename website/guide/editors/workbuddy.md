# 在 WorkBuddy 中使用

当前先采用**手动 MCP 接入**，与 Codex、Cursor 共用[统一手动接入入口](../mcp.md#workbuddy)和 **v0.3.12 正式完整包**。

## 1. 准备程序和项目绑定

按[统一步骤](../mcp.md#_1-下载和准备)下载、校验、完整解压正式包，准备检查组件，并为实际本地 Git 项目生成 MCP JSON。程序目录需要长期保留。

## 2. 在桌面添加连接

1. 打开 **专家·技能·连接器 → 连接器 → 自定义连接器 → 添加 MCP**。
2. 合并生成的 `mcpServers` 服务条目，保留其他连接，保存。
3. 对已核验的本地 Runtime 点击“信任”，等待工具加载。
4. 在目标项目新建聊天，按下面的提示实际调用。

macOS WorkBuddy 5.9.4 实测界面使用 `~/.workbuddy-ai/mcp.json`。产品原有 `setup workbuddy --path "项目路径"` 生成的是项目 `.workbuddy/mcp.json`，本次桌面测试没有自动加载该文件；不能仅凭命令自检成功就认定连接成功。其他发行版本以客户端显示的配置路径为准。

完整 JSON 示例、Windows 路径写法、卸载与排查见[统一手动接入页](../mcp.md#workbuddy)。

## 3. 验证和使用

```text
请通过 AI Security Runtime 的 MCP 工具检查实际版本、项目路径和组件状态。
只读取状态，不扫描或修改项目，不要用终端命令代替 MCP。
若工具不可用，请明确说明。
```

调用成功并确认项目绑定及组件就绪后，再在独立示例项目请求：

```text
请使用 AI Security Runtime 检查当前示例项目，说明实际检查范围和发现。
先不要修改代码。
```

仅 MCP 需要主动发起检查，不自动安装 Skill 或原生 Hook。

## 实测结果与原生 Hook 边界

2026-11-03 通过上述桌面界面配置后，服务加载了 81 个工具，Agent 实际调用 `get_runtime_info` 成功。本轮使用本地 0.3.12 **DEV** Runtime 验证 MCP 通道；这不替代正式发行包在 WorkBuddy 中的安装及扫描验收。



2026-11-03 在 macOS WorkBuddy 5.9.4 的独立测试项目中，实测原生 `SessionStart`、`PreToolUse`、`PostToolUse`、`Stop` 均触发；启动和工具执行后的附加上下文能到达 Agent。测试配置为项目 `.codebuddy/settings.local.json`。其中 `SessionStart` 输入没有 `cwd`，不能直接照搬其他宿主的项目识别逻辑。

这些回执证明宿主具备原生 Hook 能力，**不代表产品完整接入已通过**。当前产品仍需 WorkBuddy 专用事件映射、会话绑定、改动收集和 Stop 续办适配及端到端验收；暂不提供完整接入配置，不承诺自动检查或自动续办修复。

[更多接入边界](../../reference/support.md) · [连接失败排查](../verify.md#遇到问题时)
