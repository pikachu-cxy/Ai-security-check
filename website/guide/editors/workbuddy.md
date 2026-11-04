# 在 WorkBuddy 中使用

WorkBuddy 全局接入复用 Codex/Cursor 的开发检查流程：编辑时只记路径，开发收尾合并扫描，按配置复核告警，同一结果的 Stop 续接去重。普通聊天不启动扫描。

## 全局配置

准备完整运行包和扫描组件后，使用固定安装位置中的程序：

```powershell
# Windows：建议将程序保留在短路径中，不要反复嵌套解压目录。
C:\ASR\security-check.exe setup workbuddy --scope global --json
```

```sh
# macOS：已安装 Runtime 时可复用固定启动器。
~/.local/share/AI-Security-Runtime-install/launcher/security-check setup workbuddy --scope global --json
```

此入口在识别到的配置目录内写入 `mcp.json`、`settings.json` 中本产品的 Hook，以及 `skills/ai-security-review`；保留其他服务器、设置和 Hook。目录优先使用 `WORKBUDDY_CONFIG_DIR`，其次使用 `CODEBUDDY_CONFIG_DIR`；未指定时优先使用已有的 `~/.workbuddy-ai`，否则使用 `~/.workbuddy`。两个目录同时存在时选择 `.workbuddy-ai`，不自动迁移或删除另一目录的配置。配置成功不等于扫描组件已经就绪，首次准备组件仍按[安装说明](../installation.md)操作。

完全退出并重启 WorkBuddy，审核连接与 Hook 权限。在新聊天中让助手创建一个临时样例，确认编辑期间不扫描、收尾只提交当前文件，报告前完成要求的复核。再发送一个只读问题，确认旧检查不会触发 Stop。

旧项目级 `.workbuddy/mcp.json` 若已有本产品配置，应先通过原项目接入的卸载入口移除，避免同时启动两套连接；全局接入不会擅自删除项目配置。

## Windows 与验收范围

Hook 命令使用固定程序入口，项目路径通过标准输入传递，不拼进命令行。配置写入沿用 Windows 扩展路径支持；新增真实 Windows 超过 260 字符目录的安装/重复安装用例。

接入依据本机 WorkBuddy 5.9.4 的 Hook 实现和[官方 Hook 协议参考](https://www.workbuddy.cn/docs/cli/hooks)。源码测试覆盖会话隔离、路径记录、Stop 补交、全局 MCP 和配置保留；Windows 真机长路径与 WorkBuddy 桌面端最终消息展示仍需实际验收，不能由 macOS 单元测试替代。

项目级手动 MCP 接入仍保留：`security-check setup workbuddy --path <项目目录>`。
