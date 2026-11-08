# 在 WorkBuddy 中使用

WorkBuddy 全局接入复用 Codex/Cursor 的开发检查流程：编辑时只记路径，开发收尾合并扫描，按配置复核告警，同一结果的 Stop 续接去重。普通聊天不启动扫描。

## 全局配置

从[下载页](../../downloads.md)下载 **0.3.14 完整包**及 SHA256，核验后完整解压到长期保留的短路径。以下命令中的程序路径按实际解压位置替换；首次执行 `prepare-scanners` 准备组件和漏洞数据，然后配置全局接入：

```powershell
# Windows：建议将程序保留在短路径中，不要反复嵌套解压目录。
C:\ASR\security-check.exe prepare-scanners
C:\ASR\security-check.exe setup workbuddy --scope global --json
```

```sh
# macOS：从完整包上一级目录执行，保留整个 security-check 文件夹。
./security-check/security-check prepare-scanners
./security-check/security-check setup workbuddy --scope global --json
```

此入口在识别到的配置目录内写入 `mcp.json`、`settings.json` 中本产品的 Hook，以及 `skills/ai-security-review`；保留其他服务器、设置和 Hook。目录优先使用 `WORKBUDDY_CONFIG_DIR`，其次使用 `CODEBUDDY_CONFIG_DIR`；未指定时优先使用已有的 `~/.workbuddy-ai`，否则使用 `~/.workbuddy`。两个目录同时存在时选择 `.workbuddy-ai`，不自动迁移或删除另一目录的配置。配置成功不等于扫描组件已经就绪，首次准备组件仍按[安装说明](../installation.md)操作。

## 重启后手动信任 MCP（必做）

1. 完全退出并重启 WorkBuddy。
2. 打开“专家 · 技能 · 连接器”中的连接器 / MCP 服务管理（不同版本名称可能略有差异）。
3. 找到 `ai-security-runtime`，**手动勾选服务信任并启用连接**。安装器写入配置不会替你批准信任。
4. 确认服务已连接，工具数为 **11**。若仍显示旧版 80 多个工具，检查是否同时存在旧项目级连接，并核对实际启动程序路径。
5. 在新聊天发送：`请只查询已连接安全服务的版本与构建信息，不修改文件、不扫描项目。` 返回版本应为 **0.3.14**。

## 做一次开发验收

在临时 Git 项目中新建聊天，发送：

```text
请创建一个 Python 命令行待办工具，支持新增、列出和完成事项，数据存到当前项目的 JSON 文件。完成必要的基本验证后交付。
```

正常体验是编辑期间仅记录路径，开发收尾检查本次文件；存在告警时按配置复核并给出详情，修复需你的决定。再发送一个只读问题，确认旧任务不会重复触发 Stop 提醒。MCP 显示“已连接”只证明连接，不能代替这一步自动检查验收。

本次发布复用用户已确认通过的 WorkBuddy 桌面开发验收，不在发布阶段重复运行。

旧项目级 `.workbuddy/mcp.json` 若已有本产品配置，应先通过原项目接入的卸载入口移除，避免同时启动两套连接；全局接入不会擅自删除项目配置。

## Windows 与验收范围

Hook 命令使用固定程序入口，项目路径通过标准输入传递，不拼进命令行。配置写入沿用 Windows 扩展路径支持；新增真实 Windows 超过 260 字符目录的安装/重复安装用例。

接入依据本机 WorkBuddy 5.9.4 的 Hook 实现和[官方 Hook 协议参考](https://www.workbuddy.cn/docs/cli/hooks)。源码测试覆盖会话隔离、路径记录、Stop 补交、全局 MCP 和配置保留；发布流水线补充真实 Windows runner 上的长路径安装及重复安装验证；这与用户确认的本机桌面验收分别记录，不代表所有 Windows 桌面版本均已测试。

项目级手动 MCP 接入仍保留：`security-check setup workbuddy --path <项目目录>`。
