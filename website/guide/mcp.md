# 只接入 MCP

手动路径只建立 MCP 连接，不自动安装宿主 Skill 或 Hook，也不保证宿主按完整任务流程自动调用工具。默认完整接入用户无需执行本页步骤。

## 先准备程序

完整解压对应系统的包，将目录放在长期稳定的位置。以下命令在解压目录执行：

```powershell
.\security-check\security-check.exe prepare-scanners
.\security-check\security-check.exe mcp config --path C:\work\your-project --toml
```

需要 JSON 配置时，将 `--toml` 换为 `--json`。macOS 将命令换为 `./security-check/security-check`，项目路径换为实际 Git 项目的绝对路径。

## 合并到宿主配置

将命令生成的 MCP 条目合并进宿主当前支持的配置文件，不要覆盖整个文件。保留生成的绝对程序路径、工作区绑定与环境配置；不能直接照抄别人的电脑路径。

不同宿主的配置格式与作用域不同。Cursor 的配置与桌面验收步骤见仓库的 [Cursor 接入指南](https://github.com/pikachu-cxy/Ai-security-check/blob/feature/runtime-mvp/docs/guides/CURSOR_INSTALL_AND_TEST.zh-CN.md)。连接可用不等于已验证 Skill、Hook 或完整任务闭环。

## 验证

重启宿主后先只读取 `get_runtime_info`，核对实际版本、构建身份与能力。随后在明确测试的项目中调用工具，确认结果绑定的是正确工作区。

只要没有安装完整任务编排，就不应承诺“每次编辑自动检查”。MCP 提供能力接口，宿主如何使用这些能力仍需单独配置与验证。
