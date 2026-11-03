# 仅 MCP：统一手动接入

Codex、Cursor、WorkBuddy 均可按本页手动连接同一个本地 Runtime。此方式只配置 MCP，不安装 Skill 或原生 Hook，不承诺编辑后自动检查。已发布的 0.3.12 可使用本页步骤；不要使用尚未发布的 `install … --mode mcp` 命令。

| 编辑器 | 完整接入 | 仅 MCP |
| --- | --- | --- |
| Codex | 使用编辑器页的一键安装 | 本页 TOML 配置 |
| Cursor | 使用编辑器页的一键安装 | 本页 JSON 配置 |
| WorkBuddy | 仍在验证，不作为已支持能力 | 本页 JSON 配置 |

## 1. 下载和准备

从[下载页](../downloads.md)取得对应系统、芯片的 **v0.3.12 正式完整包及 SHA256**，校验后解压到长期保留的目录。仅 MCP 不需要运行 `install codex/cursor`。下面在能看到 `security-check` 文件夹的目录执行：

::: code-group
```sh [macOS]
./security-check/security-check prepare-scanners
./security-check/security-check mcp config --path "/Users/you/work/project" --json
```
```powershell [Windows]
.\security-check\security-check.exe prepare-scanners
.\security-check\security-check.exe mcp config --path "C:\work\project" --json
```
:::

路径须替换为真实本地 Git 项目。Codex 将最后的 `--json` 换为 `--toml`。配置生成命令只打印内容，不替你写入编辑器配置。组件下载失败与 MCP 连接失败是不同状态。

## 2. 合并配置

只合并生成的服务条目，保留其他服务。以下是结构示例，优先使用上一步实际输出，不能原样照抄占位路径。每个连接固定绑定一个项目；切换项目必须重新生成绑定并重载连接，不把旧项目结果当成新项目结果。

### Codex {#codex}

合并到 `~/.codex/config.toml`（自定义 CODEX_HOME 时使用对应目录）。相同服务名只保留一个条目：

```toml
[mcp_servers.ai_security_runtime]
command = "/绝对路径/security-check/security-check"
args = ["mcp"]

[mcp_servers.ai_security_runtime.env]
SECURITY_RUNTIME_WORKSPACE = "/绝对路径/项目"
SECURITY_RUNTIME_INTEGRATION = "generic-mcp"
```

Windows 的 command 使用完整 EXE 路径；TOML 可用单引号字面量路径，例如 `'C:\Tools\security-check\security-check.exe'`。配置格式参见 [Codex 官方 MCP 文档](https://developers.openai.com/codex/mcp)。

### Cursor {#cursor}

合并到当前项目的 `.cursor/mcp.json`，或在用户级 `~/.cursor/mcp.json` 配置固定项目的连接。不要同时保留同一产品的项目级和全局重复条目：

```json
{
  "mcpServers": {
    "ai-security-runtime": {
      "command": "/绝对路径/security-check/security-check",
      "args": ["mcp"],
      "env": {
        "SECURITY_RUNTIME_WORKSPACE": "/绝对路径/项目",
        "SECURITY_RUNTIME_INTEGRATION": "generic-mcp"
      }
    }
  }
}
```

Windows JSON 路径使用双反斜杠，例如 `C:\\Tools\\security-check\\security-check.exe`。参见 [Cursor 官方 MCP 文档](https://prod.cursor.com/help/customization/mcp)。

### WorkBuddy {#workbuddy}

在 WorkBuddy 桌面打开 **专家·技能·连接器 → 连接器 → 自定义连接器 → 添加 MCP**。在 JSON 编辑框中合并上面的 `mcpServers` 配置，保留原有服务，然后保存。回到列表，对自己核验过的本地程序点击“信任”，等待工具加载。command 是实际程序绝对路径，args 为 `["mcp"]`，env 中填写项目绑定。

macOS WorkBuddy 5.9.4 实测界面显示的配置路径是 `~/.workbuddy-ai/mcp.json`；仅写入项目 `.workbuddy/mcp.json` 后新建任务，服务未自动出现。因此该桌面版本应使用上述界面。以客户端显示的路径为准，不要覆盖整份已有配置。

官方文档提供项目级 `.workbuddy/mcp.json` 和用户级 `~/.workbuddy/mcp.json`。不同桌面发行的配置根可能不同；优先使用客户端实际的 MCP 配置界面，不因文件写入成功就认定它已加载。参见 [WorkBuddy 官方 MCP 文档](https://www.workbuddy.ai/docs/zh/workbuddy/From-Beginner-to-Expert-Guide/Function-Description/MCP-Guide)。

已发布产品也提供项目配置辅助命令：

```sh
./security-check/security-check setup workbuddy --path "/绝对路径/项目"
```

它写入项目 `.workbuddy/mcp.json` 并进行 Runtime 自检，不能替代桌面的实际调用验证。手动配置不增加 Hook、Skill 或自动修复授权。

## 3. 验证连接

保存后重载 MCP 或完全退出并重新打开编辑器，在目标项目中新建聊天。按客户端提示启用该服务，再发送：

```text
请通过 AI Security Runtime 的 MCP 工具检查连接、实际版本、构建、项目路径和组件状态。
只读取状态，不扫描或修改项目。不要用终端命令代替 MCP 调用。
如果服务或工具不可用，请说明失败在哪一步。
```

实际调用成功、版本与项目绑定正确后，再在独立示例项目中请求：

```text
请使用 AI Security Runtime 检查当前示例项目，报告实际检查范围和发现。
先不要修改代码。若组件未就绪，请明确说明，不把未执行报告为通过。
```

“工具列表出现”“配置已保存”“Runtime 自检成功”都不能代替实际调用。仅 MCP 模式需要用户主动要求检查；自动编辑检查必须另外完成宿主 Hook 和 Skill 接入验证。

## 4. 切换模式和卸载

从完整接入改为仅 MCP：先按[卸载说明](./installation.md#卸载与重新安装)移除该编辑器已有的产品接入，再合并本页配置。只添加 MCP 不会自动关闭原 Hook；共享 Skill 仅在其他宿主不再需要时移除。

手动配置的 MCP 连接，由你从客户端删除对应服务条目；不要删除整份配置文件。项目源码、历史检查记录与组件缓存不需要清空。

## 排查

| 现象 | 核对 |
| --- | --- |
| 服务未出现 | 当前配置作用域、项目路径、JSON/TOML 格式和客户端实际配置位置 |
| 程序启动失败 | command 是否为存在的绝对路径，完整包是否完整保留，系统是否阻止程序 |
| MCP 连上但无法扫描 | 检查组件和漏洞数据准备状态 |
| 结果属于别的项目 | 重新生成当前项目绑定并重载 MCP |
| 改完代码没有自动检查 | 仅 MCP 的预期边界；需要主动提出检查请求 |
