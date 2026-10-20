# 在 WorkBuddy 中使用

WorkBuddy 当前提供项目级 MCP 配置。你可以尝试在聊天中主动要求检查项目；自动编辑检查和真实桌面完整流程尚未完成验收。

## 让助手帮你接入

如果 WorkBuddy 能在本机执行命令，复制下方请求到聊天，并说明实际项目路径。助手会下载、核验完整包并配置当前项目的 MCP 连接；你也可以按后面的步骤手动操作。

<InstallRequest editor="workbuddy" />

## 1. 准备程序

下载并校验[完整包](../../downloads.md)，完整解压到长期保留的位置。此接入会引用这个程序路径，之后不要随意移动文件夹。

## 2. 配置当前项目

在能看到 `security-check` 文件夹的目录执行，将路径替换为你实际的本地 Git 项目：

::: code-group
```powershell [Windows]
.\security-check\security-check.exe setup workbuddy --path "C:\work\your-project"
```

```sh [macOS]
./security-check/security-check setup workbuddy --path "/Users/you/work/your-project"
```
:::

配置写入当前项目的 `.workbuddy/mcp.json`。检查组件需另行准备，参见[高级组件准备](../installation.md#手动准备组件)。这是手动 MCP 路径，不是 Codex 的完整安装流程。

## 3. 在 WorkBuddy 中验证

重新打开该项目，查看 MCP 服务是否可用，然后在聊天中发送：

```text
请只检查 AI Security Runtime 的连接、实际版本、项目路径和组件状态。
不要扫描或修改项目。如果无法调用，请说明失败在哪一步。
```

配置、自检和测试客户端的结果不能替代 WorkBuddy 桌面的实际调用。确认调用成功且组件就绪后，才继续[示例检查](../demo.md)。

## 4. 主动发起检查

```text
请使用 AI Security Runtime 检查当前示例项目，说明实际检查范围和发现的问题。
先不要修改代码。
```

每次需要检查时明确提出请求。当前接入没有标准化的原生编辑事件适配，不承诺修改后自动检查或自动续办修复。

[更多接入边界](../../reference/support.md) · [连接失败时怎么排查](../verify.md#遇到问题时)
