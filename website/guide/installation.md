# 安装参数、准备与升级

本页适用于 **0.3.10 正式版**，Mac 自动安装对应独立发行 **macos-trial-v0.3.10**。首次安装请直接进入 [Codex](./editors/codex.md)或 [Cursor](./editors/cursor.md) 页面；以下用于状态查询、组件准备、升级和卸载。

## 先选择正确的程序路径 {#runtime-path}

| 安装方式 | 查询时使用的程序 |
| --- | --- |
| Windows 完整包 | 在包的上级目录使用 `.\security-check\security-check.exe` |
| Mac 按编辑器页自动安装 | 使用 `"$HOME/.local/share/AI-Security-Runtime-macos-trial/security-check"`，可在任意目录执行 |
| Mac 手动下载完整包 | 在包的上级目录使用 `./security-check/security-check` |

Mac 的两种安装方式路径不同，不要混用。以下默认展示 Windows 完整包和 Mac 自动安装；手动完整包将 Mac 示例的程序路径换成上表对应路径即可。

## 查看准备进度

按实际安装方式，选择一条查询命令：

::: code-group
```powershell [Windows]
.\security-check\security-check.exe preparation status
```

```sh [macOS]
"$HOME/.local/share/AI-Security-Runtime-macos-trial/security-check" preparation status
```
:::

`status` 查看当前状态；将末尾的 `status` 改成 `watch` 可持续观察。它们是可选的查询命令，不是第二条安装命令。

首次准备可能下载检查引擎、专用运行环境和漏洞数据。耗时取决于网络、平台和已有缓存。分别查看仍在下载、准备失败和数据过期的项目，保留具体诊断；同一用户的数据缓存可复用，无需先清空。

## 查看版本与构建

::: code-group
```powershell [Windows]
.\security-check\security-check.exe runtime-info --json
```

```sh [macOS]
"$HOME/.local/share/AI-Security-Runtime-macos-trial/secu…12064 tokens truncated…重新扫描指定范围，不复用旧扫描结果。” |
| 严格差异审计 | “开发前建立严格任务，审计实际工作区前后完整差异。” |

严格审计才使用修改前后版本及对应复核流程；不能在编辑后补造基线。普通聊天、只读查询和普通结束事件不启动项目扫描。Git 拉取或源码更新也不会自动升级已安装产品。

## 等待、读取和重连

收尾可能在后台继续；等待超时不代表失败，也不应另建检查来替代。沿同一检查继续读取。后续又修改文件时，需要再次收尾，新结果才代表新版本。

Codex / Cursor 的 Hook 提供会话归属，帮助重连后找到原聊天有权读取的检查。凭证由宿主传递，用户不需要手填，Agent 也不能猜测。重连验收应读取原检查并确认风险处置保留；缺失凭证或归属不符时保留原引用，先排查接入。

读取历史结果不会重新校验磁盘内容，不代表此刻源码与扫描时完全一致。

## 组件和覆盖

默认代码检查使用 OpenGrep，密钥检查使用 Gitleaks，依赖检查使用 Trivy。OSV 不参与默认流程，也不会在 Trivy 失败后自动接替。没有适用依赖文件时，依赖检查可显示“不适用”。

文件无法读取、被排除、解析失败、组件或漏洞数据不可用、规则或分析预算受限，都可能产生部分覆盖。结果应说明具体文件、能力和原因；“未扫描整个项目”本身不构成本次记录文件检查的缺口。扫描范围与 Agent 业务分析范围分别说明。

组件准备见[安装与升级](./installation.md#手动准备组件)。不要把覆盖缺口当作漏洞，也不要用“候选已排除”代替尚未完成的扫描。

## 风险处理与统计

可以说“先分析影响，不修改”“修复这项并保持现有权限”“稍后处理”或提供排除依据。已获授权的同一修复范围无需反复确认，复查必须关联原问题。[风险说明与统计](./risk-handling.md)介绍保存、筛选与汇总方式。

## 可选消耗监控

在支持的 Codex 聊天中说“启动本聊天的消耗监控”，结束后在页面导出报告。聊天 token 不等于纯安全检查 token，不能可靠拆分的部分保持未知。详见[监控指南](./context-cost.md)。
