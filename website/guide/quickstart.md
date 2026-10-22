---
description: 选择你的编辑器和系统，完成安装、连接验证和第一个独立示例。
---

# 快速开始

::: info 安装前先看语言覆盖
**代码规则：Java、Python、JavaScript / TypeScript 的明确子集**，共 56 条独立规则、48 条默认启用。Vue 单文件组件、Go、PHP 等暂无自带 SAST 规则；密钥检查与依赖生态另计。[查看语言、文件后缀与检测覆盖 →](../reference/support.md#语言覆盖)
:::

当前使用 **0.3.9 正式版**。让 AI 帮你改代码时，同时查看这次改动里的安全问题；接入后照常提出需求、查看风险，再决定如何处理。Mac 自动安装使用独立发行 `macos-trial-v0.3.9.3`，Runtime 版本同为 0.3.9。

<div class="doc-journey" aria-label="开始使用的四个步骤">
<span><b>01</b> 选择编辑器</span><span><b>02</b> 按系统安装</span><span><b>03</b> 确认连接与组件</span><span><b>04</b> 做一个小任务</span>
</div>

## 1. 选择你的编辑器 {#choose-editor}

进入你实际使用的编辑器页面。**Windows 和 macOS 安装都在同一页**，后面直接跟着重启、验证和小 Demo。

<EditorCards />

| 你要怎么接入 | 从哪里开始 |
| --- | --- |
| Codex：Windows 完整包 / Mac 自动安装 | [Codex 安装与使用](./editors/codex.md) |
| Cursor：Windows 完整包 / Mac 自动安装 | [Cursor 安装与使用](./editors/cursor.md) |
| WorkBuddy 或其他 MCP 客户端 | 按上方对应页面完成项目级或手动 MCP 配置 |

## 2. 选择一种安装方式

- **自己安装**：在编辑器页选择 Windows 或 macOS，复制对应系统的一条命令到终端。
- **让助手安装**：复制编辑器页的“安装请求”到对应助手聊天，由它下载、校验和接入。自然语言请求不要粘贴到终端。

Windows 完整包需要先下载、校验并解压，再在能看到 `security-check` 文件夹的目录打开 PowerShell。Mac 的 Codex / Cursor 自动安装命令可以在任意终端目录执行，运行环境会自动准备。

安装会自动开始准备检查组件；首次下载可能在安装返回后继续，不需要再执行一条准备命令。Mac 遇到粘贴提醒时，先看[提醒原因与处理方式](../reference/faq.md#macos-paste)。

## 3. 重启并验证

安装结束后完全退出并重新打开编辑器。

<!--@include: ../.vitepress/snippets/check-install.md-->

具体状态和排查方式见[安装成功了吗？](./verify.md)。

## 4. 在独立示例中试用

先完成编辑器页的小任务，确认检查结果能回到聊天；再用[第一个使用 Demo](./demo.md)体验“发现问题 → 选择修复 → 沿原问题复查”。需要逐项记录结果时，使用[动手测试用例](./playground.md)。

接入成功后，日常直接描述需求即可。发现风险时先看位置、影响和依据，再选择需要修复的具体问题。
