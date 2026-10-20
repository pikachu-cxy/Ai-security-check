# 常见问题

## 安装为什么这么慢？

安装命令已经自动开始准备组件，首次可能下载引擎、独立运行环境和漏洞数据库。无需再执行第二条安装命令；需要了解进度时，按[高级命令](../guide/installation.md#查看准备进度)查询。不要反复清空缓存后重装。

## 安装完了，怎么知道能用了？

重启编辑器，在项目聊天中请求只读连接与组件状态查询，再用一个小例子确认实际检查结果能返回聊天。可直接复制[安装验证页](../guide/verify.md)的请求；随后完成[使用 Demo](../guide/demo.md)。

## 在哪里查看各编辑器的安装步骤？

左侧“接入你的编辑器”分为 [Codex](../guide/editors/codex.md)、[Cursor](../guide/editors/cursor.md)、[WorkBuddy](../guide/editors/workbuddy.md)和[其他 MCP 客户端](../guide/editors/other.md)。每页说明对应入口、安装或配置方法，以及实际支持范围。

## 能不下载漏洞库吗？

当前版本不能把“无需本地漏洞库”作为已交付特性。在线与本地双模式已确定为后续优化方向，届时由用户选择。安装方式与未来能力见[安装说明](../guide/installation.md)。

## 每台电脑都能使用 npx 吗？

不能。`npx` 属于 Node.js/npm 工具链，并不是 Windows 或 macOS 自带命令。本项目当前没有正式交付 `npx` 安装入口；完整包也不要求 Node.js。

## 源码已更新，为什么连接的还是旧版？

已安装的完整包不会随 Git 工作区自动更新。重启宿主后读取实际 `get_runtime_info`，核对版本、`build_id` 与配套 Skill，不能只看 README 或版本字符串。

## Git 拉取会导致漏查文件吗？

Git 拉取与正常开发都按真实修改前记录和实际改动范围核对。0.3.7 修正了复核可以提前结束的问题：必需窗口尚未读完、复核单元尚未提交时要求 Agent 继续。拉取完成不等于全部文件已人工复核；真实证据缺失或预算耗尽仍需明确说明。

## 为什么有 PARTIAL？为什么代码还会脱敏？

`PARTIAL` 表示部分覆盖，还有不能确认的范围，并不等于已发现漏洞。0.3.7 保留普通代码文本，对识别出的凭据值继续脱敏；如果隐藏值影响判断，仍保留该语义缺口。Windows 与 macOS 使用相同策略，旧任务不会被重新生成证据。详见[检查流程](../guide/workflow.md)和[源码证据脱敏](./privacy.md#源码证据如何脱敏)。

## 只要 MCP，不想安装 Hook 和 Skill？

不要执行默认完整接入命令。按[仅 MCP 指南](../guide/mcp.md)准备组件并生成宿主配置，手动合并；此时不承诺完整任务自动化。

## Cursor 支持哪些系统，如何确认能用？

Cursor 安装页提供 Windows 完整包和 [Mac 独立环境试用入口](../guide/macos-trial.md)，Mac 安装器会自动选择 Apple Silicon 或 Intel。安装后重启 Cursor，先核对连接、版本、组件与项目路径，再完成一次小任务检查。可直接使用 [Cursor 安装与使用](../guide/editors/cursor.md)中的请求和示例。具体桌面验收记录与尚未覆盖的环境见[支持状态](./support.md#cursor-接入与桌面验证)。

## Mac 安装提示 Python 动态库被系统拒绝，怎么办？

原完整包如果出现 `Failed to load Python shared library` 或 `library load disallowed by system policy`，可以尝试 [Mac 独立环境安装](../guide/macos-trial.md)。它自动下载产品专用 Python 与产品包，无需预装 Python、Git 或 Homebrew，避开原包内嵌 Python 的加载路径。这个新入口仍处于试用阶段，请按页面核对真实连接与组件状态，失败时提供脱敏诊断，不关闭系统安全保护。

## Windows TEMP 路径太长怎么办？

当前源码为 Semgrep 使用短私有临时目录，无需全局修改系统 TEMP/TMP。特殊账户可按诊断配置项目外已有的短本地 `SECURITY_RUNTIME_ENGINE_TEMP_ROOT`。权限或本地通信被沙箱拒绝时，应在获准支持该能力的环境执行，不要关闭系统安全控制。

## “准备成功”代表项目通过检查吗？

不是。安装、组件准备、MCP 连接、项目检查与原风险复查分别记录。普通测试成功也不等于漏洞已修复。

## 如何报告问题？

到 [GitHub Issues](https://github.com/pikachu-cxy/Ai-security-check/issues) 提供脱敏后的系统架构、宿主版本、实际构建身份、失败步骤与具体诊断。不要公开真实凭据、原始聊天或私有源码。
