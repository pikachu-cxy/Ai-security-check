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

0.3.9 对 Git 拉取与正常开发都按真实修改前记录和实际改动范围核对。必需窗口尚未读完、复核单元尚未提交时要求 Agent 继续。拉取完成不等于全部文件已人工复核；真实证据缺失或预算耗尽仍需明确说明。

## 为什么有 PARTIAL？为什么代码还会脱敏？

`PARTIAL` 表示部分覆盖，还有不能确认的范围，并不等于已发现漏洞。0.3.9 保留普通代码文本，对识别出的凭据值继续脱敏；新任务保存完整脱敏长行并分片交付。如果隐藏值影响判断，仍保留该语义缺口。Windows 与 macOS 使用相同策略，旧任务不会被重新生成证据。详见[检查流程](../guide/workflow.md)和[源码证据脱敏](./privacy.md#源码证据如何脱敏)。

## 项目显示 NEEDS_SCAN，或者路径被拒绝，怎么办？

`NEEDS_SCAN` 表示该项目没有扫描记录；组件 `READY` 且实际源码根目录已被接受时，安装可以正常使用，无需为了消除这个状态重装。需要检查项目时，再明确提出扫描请求。

路径被拒绝时，先确认打开的是包含源码和 Git 仓库的实际根目录，而不是 ZIP 外层目录，并让助手使用该绝对路径查询。拒绝码本身不能确定具体原因；仍失败时保留目录验证和返回诊断，参见[安装验证](../guide/verify.md)。

## 工具显示版本，为什么仍不能检查？

能读取版本不代表能核实实际执行环境。0.3.9 会检查 Semgrep 的程序、解释器和包身份；不明包装脚本不能仅凭版本正确就被视为就绪。在线准备可为自动发现的系统 Semgrep 创建独立受管环境，显式路径或受管组件故障则保留诊断。缺少 OSV 数据库、漏洞数据过期和更新时间未知也分别说明，见[组件准备](../guide/installation.md#手动准备组件)。

## 怎么卸载后重新安装？

先退出编辑器，使用产品的卸载入口移除对应宿主接入；共享 Skill 在其他宿主不再需要时再移除。程序、缓存和历史默认保留，常规升级无需清空它们。命令见[卸载与重新安装](../guide/installation.md#卸载与重新安装)，不要手动删除整个编辑器配置目录或源码。

## 只要 MCP，不想安装 Hook 和 Skill？

不要执行默认完整接入命令。按[仅 MCP 指南](../guide/mcp.md)准备组件并生成宿主配置，手动合并；此时不承诺完整任务自动化。

## Cursor 支持哪些系统，如何确认能用？

[Cursor 安装页](../guide/editors/cursor.md)同时提供 Windows 完整包和 Mac 自动安装，Mac 安装器会识别 Apple Silicon 或 Intel。安装后重启 Cursor，先核对连接、版本、组件与项目路径，再完成一次小任务检查。可直接使用 [Cursor 安装与使用](../guide/editors/cursor.md)中的请求和示例。具体桌面验收记录与尚未覆盖的环境见[支持状态](./support.md#cursor-接入与桌面验证)。

## Mac 提示“可能是恶意软件，已阻止粘贴”，怎么办？ {#macos-paste}

这是 macOS 终端针对可疑粘贴场景的防诈骗提醒。Apple 说明：不常使用终端、从浏览器或聊天等应用复制内容时可能出现；该类提醒可以不依据命令的具体内容触发。**单凭这个弹窗，不能判定安装脚本已被检出为恶意软件。** 它发生在粘贴阶段，也不能证明安装已开始或成功。依据：[Apple 处理指引](https://support.apple.com/zh-cn/127377)、[终端与脚本保护说明](https://support.apple.com/en-ie/guide/security/sece3b202c4b/web)。

遇到时按这个顺序处理：

1. 核对只复制了对应编辑器页面的一条 Shell 命令，未混入提示符、其他命令或聊天说明。
2. 核对下载地址是 `https://pikachu-cxy.github.io/Ai-security-check/install/macos.sh`，末尾是你要接入的 `codex` 或 `cursor`。
3. 理解用途：`curl` 下载脚本，管道将脚本交给 `bash` 执行；脚本准备专用运行环境、校验产品包并配置所选编辑器。可以先打开[脚本原文](https://pikachu-cxy.github.io/Ai-security-check/install/macos.sh)查看。
4. 只有确认来源可靠、理解用途且确实要安装时，才由你选择“仍然粘贴”，再次核对终端中的内容后执行。不确定就选择“不粘贴”。

**若原文是“检测到恶意软件，粘贴被阻止”或“已阻止恶意脚本”**，请停止并保留提示，不套用普通粘贴提醒的继续步骤。这个区别同样见上述 Apple 指引。无需关闭系统保护、修改 TLS 校验或改用另一种复制方式规避提醒。

自然语言“安装请求”应粘贴到 Codex / Cursor 聊天；只有代码块中的安装命令粘贴到终端。

## Mac 安装提示 Python 动态库被系统拒绝，怎么办？

原完整包如果出现 `Failed to load Python shared library` 或 `library load disallowed by system policy`，可以改用 [Codex 的 Mac 安装](../guide/editors/codex.md#macos)或 [Cursor 的 Mac 安装](../guide/editors/cursor.md#macos)。它自动下载产品专用 Python 与产品包，无需预装 Python、Git 或 Homebrew，避开原包内嵌 Python 的加载路径。请按对应编辑器页核对真实连接、构建和组件状态，失败时提供脱敏诊断。运行时加载失败与[终端粘贴提醒](#macos-paste)发生在不同阶段。

## Windows TEMP 路径太长怎么办？

0.3.9 为 Semgrep 使用短私有临时目录，无需全局修改系统 TEMP/TMP。特殊账户可按诊断配置项目外已有的短本地 `SECURITY_RUNTIME_ENGINE_TEMP_ROOT`。权限或本地通信被沙箱拒绝时，应在获准支持该能力的环境执行，不要关闭系统安全控制。

## “准备成功”代表项目通过检查吗？

不是。安装、组件准备、MCP 连接、项目检查与原风险复查分别记录。普通测试成功也不等于漏洞已修复。

## 如何报告问题？ {#report}

向 [GitHub Issues](https://github.com/pikachu-cxy/Ai-security-check/issues) 提供以下记录。Mac 的系统版本与芯片可在苹果菜单“关于本机”中查看；无法查询的项目填写“无法确认”。

```text
系统与版本：Windows / macOS
芯片：x64 / Apple Silicon（具体 M 型号）/ Intel Mac
编辑器与版本：Codex / Cursor / 其他
安装方式：Windows 完整包 / Mac 自动安装 / Mac 完整包
Runtime 版本 / build_id / 来源提交：
结果：安装完成 / 真实连接成功 / 组件就绪 / Demo 完成（分别填写）
失败阶段与组件：粘贴 / 下载 / 校验 / 安装 / 重启连接 / 组件准备 / 检查
脱敏后的完整报错：
```

删除日志中的用户名、私人目录、令牌等敏感内容，不上传业务源码、真实密钥或原始聊天。请保留具体错误和失败阶段，不只写“安装失败”。
