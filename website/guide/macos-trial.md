---
description: 在 Mac 上用一条命令安装独立运行环境，接入 Cursor 或 Codex，再验证连接与检查能力。
---

# Mac 一条命令安装 · 试用

如果你使用 Mac 和 Cursor / Codex，可以通过本页安装 AI Security Runtime。安装器会自动识别 Apple Silicon（M 系列）或 Intel 芯片，下载产品专用的 Python 3.12.12 和产品包。**无需预装 Python、Git、Homebrew，也无需手动配置环境变量。**

这条路径用于试用新的独立环境安装方式，也适合原完整包出现 `Failed to load Python shared library` 或 `library load disallowed by system policy` 的用户。它避开原包加载内嵌 Python 的方式；是否适用于你的系统，仍以安装、编辑器连接和组件实际检查结果为准。

::: warning 试用范围与已有安装
本入口对应独立预发行 `macos-trial-v0.3.8.1`。目前尚未完成用户真实 M 系列 Mac 的桌面验收，也不宣称已获得 Apple Developer ID 签名或公证。

如果你已经接入所选编辑器，本次安装可能将它的用户级 AI Security Runtime 连接、Skill 和 Hook 更新为试用版本。安装器会保留其他服务并按已有冲突处理规则保护用户修改。请先结束正在运行的检查任务，安装期间不要同时修改编辑器配置。
:::

## 1. 选编辑器，执行一条命令

在 Mac 的“终端”中执行你需要的一条。命令会从本文档站下载并运行安装脚本，需要联网；可以先[查看安装脚本](https://pikachu-cxy.github.io/Ai-security-check/install/macos.sh)及[试用发行](https://github.com/pikachu-cxy/Ai-security-check/releases/tag/macos-trial-v0.3.8.1)。

::: code-group
```sh [Cursor]
curl --proto '=https' --tlsv1.2 -fsSL https://pikachu-cxy.github.io/Ai-security-check/install/macos.sh | bash -s -- cursor
```

```sh [Codex]
curl --proto '=https' --tlsv1.2 -fsSL https://pikachu-cxy.github.io/Ai-security-check/install/macos.sh | bash -s -- codex
```
:::

安装器会校验下载内容，安装产品并接入所选编辑器，自动开始准备检查引擎和漏洞数据。安装过程不会扫描或修改你的业务项目。首次下载时间取决于网络和已有缓存，不需要再执行第二条安装或准备命令。

安装位置是 `~/.local/share/AI-Security-Runtime-macos-trial`。请保留这个目录；下载目录中的压缩包或临时文件不作为编辑器长期启动路径。已有检查组件缓存按产品原有规则复用。

如果命令失败，保留最后一次显示的阶段和具体错误，不要关闭系统安全保护或 TLS 校验。脚本未完成时，不要只凭目录已经创建就判断安装成功。

## 2. 重启编辑器，确认真的能用

安装返回后，完全退出并重新打开所选编辑器。在你要使用的本地项目中新建聊天，发送：

```text
我刚安装了 AI Security Runtime 的 Mac 独立环境试用版。
请通过实际工具调用，只查询安装状态：
1. 是否已连接，实际版本、build_id 和来源提交是什么，是否对应刚安装的试用版；
2. 代码、密钥和依赖检查是否就绪，有没有仍在下载、失败或漏洞数据过期的项目；
3. 当前绑定的项目绝对路径是什么，是否与我打开的项目一致。
不要扫描或修改项目。不能确认的部分明确列出，不根据配置文件猜测连接成功。
```

请按下面的标准判断：

| 观察点 | 成功时应看到 | 未达到时 |
| --- | --- | --- |
| 产品安装 | 安装完成，实际版本与构建身份可查询 | 保留安装阶段和错误 |
| 编辑器连接 | 重启后真实工具调用成功，构建对应本次安装 | 核对服务启用状态、启动错误和旧进程 |
| 检查组件 | 代码、密钥、依赖检查均就绪，漏洞数据有效 | 等待下载或记录失败组件，不能视为全部可用 |
| 项目绑定 | 返回你实际打开的项目绝对路径 | 在正确项目中新建聊天并核对配置作用域 |

“配置已写入”仅代表安装的一部分。组件可能仍在后台准备，编辑器也需要重启才能加载新版本。

::: details 可选：在终端查询安装版本和准备进度
以下是查询命令，不是第二次安装。每次选择你需要的一条。

查看版本与构建身份：

```sh
"$HOME/.local/share/AI-Security-Runtime-macos-trial/security-check" runtime-info --json
```

查看检查组件状态：

```sh
"$HOME/.local/share/AI-Security-Runtime-macos-trial/security-check" preparation status
```

将末尾 `status` 改成 `watch` 可持续观察准备进度。查询本地状态成功不能替代编辑器内的真实连接验证。
:::

## 3. 用独立示例试一次

新建一个空的 `security-runtime-demo` 文件夹，用刚接入的编辑器打开。检查示例需要本地 Git 工作区；如果编辑器提示缺少 Git，请先完成其正常的 Git 安装指引，再初始化这个示例文件夹。**安装 Runtime 本身不要求 Git。**

在示例项目的聊天中发送：

```text
请确认当前目录是独立的 security-runtime-demo 示例目录，并在需要时初始化 Git。
新建 labels.py，实现 normalize_label(text)，去除首尾空格并转为小写。
完成后使用 AI Security Runtime 检查本次改动，说明实际检查范围和结果。
无需安装业务依赖；发现风险时先解释，不自动修复。
```

你应看到文件创建结果，以及本次改动的实际检查状态。组件未就绪、范围未覆盖或检查失败时，应保留明确原因；文件创建成功不能替代检查成功。

想验证确实能发现问题，再完成[已知命令拼接问题 Demo](./demo.md)和[动手测试用例](./playground.md)。这些样例只放在独立示例目录，不需要执行有问题的函数。

## 4. 反馈试用结果

无论成功还是失败，都可以将下面的记录提交到 [GitHub Issues](https://github.com/pikachu-cxy/Ai-security-check/issues)。系统版本和芯片可在苹果菜单的“关于本机”中查看。

```text
macOS 版本：
芯片：Apple Silicon（具体 M 型号）/ Intel
编辑器与版本：Cursor / Codex
试用发行：macos-trial-v0.3.8.1
Runtime 版本 / build_id / 来源提交：
原来是否已安装 AI Security Runtime：
结果：安装完成 / 连接成功 / 组件就绪 / Demo 完成（分别填写）
失败阶段或组件（如有）：
脱敏后的完整报错：
```

只提供安装与示例测试记录。删除日志中的用户名、私人目录、令牌等敏感内容，不上传业务源码或真实密钥。无法查询的版本或状态直接写“无法确认”。

## 已有用户如何切回原安装

需要切回时，先结束正在运行的检查任务，用原来的已验证完整包重新执行 `install cursor` 或 `install codex`，再完全退出并重启对应编辑器。核对服务实际返回的版本与 `build_id`，确认连接已切回后再决定是否清理试用目录。

如果原 Mac 完整包本来就被系统拒绝，重新安装它仍可能失败；请保留诊断并反馈，不能把“执行过恢复命令”当成恢复成功。其他编辑器连接和共享组件缓存不要手动清空。

[返回快速开始](./quickstart.md) · [Cursor 使用说明](./editors/cursor.md) · [Codex 使用说明](./editors/codex.md) · [下载与构建状态](../downloads.md)
