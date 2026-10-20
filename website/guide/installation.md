# 安装参数、准备与升级

首次安装请直接进入 [Codex](./editors/codex.md)或 [Cursor](./editors/cursor.md) 页面，按 Windows / macOS 选择一条命令。本页用于安装后的查询、升级和手动接入。

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
"$HOME/.local/share/AI-Security-Runtime-macos-trial/security-check" runtime-info --json
```
:::

核对 `version`、`build_id` 和 `source_commit`。同样的 0.3.8 版本号可能对应完整包或 Mac 自动安装的不同构建，以[对应发行记录](../downloads.md#build-details)为准。

## 查看接入状态

Codex 用户：

::: code-group
```powershell [Windows]
.\security-check\security-check.exe status --json
```

```sh [macOS]
"$HOME/.local/share/AI-Security-Runtime-macos-trial/security-check" status --json
```
:::

Cursor 用户：

::: code-group
```powershell [Windows]
.\security-check\security-check.exe integration status cursor --scope global --json
```

```sh [macOS]
"$HOME/.local/share/AI-Security-Runtime-macos-trial/security-check" integration status cursor --scope global --json
```
:::

这些命令核对本地配置。编辑器是否真的加载了服务，还需要在重启后的聊天中完成[安装验证](./verify.md)。

## 完整包的安装参数

本节参数只用于完整包程序的 `install codex` / `install cursor`，不要加到 Mac 的 `curl … | bash -s -- codex` 命令后。Mac 自动安装入口当前只接受一个编辑器名称，安装目录固定。

例如，Windows 完整包自定义安装位置：

```powershell
.\security-check\security-check.exe install codex --root "D:\Apps\AI-Security-Runtime"
```

| 参数 | 什么时候使用 |
| --- | --- |
| `--root <目录>` | 指定完整包的稳定安装目录 |
| `--bundle <目录>` | 显式指定已验证的本地完整包 |
| `--offline` | 只核对本地已有组件和数据；缺失范围仍不可用 |
| `--json` | 获取机器可读的安装回执 |
| `--dev` | 仅供源码开发调试 |

## 手动准备组件

只有手动 MCP 接入或按诊断处理准备问题时，才需要单独执行：

::: code-group
```powershell [Windows]
.\security-check\security-check.exe prepare-scanners
```

```sh [macOS]
"$HOME/.local/share/AI-Security-Runtime-macos-trial/security-check" prepare-scanners
```
:::

该命令准备检查引擎和公开漏洞数据，不安装业务依赖，也不启动项目服务。当前依赖检查需要漏洞数据，不能承诺跳过下载后仍有完整检查能力。其他 MCP 客户端使用完整包时，按[程序路径表](#runtime-path)调整路径。

## macOS 首次启动

| 提醒或报错 | 处理方式 |
| --- | --- |
| “可能是恶意软件，已阻止粘贴” | 按[粘贴提醒说明](../reference/faq.md#macos-paste)核对来源、命令和用途，属于执行前的粘贴阶段 |
| “检测到恶意软件”或“已阻止恶意脚本” | 停止，保留原文和下载来源，不套用普通粘贴提醒的继续步骤 |
| 完整包提示无法验证开发者 | 先校验来源与 SHA256，再按 [Apple 的应用批准指引](https://support.apple.com/zh-cn/102445)核对系统提示 |
| `Failed to load Python shared library` / `library load disallowed by system policy` | 保留完整报错；Codex / Cursor 可改用各自页面的 Mac 自动安装入口，随后重新验证 |
| `no such file` | 完整包核对解压层级；自动安装核对是否完成及产品目录是否保留 |
| `Permission denied` | 先核对路径和权限；仅在可信完整包执行位丢失时补执行权限，不能用它解决签名或系统策略问题 |

当前没有 Apple Developer ID 签名或公证保证。不要全局关闭系统保护、移除所有隔离属性或关闭 TLS 校验来换取成功提示。

## 升级与切回

### Mac 按编辑器页自动安装

重新执行 [Codex](./editors/codex.md#macos)或 [Cursor](./editors/cursor.md#macos) 页的安装命令，再重启编辑器并核对构建。固定发行的重复安装不代表一定有新版本；以该入口实际发行和状态输出为准。

需要切回原完整包时，用原已验证包执行对应编辑器的安装命令。确认真实连接已切回后，再决定是否清理自动安装目录；原包本来被系统拒绝时，仍需保留失败诊断。

### Windows 或 Mac 手动完整包

1. 结束正在运行的检查任务，保存配置，安装期间不同时编辑配置。
2. 下载新包及配套 SHA256，核验后解压到新目录。
3. 用新包执行对应编辑器的安装命令，按实际冲突诊断处理。
4. 完全退出并重启编辑器，核对构建、组件和项目路径。

升级无需先清空共享组件缓存；不要覆盖仍在运行的程序或删除用户修改。源码拉取不会自动更新已安装产品。

::: details 源码开发安装（仅开发调试）
需要 Python 3.12+、Git，并保持源码目录稳定：

```powershell
git clone --branch feature/runtime-mvp https://github.com/pikachu-cxy/Ai-security-check.git
Set-Location .\Ai-security-check
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\security-check.exe install codex --dev
```

普通用户按对应编辑器页安装。当前未提供 `npx` 或远程 PowerShell 安装入口。
:::
