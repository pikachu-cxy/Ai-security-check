# 安装参数、准备与升级

正常接入从[选择编辑器](./quickstart.md)开始。0.3.8 完整包的 `install codex` 和 `install cursor` 已自动启动组件准备。本页的查询和扩展命令按需使用。

## 查看准备进度

以下命令在能看到 `security-check` 文件夹的目录执行，每次选择需要的一条：

::: code-group
```powershell [Windows]
.\security-check\security-check.exe preparation status
```

```sh [macOS]
./security-check/security-check preparation status
```
:::

`status` 查询当前状态；把末尾的 `status` 改为 `watch` 可以持续查看准备进度。**它们都不是第二条安装命令。** 首次准备可能下载检查引擎、独立运行环境和依赖漏洞数据库，耗时取决于网络、平台和已有缓存。

下载或启动失败时保留具体诊断，按失败组件的建议处理。同一用户数据目录中的缓存可以复用，升级前无需清空。

## 查看接入状态

Codex 用户可执行：

::: code-group
```powershell [Windows]
.\security-check\security-check.exe status --json
```

```sh [macOS]
./security-check/security-check status --json
```
:::

Cursor 用户使用 `integration status cursor --scope global --json`。这些命令检查本地配置；编辑器内的实际调用仍按[安装验证](./verify.md)完成。

## 安装参数

在对应编辑器的安装命令后添加参数。例如 Windows 自定义安装位置：

```powershell
.\security-check\security-check.exe install codex --root "D:\Apps\AI-Security-Runtime"
```

| 参数 | 什么时候使用 |
| --- | --- |
| `--root <目录>` | 指定用户稳定安装目录 |
| `--bundle <目录>` | 显式指定已验证的本地完整包 |
| `--offline` | 只核对本地已有组件和数据，不启动下载；缺失的部分仍不可用 |
| `--json` | 需要机器可读的安装回执 |
| `--dev` | 源码开发调试，普通完整包安装无需使用 |

当前没有正式交付 `npx` 或远程 Shell / PowerShell 一键下载安装入口。完整包不要求系统 Python 或 Node.js。

## 手动准备组件

只有手动 MCP 接入或按诊断处理准备问题时才需要单独使用：

::: code-group
```powershell [Windows]
.\security-check\security-check.exe prepare-scanners
```

```sh [macOS]
./security-check/security-check prepare-scanners
```
:::

该命令准备检查引擎和公开漏洞数据，不安装业务项目依赖，也不启动项目服务。当前版本依赖本地漏洞数据，不能承诺跳过下载后仍有完整依赖检查。

## macOS 首次启动

公开包尚无 Apple Developer ID 签名与公证保证。出现“未知开发者”时，先核对官方包的 SHA256 并保留完整目录。确认来源可信后，按 [Apple 的单个应用批准流程](https://support.apple.com/zh-cn/102445)，在“系统设置 → 隐私与安全性”中处理系统提示。

若出现 `library load disallowed by system policy`，保留完整报错，查看[下载页](../downloads.md)的 Mac 修订状态。不要全局关闭系统保护或 TLS 校验。若出现 `no such file`，检查是否完整解压；重新解压到新目录，避免混入旧包文件。

Mac 包通常已带执行权限。仅当执行位丢失且出现 `Permission denied` 时才补充执行权限；执行位不能解决签名或系统策略拒绝的问题。

Intel 与 Apple Silicon 使用各自完整包。0.3.8 三平台包来自同一发布提交，以该发行的 `release-manifest.json` 为准；平台不同或版本号相同仍不代表相同构建。历史 0.3.6 Mac 单独修订另见当时的 `macos-refresh.json`，不要与当前发行混用。

## 升级

1. 保存编辑器配置，暂停其他安装或配置编辑。
2. 下载新完整包与对应 SHA256，核验后解压到新目录。
3. 使用新包执行对应编辑器的安装命令，按实际冲突与迁移诊断处理。
4. 等待组件就绪，完全退出并重启编辑器，再完成[连接验证](./verify.md)。

升级使用新包重新接入即可，不要覆盖仍在运行的程序。源码仓库更新不会自动更新已安装的完整包。自定义 Skill 或配置存在冲突时，保留诊断和用户内容。

## 源码开发安装

仅供开发调试，需要 Python 3.12+、Git，并保持源码目录稳定：

```powershell
git clone --branch feature/runtime-mvp https://github.com/pikachu-cxy/Ai-security-check.git
Set-Location .\Ai-security-check
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\security-check.exe install codex --dev
```

普通用户使用[完整包安装](./quickstart.md)。已有工作目录先保存自己的改动，再同步分支。
