# 安装、准备与升级

## 默认完整接入

<InstallRequest />

发行包的 `install codex` 是默认接入路径：安装 Runtime、配置 MCP、安装配套 Skill 与 Hook。不增加一层“MCP / 完整版”选择。高级用户可以不运行这条命令，改为[手动 MCP 配置](./mcp.md)。

完整包不依赖用户电脑已有 Python 或 Node.js；但检查组件不全部塞入主包，首次准备需要下载。安装器不会为此安装你的业务项目依赖或启动项目服务。

## 为什么首次准备较慢

主程序与检查数据分开管理。准备过程可能包括扫描引擎、Semgrep 独立运行环境和依赖漏洞数据库下载；网络、平台和已有缓存会影响耗时，不能承诺固定安装秒数。

```powershell
.\security-check\security-check.exe preparation status
.\security-check\security-check.exe preparation watch
```

macOS 使用 `./security-check/security-check` 加相同参数。程序安装与组件准备分阶段呈现；没有准备成功时，不应说“已具备完整检查能力”。

## macOS 首次启动

当前公开 v0.3.6 包没有 Apple Developer ID 签名及公证保证。浏览器下载后可能出现“未知开发者”或内置 Python 库被系统策略拒绝；原生 CI 通过不能代替此项验收。

先核对官方安装包的 SHA256 并保留完整目录。确认来源可信后，按 [Apple 的单个应用批准流程](https://support.apple.com/zh-cn/102445)，在“系统设置 → 隐私与安全性”中选择“仍要打开”。不要全局关闭系统保护或 TLS 验证。

如果仍显示 `library load disallowed by system policy`，停止安装并保存完整报错，等待维护者提供签名、公证及真实下载验收通过的包。若随后变成 `no such file`，检查包内文件是否被移走；保留现场并将核验后的完整包解压到新目录，不要只补一个不明来源的库，也无需另装系统 Python。

本地源码中的安装改进不会自动更新公开下载包。请核对包的 `build_id`，不要用本地构建成功推定浏览器下载流程已通过。

默认数据位于当前用户的数据目录；同一数据目录中的组件与缓存可复用。不要为升级先删除缓存，也不要复制其他用户的扫描状态。显式设置 `SECURITY_RUNTIME_DATA_DIR` 会改变数据位置，配置前应确认权限与剩余空间。

## 当前支持与后续优化

| 方式 | 当前状态 |
| --- | --- |
| 完整包、用户级稳定安装、后台准备、缓存复用 | 当前已有路径 |
| 手动仅配置 MCP | 当前已有路径 |
| 在线查询 / 本地漏洞库由用户选择 | 已确认方向，尚未作为本版能力交付 |
| 官方一条 Shell / PowerShell 命令安装 | 尚未交付 |
| `npx` 安装入口 | 尚未交付；也不代表系统原生自带 Node.js |

本版不能承诺“不下载漏洞库”。不要把尚未实现的在线模式写进配置，也不要随意移除漏洞数据后声称依赖检查可用。

## 升级

1. 保存宿主配置，暂停其他安装、升级或配置编辑。Codex 辅助安装时可保持当前聊天，最后再重启；当前运行的连接不会自动换版本。
2. 下载新包并核对对应版本的 SHA256，完整解压到新目录。
3. 使用新包执行 `install codex`，按实际冲突与迁移诊断处理。
4. 等待准备完成，重启宿主，核对实际连接的构建身份与配套 Skill。

不要直接覆盖仍在运行的可执行文件；不要以仓库已更新推断已安装 Runtime 也更新。用户自定义 Skill 文件与受管文件的冲突应保留诊断，不要手工清空整个 Skill 目录。

## 源码开发安装

仅供开发调试，需要 Python 3.12+、Git，并保持源码目录稳定：

```powershell
git clone --branch feature/runtime-mvp https://github.com/pikachu-cxy/Ai-security-check.git
Set-Location .\Ai-security-check
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\security-check.exe install codex --dev
.\.venv\Scripts\security-check.exe preparation watch
```

`--dev` 显式使用可编辑源码，不是普通用户完整包安装。已有工作目录先保存自己的改动，再同步分支。
