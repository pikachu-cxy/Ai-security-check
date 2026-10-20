# 下载与构建状态

## 当前发行：0.3.8 · Developer Alpha

[v0.3.8 Release](https://github.com/pikachu-cxy/Ai-security-check/releases/tag/v0.3.8) 已公开发布。Windows、Mac Apple Silicon 与 Mac Intel 来自同一源码提交 [`be65833`](https://github.com/pikachu-cxy/Ai-security-check/commit/be658339322d8b74554219901e1265034a146ae7)，实际构建身份以各平台包的 `build_id` 为准。

0.3.8 包含工作流指导去重、MCP 阶段进度与计时、明确文件范围扫描，以及经过身份核验的完整项目扫描结果复用。必要复核、修复授权与强制重扫行为保留，Windows/macOS、Codex/Cursor 共用核心实现；实时进度显示取决于宿主支持。

**2026-10-20 发布状态：已公开发布。** [本次 GitHub Release 工作流](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/39386551651)通过 Windows/macOS 精简相关回归、合规、包完整性和三平台原生验收，共公开九项资产。此次采用精简发布模式，未重复执行全库回归；不沿用旧版本的原生验收结论。

| 平台 | 完整安装包 | 校验 | 当前状态 |
| --- | --- | --- | --- |
| Windows x64 | [下载 ZIP](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.8/ai-security-runtime-v0.3.8-windows-x64.zip) | [SHA256](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.8/ai-security-runtime-v0.3.8-windows-x64.zip.sha256) | 原生 CI 验收通过 |
| macOS Apple Silicon | [下载 tar.gz](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.8/ai-security-runtime-v0.3.8-macos-arm64.tar.gz) | [SHA256](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.8/ai-security-runtime-v0.3.8-macos-arm64.tar.gz.sha256) | ARM 原生 CI 验收通过 |
| macOS Intel | [下载 tar.gz](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.8/ai-security-runtime-v0.3.8-macos-x64.tar.gz) | [SHA256](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.8/ai-security-runtime-v0.3.8-macos-x64.tar.gz.sha256) | Intel 原生 CI 验收通过 |

[完整 SHA256 清单](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.8/SHA256SUMS.txt) · [机器可读发行清单](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.8/release-manifest.json) · [验收证据 ZIP](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.8/ai-security-runtime-v0.3.8-release-evidence.zip)

原生验收包含无外部 Python 启动、扫描组件准备、样例扫描、受管 Skill、MCP、隔离安装生命周期及合成修复与 Hook 流程。各项实际结果以本次工作流和证据 ZIP 为准。安装包可用性验收不代表任何用户项目已完成漏洞检查。

本版仍为 Developer Alpha 预发行试用版。合成 SDK / Hook 场景不等于实际桌面操作；macOS 真机、Cursor 桌面、苹果签名与公证等仍按[支持边界](./reference/support.md)单独认定。

::: warning 使用同一发行的包与校验
0.3.7 及更早发行、本地临时候选与本次 0.3.8 发行分别记录。请使用本页平台包及其配套校验，不将旧候选的 SHA256 或其他版本 Skill 套用到新包。源码拉取不会自动更新已安装产品，安装后重新连接宿主并核对实际版本与 `build_id`。
:::

## 校验后再安装

下载包与同名 SHA256 文件后，核对文件名与摘要。

Windows：

```powershell
Get-FileHash .\ai-security-runtime-v0.3.8-windows-x64.zip -Algorithm SHA256
Get-Content .\ai-security-runtime-v0.3.8-windows-x64.zip.sha256
```

macOS：在对应包与 `.sha256` 文件所在目录执行：

```sh
shasum -a 256 -c ai-security-runtime-v0.3.8-macos-arm64.tar.gz.sha256
```

Intel 换为 `macos-x64`。摘要用于检查下载完整性，不代替发布者身份、系统签名或平台兼容性验证。

完整解压后按[快速开始](./guide/quickstart.md)安装，也可复制页面上的安装请求交给本地 Codex。Mac 包已保留执行权限，正常解压通常无需另行 `chmod`。当前尚未配置 Apple Developer ID 签名和公证，“未知开发者”提示仍可能出现；处理方式见[安装故障排查](./guide/installation.md)。签名、公证、真机与宿主验收不能用一次交叉编译或校验和替代。
