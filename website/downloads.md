# 下载与构建状态

## 当前发行：0.3.8 · Developer Alpha

[v0.3.8 Release](https://github.com/pikachu-cxy/Ai-security-check/releases/tag/v0.3.8) 已公开发布并于 2026-10-20 替换更新。Windows、Mac Apple Silicon 与 Mac Intel 的当前包来自同一产品源码提交 [`8d5d9a6`](https://github.com/pikachu-cxy/Ai-security-check/commit/8d5d9a694529c7d29cb1fa79c6843ea0763576a9)，实际构建身份以各平台包的 `build_id` 为准。

0.3.8 包含工作流指导去重、MCP 阶段进度与计时、明确文件范围扫描，以及经过身份核验的完整项目扫描结果复用。必要复核、修复授权与强制重扫行为保留，Windows/macOS、Codex/Cursor 共用核心实现；实时进度显示取决于宿主支持。

更新包还包含紧凑摘要、完整证据交接预算、重复及重叠源码共享，以及[上下文开销与 token 监测](./guide/context-cost.md)。公共优化不按编辑器或系统分叉；Codex CLI 用量导入独立启用，其他宿主没有真实用量时保持未知。

**2026-10-20 更新状态：九项资产已替换。** [本次三平台构建与原生验收](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/39398870803)通过；同一源码的合规、Windows/Ubuntu 包完整性检查通过。复用已有 204 项相关定向测试，文档打包契约另有 13 项通过；本次替换不以重复全库回归为门槛，不沿用旧包原生验收结论。

已有 0.3.8 用户也需要重新下载包与配套 SHA256。当前 Windows 构建 ID 为 `7abf1b6e2d587bd87d5d577122ef71c51288f6c46f75ffdddaf40f7cc24e309d`；安装后重启宿主并核对真实构建，不能只看版本号。

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

完整解压后按[快速开始](./guide/quickstart.md)安装，也可在该页选择 Codex、Cursor、WorkBuddy 或其他 MCP 客户端，复制对应安装请求交给本机助手。Mac 包已保留执行权限，正常解压通常无需另行 `chmod`。当前尚未配置 Apple Developer ID 签名和公证，“未知开发者”提示仍可能出现；处理方式见[安装故障排查](./guide/installation.md)。签名、公证、真机与宿主验收不能用一次交叉编译或校验和替代。
