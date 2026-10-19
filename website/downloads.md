# 下载与构建状态

## 当前发行：0.3.6 · Developer Alpha

[v0.3.6 已公开发布](https://github.com/pikachu-cxy/Ai-security-check/releases/tag/v0.3.6)，原始版本标签与 Windows 包对应提交 `b4fa0ab086866f5db5c59b8f5f74ec180ed43f23`。这是 Developer Alpha 预发行版，不是稳定版或桌面兼容性认证。

**Mac 安装兼容修订：** 修订源码为 [`82b554d94ddec9692f8d27c82f239e9bf92c4509`](https://github.com/pikachu-cxy/Ai-security-check/commit/82b554d94ddec9692f8d27c82f239e9bf92c4509)，Intel、Apple Silicon 和 Windows 原生包均已通过[本轮原生验收](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/39268609668)。该流程在[Windows/Mac 全量回归](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/39268609723)通过后仅替换两套 Mac 资产，Windows 公开包保持不变。只有 Release 出现对应的 [Mac 修订回执](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.6/macos-refresh.json)，且源码、包摘要与配套清单一致，才表示修订已发布。完成后请重新下载 Mac 完整包及 SHA256 文件；机器清单的 `artifact_source_commits` 分别记录各平台实际源码，原始标签不代表修订后的 Mac 包源码。

| 平台 | 完整安装包 | 校验 | 当前状态 |
| --- | --- | --- | --- |
| Windows x64 | [下载 ZIP](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.6/ai-security-runtime-v0.3.6-windows-x64.zip) | [SHA256](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.6/ai-security-runtime-v0.3.6-windows-x64.zip.sha256) | 原生全量 CI 验收通过 |
| macOS Apple Silicon | [下载 tar.gz](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.6/ai-security-runtime-v0.3.6-macos-arm64.tar.gz) | [SHA256](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.6/ai-security-runtime-v0.3.6-macos-arm64.tar.gz.sha256) | ARM 原生全量 CI 验收通过 |
| macOS Intel | [下载 tar.gz](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.6/ai-security-runtime-v0.3.6-macos-x64.tar.gz) | [SHA256](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.6/ai-security-runtime-v0.3.6-macos-x64.tar.gz.sha256) | Intel 原生全量 CI 验收通过 |

[完整 SHA256 清单](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.6/SHA256SUMS.txt) · [机器可读发行清单](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.6/release-manifest.json) · [验收证据 ZIP](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.6/ai-security-runtime-v0.3.6-release-evidence.zip)

[发布工作流](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/39231001213)已通过 Windows / macOS 全量测试、规则质量、合规、包完整性与三平台原生安装包验收。原生验收包含无外部 Python 启动、扫描组件准备、样例扫描、受管 Skill、MCP、隔离安装生命周期及合成修复与 Hook 流程。

合成 SDK / Hook 场景不是实际桌面操作；macOS 真机、Cursor 桌面、苹果签名与公证等仍按[支持边界](./reference/support.md)单独认定。安装包通过检查也不代表任何用户项目已完成漏洞检查。

::: warning 不要混用旧候选与新发行
此前本地 `c526cdd` 候选和 v0.3.4 旧发行不等于本次发行。请使用本页平台包及其配套校验，不将旧候选的 SHA256 或其他版本 Skill 套用到新包。
:::

## 校验后再安装

下载包与同名 SHA256 文件后，核对文件名与摘要。

Windows：

```powershell
Get-FileHash .\ai-security-runtime-v0.3.6-windows-x64.zip -Algorithm SHA256
Get-Content .\ai-security-runtime-v0.3.6-windows-x64.zip.sha256
```

macOS：在对应包与 `.sha256` 文件所在目录执行：

```sh
shasum -a 256 -c ai-security-runtime-v0.3.6-macos-arm64.tar.gz.sha256
```

Intel 换为 `macos-x64`。摘要用于检查下载完整性，不代替发布者身份、系统签名或平台兼容性验证。

完整解压后按[快速开始](./guide/quickstart.md)安装。macOS 签名、公证、真机与宿主验收不能用一次交叉编译或校验和替代。
