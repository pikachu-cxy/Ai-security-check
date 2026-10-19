# 下载与构建状态

## 当前候选：0.3.6

源码基准为默认分支 `feature/runtime-mvp` 的 `c526cdd3d6c6923e04d64334c5dc19c0908cef31`。本次已在隔离工作树中构建 Windows 完整包；本地交付不等于 GitHub Release 已发布。

| 平台 | 文件名 | 当前状态 |
| --- | --- | --- |
| Windows x64 | `ai-security-runtime-v0.3.6-windows-x64.zip` | 约 26.1 MiB，本地包级冒烟通过；公开上传待完成 |
| macOS Apple Silicon | `ai-security-runtime-v0.3.6-macos-arm64.tar.gz` | 需通过修正后的原生 CI 验证 |
| macOS Intel | `ai-security-runtime-v0.3.6-macos-x64.tar.gz` | 需通过修正后的原生 CI 验证 |

Windows 本地候选包 SHA256：

```text
3072ced5d079b88097797f0384eeafeeedf05c1b392e68f5df23d89eb93655c9
```

该值只对应本次本地候选 ZIP。后续 CI 重新构建应使用它自己的校验文件，不能混用。

本地包级验证包含无外部 Python 的原生启动、版本、受管 Skill 内容、MCP 工具与能力、工作区绑定、自检及隔离安装生命周期。这不是扫描引擎全量准备、真实桌面验收或漏洞检查结果；相应完整 CI 与手工验收仍分开记录。

公开入口：[GitHub Releases](https://github.com/pikachu-cxy/Ai-security-check/releases) · [三平台构建记录](https://github.com/pikachu-cxy/Ai-security-check/actions/workflows/standalone.yml)。没有通过验证的产物不应冒充正式发行。

::: warning 历史发行不等于当前源码
已有 v0.3.4 属于旧发行，不包含当前分支后续 v3 与恢复修复。不要将它与当前新版 Skill 混用。新版未上传前，本页不提供虚构的 v0.3.6 Release 下载链接。
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
