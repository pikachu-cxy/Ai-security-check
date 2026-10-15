# AI Security Runtime

在 AI 编程聊天中检查本次开发改动，结合静态检查与 Agent 对关联代码的分析，说明风险依据、当前防护和未知范围。你决定 **修复** 或 **暂不处理**；Agent 修改代码，Runtime 复查原问题并记录逐项结果。

当前为 **Developer Alpha 试用版**，主要试用宿主是 Codex。源码在本机检查，首次准备扫描组件和漏洞数据需要联网。完整安装包自带 Python，**无需安装 Python、pip 或 venv**，也不会安装你的项目依赖或启动项目服务。

## 安装到 Codex：三步

### 1. 下载并解压完整包

当前发布版为 [v0.3.4](https://github.com/pikachu-cxy/Ai-security-check/releases/tag/v0.3.4)。按系统下载：

| 系统 | 下载完整包 |
| --- | --- |
| **Windows x64（优先试用）** | [ai-security-runtime-v0.3.4-windows-x64.zip](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.4/ai-security-runtime-v0.3.4-windows-x64.zip) |
| Mac：Apple Silicon（M1/M2/M3/M4 等） | [ai-security-runtime-v0.3.4-macos-arm64.tar.gz](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.4/ai-security-runtime-v0.3.4-macos-arm64.tar.gz) |
| Mac：Intel | [ai-security-runtime-v0.3.4-macos-x64.tar.gz](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.4/ai-security-runtime-v0.3.4-macos-x64.tar.gz) |

解压到一个新文件夹，保留完整的 `security-check` 子目录；不要下载 GitHub 的 **Source code** 包或只复制可执行文件。[SHA256 校验方法见下方](#下载校验与详细操作)。Mac 不确定芯片型号时查看“关于本机”。Linux 暂不发行。

### 2. 退出 Codex，执行两条命令

在**包含 `security-check` 子目录的解压文件夹**中打开普通 PowerShell，逐条执行；任何一步失败就停止，按[详细指南](docs/PILOT_INSTALL_AND_USE.zh-CN.md#升级重试和卸载)处理。

```powershell
.\security-check\security-check.exe install codex
.\security-check\security-check.exe preparation watch
```

第一条安装 MCP、Codex 生命周期 Hook 和配套 Skill，并自动在后台准备检查组件；第二条等待准备结果。看到 **“扫描能力已准备完成”** 再继续，下载中或失败都不表示检查已就绪。

<details>
<summary>Mac：解压后使用这两条命令</summary>

完全退出 Codex，在包含 `security-check` 子目录的解压文件夹打开终端，逐条执行：

```bash
./security-check/security-check install codex
./security-check/security-check preparation watch
```

Apple Silicon 与 Intel 使用相同命令，下载包按上表选择。若系统阻止运行，保存提示并参考[Mac 详细步骤](docs/PILOT_INSTALL_AND_USE.zh-CN.md#macoscodex自动接入真机待验)；当前没有 Apple 开发者签名／公证承诺，不要关闭系统安全检查。macOS CI 与试用者真机验收分别记录，维护者暂无 Mac 真机，平台限制见[开发进度](docs/DEVELOPMENT_PROGRESS.md)。

</details>

### 3. 重启 Codex，确认接入

完全重新打开 Codex，在实际项目目录创建新聊天，先发：

> 请只核对已连接的 ai_security_runtime 的版本和构建身份，不扫描、不修改代码。

确认 MCP 已连接，返回版本为 **0.3.4**，构建身份与解压包的 `security-check/version.json` 一致。连接成功只代表已接入；发一个普通开发需求后，最终回复应说明实际安全核查结果或未完成的范围，不能把“工具已列出”当作检查已运行。

之后正常提开发需求，无需额外说“使用 ai-security 扫描”，也不要求 `git commit`。有风险时，查看依据、防护、触发条件和未知范围，再选择 **修复／暂不处理**。多个问题要指明具体项；批量修复需明确说“修复本轮全部已登记风险”。暂不处理保留记录，修复后逐项区分复查通过、仍存在和验证未完成。

Git 提交 Hook **默认关闭、常规帮助隐藏**；默认安装保留已有 Git Hook。

## 下载校验与详细操作

<details>
<summary>校验下载包（安装前）、升级、卸载、离线和故障排查</summary>

安装前下载 [v0.3.4 SHA256SUMS.txt](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.4/SHA256SUMS.txt)，在下载目录计算对应压缩包的 SHA256，与清单中同名文件核对：

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath .\ai-security-runtime-v0.3.4-windows-x64.zip
```

Mac 使用 `shasum -a 256 ai-security-runtime-v0.3.4-macos-arm64.tar.gz`，Intel 将文件名中的 `macos-arm64` 换为 `macos-x64`。不一致时不要安装。

- [详细安装、准备状态、重试、升级和卸载](docs/PILOT_INSTALL_AND_USE.zh-CN.md)：需要诊断时核对组件整体 `ready=true` 与漏洞库 `FRESH`；仍在下载时依赖检查未完成。升级使用新 Release 的完整包重复安装，再重启核对构建身份。
- [离线安装、缓存与本地差分包](docs/PERSONAL_INSTALL_AND_GUIDANCE.zh-CN.md#安装缓存与增量升级)：离线只复用已有可用缓存，不能从零准备缺失组件。当前没有在线产品自动下载更新器，也没有漏洞库持续定时刷新服务。
- [Hook 诊断与使用反馈](docs/PILOT_INSTALL_AND_USE.zh-CN.md#接入与自动检查诊断)：确认项目、时间和执行状态；没有记录不能直接断言没有触发。

卸载接入和 Skill 保留程序数据与检查历史。遇到未知配置冲突时保留诊断，按详细指南处理，不手动删除其它服务。

</details>

<details>
<summary>其它客户端／仅 MCP 接入（按需）</summary>

如只需主动调用工具，或客户端使用本地 stdio MCP，请看[仅 MCP 模式](docs/PILOT_INSTALL_AND_USE.zh-CN.md#仅mcp模式windowsmacos)：跳过 `install codex`，准备组件后生成项目配置，合并进客户端并重连。此模式不安装 Hook 或 Skill；普通浏览器远程聊天不能直接启动本机程序，自动调用取决于客户端行为。本批主要验收 Codex，其它客户端不承诺相同自动核查体验。

</details>

反馈到 [Issues](https://github.com/pikachu-cxy/Ai-security-check/issues)：提供系统／架构、版本和构建身份、失败步骤及准备状态。分享前去除私有代码、真实密钥和个人路径。

## 检查范围与开发资料

支持 Java、Python、JavaScript／TypeScript 的已安装规则子集、密钥检测、可识别依赖版本和有界关联代码分析。没有发现问题不证明项目安全；未支持输入、缺失组件、上下文预算和未知部署条件须保留。声明版本的原公告复查通过，不代表完整依赖图或实际部署安全。

- [详细安装使用指南](docs/PILOT_INSTALL_AND_USE.zh-CN.md)
- [开发进度与限制](docs/DEVELOPMENT_PROGRESS.md)、[下一步计划](docs/NEXT_DEVELOPMENT_PLAN.zh-CN.md)
- [规则范围](docs/RULE_FOUNDATION.md)、[覆盖矩阵](docs/RULE_COVERAGE_MATRIX.md)
- [开发交接](docs/DEVELOPMENT_HANDOFF.zh-CN.md)
- [许可说明](LICENSING.md)、[使用条款](EULA.md)、[第三方声明](THIRD_PARTY_NOTICES.md)

安装入口为 Releases 完整包，Homebrew／winget 外部上架不作为试用安装前提。
