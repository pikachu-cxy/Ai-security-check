# AI Security Runtime

在 AI 编程聊天中检查本次开发改动，结合静态检查与 Agent 对关联代码的分析，说明风险依据、当前防护和未知范围。你决定 **修复** 或 **暂不处理**；Agent 修改代码，Runtime 复查原问题并记录逐项结果。

当前为 **Developer Alpha 试用版**，主要试用宿主是 Codex。源码在本机检查，首次准备扫描组件和漏洞数据需要联网。原生安装包自带 Python，**无需安装 Python、pip 或 venv**，也不会安装你的项目依赖或启动项目服务。

首版支持 **Windows x64、Mac Apple Silicon、Mac Intel**。Linux 发行与验收暂缓。

## 1. 在 Releases 下载完整包

打开 [Releases](https://github.com/pikachu-cxy/Ai-security-check/releases)，选择试用版本，在 **Assets** 下载对应安装包和同名 `.sha256` 文件。

| 系统 | v0.3.2 安装包 |
| --- | --- |
| Windows x64 | `ai-security-runtime-v0.3.2-windows-x64.zip` |
| Mac：Apple Silicon（M1/M2/M3/M4 等） | `ai-security-runtime-v0.3.2-macos-arm64.tar.gz` |
| Mac：Intel | `ai-security-runtime-v0.3.2-macos-x64.tar.gz` |

新版本的文件名随 Release 改变。Mac 运行 `uname -m`，`arm64` 选 ARM 包，`x86_64` 选 Intel 包。不要把 GitHub 的 **Source code** 压缩包当安装包；不要只复制可执行文件。若 Assets 没有对应包，该版本还未完成发布。

## 2. 选择使用方式

- **Codex 自动接入**：安装 MCP、Hook 和配套 Skill；发普通开发需求后检查，不用点名产品。继续第 3 节。
- **独立仅 MCP**：作为聊天内主动调用的工具，不安装 Hook 或 Skill。解压包后跳到第 5 节。

macOS CI 与试用者真机验收分别记录；维护者暂时没有 Mac 真机。[当前验收与限制](docs/DEVELOPMENT_PROGRESS.md)以实际回执为准。

## 3. 安装并等待检查组件就绪

先完全退出 Codex。以下假设安装包在用户“下载”目录，命令报错时先处理错误再继续。

### Windows：PowerShell

```powershell
$archive = Join-Path $env:USERPROFILE 'Downloads\ai-security-runtime-v0.3.2-windows-x64.zip'
Get-FileHash -Algorithm SHA256 -LiteralPath $archive
# 与下载的同名 .sha256 文件核对。
$destination = Join-Path $env:USERPROFILE 'Downloads\AI-Security-Runtime-v0.3.2'
Expand-Archive -LiteralPath $archive -DestinationPath $destination
$bundle = Join-Path $destination 'security-check'
$exe = Join-Path $bundle 'security-check.exe'
& $exe --version
& $exe install codex --bundle $bundle --json
& $exe preparation watch
& $exe prepare-scanners --status --json
```

### Mac：终端

以下以 ARM 包为例，Intel 将 `macos-arm64` 换成 `macos-x64`。

```bash
cd "$HOME/Downloads"
shasum -a 256 ai-security-runtime-v0.3.2-macos-arm64.tar.gz
# 与下载的同名 .sha256 文件核对。
mkdir AI-Security-Runtime-v0.3.2
tar -xzf ai-security-runtime-v0.3.2-macos-arm64.tar.gz -C AI-Security-Runtime-v0.3.2
bundle="$HOME/Downloads/AI-Security-Runtime-v0.3.2/security-check"
exe="$bundle/security-check"
"$exe" --version
"$exe" install codex --bundle "$bundle" --json
"$exe" preparation watch
"$exe" prepare-scanners --status --json
```

解压目标目录已存在时请换新目录，避免覆盖正在使用的程序。若 macOS 阻止运行，核对来源、校验值和系统提示后保存诊断联系维护者。当前没有 Apple 开发者签名／公证承诺，不要关闭系统安全检查。

**程序安装完成 ≠ 安全检查已准备完成。** 安装默认启动后台准备并先返回；等组件及整体 `ready=true`、漏洞库 `FRESH` 后再测试依赖漏洞。仍在下载时，依赖检查未完成。

准备失败或需要更新库：Windows 运行 `& $exe prepare-scanners`，Mac 运行 `"$exe" prepare-scanners`，完成后用 `prepare-scanners --status --json` 核对状态。当前没有持续定时更新服务，后续仍需核对新鲜度。无需重装项目依赖。

## 4. 在 Codex 正常开发

完全重新打开 Codex，在实际项目目录创建新聊天并确认 MCP 连接可用，发普通需求，例如：

> 在现有订单模块新增订单详情接口，复用服务和仓储，增加必要测试，完成后总结改动、验证结果和需要我决定的事项。

无需增加“使用 ai-security 扫描”。有待处理问题时，回复应显示 **有 N 项风险需要你决定**，说明代码依据、当前防护、触发条件和未知范围，并单独给出 **修复／暂不处理**。

多个问题请选择具体项；要批量修复，明确回复“修复本轮全部已登记风险”。暂不处理保留记录，不代表风险消除。修复总结应逐项区分复查通过、仍存在和验证未完成；规则复查与 Agent 代码复核的依据不同。

需要确认自动检查时，读取当前项目最近 Hook 诊断：

```powershell
& $exe hooks recent --path 'C:\Projects\your-project' --limit 32 --json
```

Mac 使用 `"$exe" hooks recent --path "$HOME/Projects/your-project" --limit 32 --json`。核对项目、时间和实际执行状态；没有记录时继续核对状态目录和保留期限，不能直接断言没有触发。详见[试用指南](docs/PILOT_INSTALL_AND_USE.zh-CN.md)。

## 5. 独立仅 MCP 模式

解压完整包并设置上面的 `exe`，**跳过 `install codex`**。先准备组件，再为已有本地 Git 项目生成配置。

```powershell
# Windows
$project = 'C:\Projects\your-project'
& $exe prepare-scanners
& $exe prepare-scanners --status --json
& $exe mcp config --path $project --toml
# 使用 mcpServers JSON 的客户端：将 --toml 换成 --json。
```

```bash
# Mac
project="$HOME/Projects/your-project"
"$exe" prepare-scanners
"$exe" prepare-scanners --status --json
"$exe" mcp config --path "$project" --toml
```

将生成的 `ai_security_runtime` 小节合并到 Codex 用户目录 `.codex/config.toml`，保留其他服务和设置。重启／重连后，在该项目聊天中发：

> 使用已连接的安全检查工具检查当前项目，只报告问题，不修改代码；说明实际检查范围，以及依赖数据和上下文尚未确认的部分。

此模式支持能启动**本地 stdio**进程的客户端，普通浏览器远程聊天不能直接启动本机程序。自动调用取决于客户端 Agent 的行为。配置绑定具体项目；换项目或移动程序目录后重新生成。[配置说明与官方参考](docs/PILOT_INSTALL_AND_USE.zh-CN.md#仅mcp模式windowsmacos)。

## 6. 升级、卸载与反馈

升级：下载新 Release 完整包，退出 Codex，用新包重复安装步骤，重启后核对版本和构建身份；源码拉取不等于程序升级。

卸载自动接入：Windows 运行 `& $exe uninstall codex --json`，Mac 运行 `"$exe" uninstall codex --json`。移除受管理接入和 Skill，保留程序数据与检查历史。仅 MCP 模式移除自己添加的配置小节即可。

反馈到 [Issues](https://github.com/pikachu-cxy/Ai-security-check/issues)：提供系统／架构、Release 和构建身份、失败步骤、耗时、组件／库状态、首次风险提示和逐项复查结果。分享前去除私有代码、真实密钥和个人路径。

## 检查范围与开发资料

支持 Java、Python、JavaScript／TypeScript 的已安装规则子集、密钥检测、可识别依赖版本和有界关联代码分析。没有发现问题不证明项目安全；未支持输入、缺失组件、上下文预算和未知部署条件须保留。声明版本的原公告复查通过，不代表完整依赖图或实际部署安全。

- [详细安装使用指南](docs/PILOT_INSTALL_AND_USE.zh-CN.md)
- [开发进度与限制](docs/DEVELOPMENT_PROGRESS.md)、[下一步计划](docs/NEXT_DEVELOPMENT_PLAN.zh-CN.md)
- [规则范围](docs/RULE_FOUNDATION.md)、[覆盖矩阵](docs/RULE_COVERAGE_MATRIX.md)
- [开发交接](docs/DEVELOPMENT_HANDOFF.zh-CN.md)
- [许可说明](LICENSING.md)、[使用条款](EULA.md)、[第三方声明](THIRD_PARTY_NOTICES.md)

当前安装入口为 Releases 完整包，Homebrew／winget 外部上架不作为试用安装前提。
