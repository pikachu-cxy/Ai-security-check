# 安装、使用与反馈

更新：2026-10-21。当前版本为 **0.3.9 正式版**，支持 Windows x64、Mac Apple Silicon（M 系列）与 Intel。下载以 [v0.3.9 Release](https://github.com/pikachu-cxy/Ai-security-check/releases/tag/v0.3.9) 的实际公开资产为准；三平台使用同一发布提交。

程序在本机检查项目，宿主聊天工具自身的数据处理按其设置。源码开发安装、原生完整包和独立 Mac 自动安装分别核对构建身份；原生 CI 验收与真实桌面、Apple 签名和公证分别认定。

## 选择模式和安装包

当前发行版本为 0.3.9 / 正式版。平台包命名示例为 `ai-security-runtime-v0.3.9-macos-arm64.tar.gz`；
请从 README 或文档站下载页选择已发布的完整平台包，并核对同版本配套 SHA256 文件。

| 模式 | 内容 | 适用 |
|---|---|---|
| Codex自动接入 | MCP、全局Hook、配套Skill | 普通开发任务自动核查、最终提示、选择修复 |
| 仅MCP | 本地stdio工具，绑定一个项目 | 在聊天中主动调用核查/审查工具，不安装Hook或Skill |

维护者给试用者完整压缩包、同名.sha256校验文件和本指南。包内 security-check 目录含程序、version.json、许可证和第三方声明，保留完整目录。
Windows x64：windows-x64.zip。Apple Silicon（M1/M2/M3/M4等）：macos-arm64.tar.gz；Intel Mac：macos-x64.tar.gz。在 Mac 终端用 uname -m 区分 arm64 与 x86_64。
同一版本号可能对应不同构建；比较 version.json 的 source_commit、source_dirty=false、build_id。同组试用须同源码提交，操作系统的build_id可以不同。
下载或拿到包不等于已经扫描；安装接入成功也不等于漏洞库准备完成。

## Windows：Codex自动接入

1. 校验包：在 PowerShell 运行 Get-FileHash .\ai-security-runtime-*.zip -Algorithm SHA256，与维护者提供的同名.sha256核对；有多包时选择准确文件名。
2. 解压完整ZIP，在含 security-check 子目录的解压目录打开普通 PowerShell。完全退出 Codex。
3. 执行：
```powershell
$bundle = (Resolve-Path '.\security-check').Path
$exe = Join-Path $bundle 'security-check.exe'
Get-Content "$bundle\version.json" -Raw | ConvertFrom-Json |
    Select-Object version,source_commit,source_dirty,build_id
& $exe install codex --bundle $bundle --json
if ($LASTEXITCODE -ne 0) { throw '安装未完成：保留回执，不删除其他配置' }
& $exe preparation watch
& $exe prepare-scanners --status --json
```
默认联网，复用有效缓存，自动后台准备缺失组件及过期数据。看到安装完成且下载中时等待即可；以准备回执 ready=true、vulnerability_db.freshness=FRESH 为依赖能力就绪依据。
进度有进展会延长等待，但有总上限。一次本机下载约15分钟只是该次测量；速度、镜像与网络会改变耗时。不要同时反复启动下载。
4. 完全重启 Codex。查看MCP连接与三个Hook启用；在一个单独聊天只核对实际连接的构建身份，不扫描。与包的build_id一致后，在真实项目开新聊天。
5. 发普通开发需求，不需要点名产品。最终查看风险依据、防护、未知范围，以及 **修复**／**暂不处理**。多个问题要指明具体项；“修复全部本轮已登记风险”才是明确批量选择。

## macOS：Codex自动接入（真机待验）

使用同提交CI构建的对应架构完整.tar.gz及.sha256。不要安装未经核验的其他构建。
终端在收到的文件目录执行（替换成实际文件名）：
```bash
uname -m
shasum -a 256 ai-security-runtime-v0.3.9-macos-arm64.tar.gz
tar -xzf ai-security-runtime-v0.3.9-macos-arm64.tar.gz
cd security-check
bundle="$(pwd)"
exe="$bundle/security-check"
"$exe" --version
cat "$bundle/version.json"
# 完全退出Codex后：
"$exe" install codex --bundle "$bundle" --json
"$exe" preparation watch
"$exe" prepare-scanners --status --json
```
Intel Mac选择macos-x64文件名。每条命令失败就保存输出并停止后续安装步骤；不能把失败的第一条安装当作完成。
若系统阻止启动，记录系统提示，在系统允许的单个应用打开流程中核对包身份；不要全局关闭Gatekeeper/系统保护。本批包没有承诺Apple开发者签名或公证；此限制必须在试用回执中明确。
组件 ready 和漏洞库 FRESH 后，完全重启Codex，按Windows第4、5步核对连接和使用。维护者要求Mac试用者先完成本节全链路，未通过前不把Mac整个平台记为通过。

## 仅MCP模式：Windows/macOS

此模式独立使用可执行程序，不运行 install codex，不安装Hook或Skill。支持能启动本地stdio进程的聊天客户端；当前产品未配置远程HTTP服务器。
配置生成器当前绑定已存在的本地Git项目；先确认项目目录正确，不把用户主目录当项目。浏览器里的普通远程聊天不能直接启动本机stdio程序。
先准备检查器，然后生成绑定该项目的配置（实际项目绝对路径替换下文占位；Windows保留PowerShell路径变量）：
```powershell
# Windows，在完整解压包目录：
$exe = (Resolve-Path '.\security-check\security-check.exe').Path
$project = 'C:\Projects\your-project'
& $exe prepare-scanners
& $exe prepare-scanners --status --json
& $exe mcp config --path $project --toml
# 其他支持mcpServers JSON配置的本地客户端：
& $exe mcp config --path $project --json
```
```bash
# macOS，在security-check目录：
exe="$(pwd)/security-check"
project="$HOME/Projects/your-project"
"$exe" prepare-scanners
"$exe" prepare-scanners --status --json
"$exe" mcp config --path "$project" --toml
"$exe" mcp config --path "$project" --json
```
把生成的整个 ai_security_runtime TOML小节合并到 Codex 用户 ~/.codex/config.toml（Windows为用户目录下.codex/config.toml）；保留其他服务和设置。不要复制别人的用户名、UUID或临时路径，也不要覆盖整个文件。
配置包含可执行程序的绝对路径、args=["mcp"]和项目环境。不要移动这个目录；要移动时重生成配置。重新连接/重启后，在该项目聊天中先说：
“使用已连接的安全核查工具检查当前项目，只报告结果，不修改代码；依赖数据或范围不完整请明确说明。”
这个提示词是纯MCP主动调用验收；自动接入的开发盲测使用普通需求，不点名产品。
换项目时重生成绑定该项目的配置；不要把一个项目的引用交给另一个项目。工具列出成功不等于扫描运行，核对实际检查回执。
Codex的stdio配置形态和MCP使用方式参考[官方文档](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)。不同客户端的配置入口按客户端文档；本批主要验收Codex。

## 接入与自动检查诊断

重启后先确认 MCP 已连接，再只读取连接的版本、source_commit 和 build_id，与包内 version.json 核对；这一步不扫描。普通开发任务完成后，应能看到实际检查结果或明确的未完成说明。需要进一步确认自动检查时，在前面已经设置好 `$exe` 的终端读取当前项目的最近 Hook 诊断：

```powershell
& $exe hooks recent --path 'C:\Projects\your-project' --limit 32 --json
```

```bash
"$exe" hooks recent --path "$HOME/Projects/your-project" --limit 32 --json
```

替换为实际项目路径，核对项目、时间和实际执行状态。没有记录时还要核对状态目录和保留期限，不能直接断言没有触发。Codex 生命周期 Hook 与 Git 提交 Hook 不同；Git 提交 Hook 默认关闭、常规帮助隐藏，默认安装保留已有 Git Hook。

离线和缓存说明见[个人安装指南](guides/PERSONAL_INSTALL_AND_GUIDANCE.zh-CN.md#安装缓存与增量升级)。当前没有在线产品自动下载更新器，也没有漏洞库持续定时刷新服务；不要把计划中的云端更新能力当作可用功能。

## 升级、重试和卸载

仍在下载且持续有进展时只观察。失败、工作进程中断或以后过期：
```powershell
& $exe preparation retry
& $exe preparation watch
& $exe prepare-scanners --status --json
```
Mac用 "$exe" 替代 & $exe。当前没有持续定时更新服务，之后需要核对数据是否仍FRESH；不需要重装来更新库。
升级时用维护者给的新完整包执行同一 install codex 流程；完全重启宿主，核对新build_id。存在用户改动/未知配置归属时保存诊断，不手动删除其他服务。
Codex接入卸载：完全退出Codex，再执行：
```powershell
& $exe uninstall --json
& $exe review-skill remove --json
```
Mac用 "$exe" 替代 & $exe。卸载接入和Skill保留程序槽位、数据与扫描历史，不是清空个人数据。仅MCP模式移除自己添加的小节并关闭连接即可；程序目录需要自行保留或删除，先确认客户端已停止使用。

## 试用安排与反馈

先邀请1位Windows用户；该用户完成安装、准备、新聊天开发、全部风险选择、逐项修复/复查和卸载，再扩到3–4人。至少安排1位Mac用户完成真机步骤；暂缺Mac时保留平台待验，不能宣布跨平台试用验收完成。
每人使用干净独立项目，普通需求首轮不告知风险、不预先扫描。保存首次最终回复和总耗时，再选择修复。若对比不加载/加载，用相同初始代码的两份副本。
每轮记录：OS/架构、Codex版本、模型设置、source_commit/build_id、模式、组件与库新鲜度、实际改动范围、静态/上下文执行、风险总数与逐项关闭结果、漏检误报、开发/修复耗时。
修复后应列出每个原风险：原规则已复查、代码复核完成、仍存在或未核实；不能以新任务零发现替代旧13项关闭。依赖“声明版本指定漏洞消除”与完整图、安装/完整性分别记录。
提交反馈前脱敏源码、用户名、凭据和私有业务数据。测试密钥为合成值；真实密钥撤销/历史泄露处理另行由持有者处理，产品不声称已撤销。
Windows示例项目与生成器见[全链路手测](RUNTIME_CHAIN_REGRESSION_ACCEPTANCE.zh-CN.md)。维护者发新项目给试用者，答案留在项目之外；不要用已开发完的旧目录冒充首轮。

## 当前源码候选

本次工作区候选为0.3.6，增加安全修复功能影响评估；Windows验收请使用 artifacts/repair-impact-latest.json 成功回执指定的完整本地包，
不要重新下载上文旧发布包来验证新修复。候选Mac ARM归档命名为
ai-security-runtime-v0.3.6-macos-arm64.tar.gz；该命名不表示已发布或完成Mac真机验收。
见 [修复影响安装与验收](RUNTIME_CHAIN_REGRESSION_ACCEPTANCE.zh-CN.md)。
