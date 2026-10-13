# 安装后自动后台准备与待检接续（2026-10-13）

本批复用既有扫描器准备、公共漏洞库下载、旧缓存、真实字节进度、动态续等、无进展超时和绝对最长等待。安装只做本地激活、配置部署和缓存检查，成功后启动隐藏后台进程并返回；不再要求普通用户手工执行前置准备命令。离线安装不联网。

## 下载期间的行为

- Hook 和主动扫描在后台尚未就绪时只使用本地可用组件；不会同步等待下载，也不会另起一次下载。
- 已检出的风险继续展示；缺失、失败及有限覆盖如实保留，零发现不能证明安全。
- 快速扫描与 Stop 通过既有 `CloseoutService` 登记 `closeout_ref`、范围、代次和原检测器规则。等待下载不消耗收尾执行次数；Stop 不因此阻塞编码。
- 后台完整准备取得有效回执后，通过本机普通 MCP 执行 `run_closeout_check`。不调用 Hook 处理器，不编辑源码，不扩大修复授权。
- 续检仍使用原收尾锁、租约、版本、检查代次和逐规则关闭证明。文件或事件再次变化，旧结果不能清除新的待检项。
- 准备失败保留旧缓存与原收尾记录。后续重新安装或显式重试复用缓存；锁忙、扫描失败和预算耗尽不会无限自动重试。

## 状态和进度

后台状态持久化，关闭安装终端不会取消下载。安装回执与扫描就绪分开。`preparation watch` 是可选进度查看入口，不是准备命令：交互终端复用原单行进度条与真实网速估算；`preparation status --json` 和普通 MCP `get_scan_preparation_status` 可读取相同状态。没有新字节进展时预计时间失效，不显示虚假倒计时。

下载仍为初始 300 秒、按实际进度续等、最长 1800 秒；无进展 30 秒停止当前来源并按既有逻辑切换官方来源。后台续检为有界一次遍历，累计最多 300 秒，每次普通 MCP 最多 120 秒。未完成项保留原收尾状态。

## 本地验收步骤

在项目根目录 `C:\Users\24170\Desktop\AI-security-check`，使用本批交付的新构建执行一次普通安装，**不加 `--offline`，不运行 `prepare-scanners`**。程序安装返回后，应显示后台准备已经安排，不能在漏洞库下载期间一直占住安装。

```powershell
$bundle = (Resolve-Path 'dist/background-prep-20261013-r2/security-check').Path
& "$bundle/security-check.exe" install codex --bundle $bundle
# 可选：只查看正在自动进行的准备，不会重新启动下载。
& "$bundle/security-check.exe" preparation watch
& "$bundle/security-check.exe" preparation status --json
```

完全退出并重启 Codex，接受宿主的 Hook 信任提示。在安全的人工验收样例项目中，下载尚未完成时编辑一个文件，并要求快速检查；观察可用组件的结果、缺失项等待准备提示和保留的待检任务。不要使用真实凭据或真实 `.env`。

准备完成后无需再次发送“继续检查”：已登记的任务应自动取得收尾回执。再读文件应复用有效状态；在下载或续检期间再次编辑，应以最新版本检查或保留未完成，不能误报关闭。重复安装和重复 Stop 不应产生并行下载；首次失败后旧缓存应仍可用。

如果本机已有新鲜缓存，准备会直接复用，可能很快结束，没有下载进度条属正常。验证下载期间行为请用脚本创建独立配置和空的隔离缓存，不要清理或改写真实缓存：

```powershell
python scripts/background_preparation_acceptance.py --bundle dist/background-prep-20261013-r2/security-check --output artifacts/your-new-background-test --tools "$env:LOCALAPPDATA/AI-Security-Runtime" --old-db "$env:LOCALAPPDATA/AI-Security-Runtime/cache/trivy/db"
```

此脚本使用现有兼容组件、新的隔离缓存和普通 MCP，编辑的是静态样例。它不替代真实 Codex 桌面 Hook 验收；原缓存只作前后摘要核对。

检查完成、覆盖完整、风险关闭分别核对。特别关注两个原凭据规则各自的证据，以及 Vue/TypeScript 部分覆盖与凭据确认关闭同时成立。

## 验收记录

交付候选：`dist/background-prep-20261013-r2/security-check`，Runtime 0.3.2；构建
`41b98a66041f668329c98fdf093f632713d9babc96d06e9ac29de63d94e092ac`，源码
`c0cfd7bbf6dbc7723a270ae9f54c341d76a27b2a`，`source_dirty=false`。
本地 ZIP：`dist/experience/ai-security-runtime-v0.3.2-background-prep-20261013-r2-windows-x64.zip`，
SHA-256 `f044c11d9dcce79a35711f2d60e3d8311c1fa7c5f3d68e7fbd07ee4642e1e12e`；基础验收通过，未运行 full 发行验收。

最终受影响回归166通过、2跳过，235.46秒。另一次广泛回归486通过、4跳过、1个偶发初始化失败；
该项独立复验1通过，并在最终全局路由分组中通过。更早的受限权限和父Git目录失败记录保留，
不称为全量项目套件全部通过。

同 r2 包真实普通安装17.922秒、重复10.250秒，首反馈0.266秒；两次复用同一后台 job。
实际全局路由普通 MCP 快速扫描9.546秒，下载期间只用可用组件，生成原 closeout_ref 待检，
尚未执行收尾、attempts=0；源文件变化后原计划不再是当前版本。
后台在线准备781.437秒，默认初始300秒/最长1800秒，`adaptive=true`；先GHCR，随后官方镜像，
共2个来源调用、1轮。最终3组件就绪、漏洞库FRESH，更新于2026-10-13T06:41:11Z，
有效期至2026-10-14T06:41:11Z，验证后才启用隔离新库。实际观察370份进度状态及网速驱动ETA。
真实 Windows 终端 watcher 捕获410次进度刷新、434个CR，下载更新使用同一行，阶段/换源/验证另行换行；
watch只读状态，没有再次启动下载。

准备完成后，后台自动通过普通 MCP 执行原收尾任务，源为 `MANUAL_QUICK_PREPARATION_PENDING`、
执行来源为 `BACKGROUND_PREPARATION_MCP`。未手动执行prepare-scanners/run_closeout_check，未手工调用Hook处理器。
收尾8.568秒，代次1→2、当前版本有效；随后再次编辑，旧回执正确失效。
没有原凭据风险的样例中关闭确认耗时0.338毫秒只代表空范围，不冒充两规则风险关闭真实验收。
原缓存和配置摘要及配置修改时间保持，全局安装未改变。
同包新鲜缓存复用：安装18.735秒，后台核对6.484秒，来源调用0，没有重复下载。

真实证据仅在本机 `artifacts/br2/result.json`、`progress.json`、`watch-terminal.txt`，
暖缓存证据在 `artifacts/br1/r2-warm-install.json`、`r2-warm-preparation.json`。
首个r1验收因真实缓存已新鲜、原先的STALE假设不成立而未通过下载前提；现场保留，未伪造过期metadata。
本次使用全新隔离空缓存下载，现有兼容引擎复用；不是冷机器所有组件首次下载验收。

同步 Hook 检查、Hook安排的Stop收尾、用户手动独立复查，与本次后台准备后的普通MCP续检分别记录。
**同构建包真实Codex桌面自动Hook→Stop链路：尚未通过；用户聊天提示延迟：未测得。**
需按前述步骤由实际重连后的Codex桌面补验，不把单元模拟或本次普通MCP结果当作通过。

用户已明确确认本批31份源码、测试和开发规划文件同步至私有仓库
`pikachu-cxy/Ai-security-check`、`feature/runtime-mvp`分支。通过已连接账号同步，
远端已有提交保留，写入前后核对分支版本和文件树；不上传安装包、漏洞库、用户配置或原始扫描日志。
安装包冻结于本地源码提交 `c0cfd7bb…`，后续文档提交仅补充验收/接续记录，不改变其构建身份。

现场核对：旧构建目录、真实安装及缓存未清理；本次未删除项目文件。
用户指定保护的 `docs/20260904/CRM人工测试（20260904）.docx` 当前工作区及本地Git历史未找到，
不能声称已保存在本机或随仓库同步；如原文件在其他电脑，应继续保留，不因本批覆盖或删除。
