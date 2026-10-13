# 安装与扫描能力准备验收

更新日期：2026-10-13。程序安装、扫描就绪、真实宿主加载分别验收。旧安装、有效缓存、历史扫描和基线保留。

## 新入口及退出码

| 操作 | 行为 | 成功或未就绪 |
| --- | --- | --- |
| `install codex --bundle <bundle>` | 安装并核对程序、全局连接、Skill；只检查已有工具和缓存 | 本地安装通过返回 0；`scan_ready` 独立报告。程序/配置失败返回 2 |
| `prepare-scanners` | 单独准备缺失组件、刷新过期漏洞库 | 全部就绪返回 0；不完整返回 2；取消返回 130 |
| `prepare-scanners --status --json` | 只读核对本机工具及数据有效期，不下载 | 就绪返回 0，否则 2；不把旧回执当成当前证明 |
| `prepare-scanners --offline` | 只核对本机组件与缓存 | 过期或损坏数据继续显示未就绪 |

默认初始等待300秒；有增长的真实字节时，根据近期传输速度及预计剩余时间自动续等，
整个命令最长1800秒，所有组件、源与额外重试共享这个绝对上限。优先官方GHCR，失败后
显式切换官方Google镜像。每源默认一次，连续30秒未取得可验证传输进度时终止本源，
在剩余范围换源；这不证明网络字节绝对停止。接近100%后最多另等120秒解压/校验，
仍受命令上限约束，不再用网络idle杀死本地处理。显式
`--timeout 600 --max-wait 1800 --idle-timeout 60 --retries 1` 允许额外一轮、最多四次源调用。
需要严格固定等待时用 `--fixed-timeout --timeout 300`；进程终止和最后缓存核对有少量收尾时间。

数据来自现有 Trivy 下载器和官方来源，不另建漏洞库下载或扫描流程。实时界面只接收固定类型、原组件身份、有限数值和脱敏原因；未知进度不伪造百分比。JSON stdout 保持单个回执，stderr 展示真实传输量、尝试、剩余预算和失败原因。默认无断点续传，重试会明确说明重新下载。
Windows 无CR/LF的连续进度也按有界字节流解析，跨块拼接不重复计数；原始日志不进入用户反馈。
交互终端使用同一行进度条，显示实际传输量、百分比、近期速度与预估剩余下载时间，不逐秒新增行；等待新进度时保留
已有计数，阶段、换源、失败、取消与最后结果另行显示。窄窗口缩短为原百分比与进度条。
输出到文件或管道时只保存每次传输最后取得的真实进度，不写终端控制字符，也不逐秒刷日志。
父子程序之间的固定事件协议保持逐行 JSON，stdout 最终回执保持独立。
ETA用滚动真实字节delta计算，开始时显示估算中；10秒没有增长即停止使用旧速率，
网速变化会调整估算，不按旧ETA伪造倒计时。这个时间仅指传输，不保证整个准备完成。

## 本地安装步骤

在项目根目录 `C:\Users\24170\Desktop\AI-security-check`，将 `$bundle` 指向本批报告记录的新目录，避免使用旧会话中的变量：

```powershell
$bundle = (Resolve-Path 'dist/db-bar-20261013-r2/security-check').Path
$exe = Join-Path $bundle 'security-check.exe'
& $exe runtime-info --json
& $exe install codex --bundle $bundle --json
$LASTEXITCODE
& $exe prepare-scanners --status --json
$LASTEXITCODE
& $exe prepare-scanners
$LASTEXITCODE
& $exe prepare-scanners --status --json
```

核对报告中的完整 build_id。安装返回 0 时仍检查 `installation.local_files_ready` 和 `installation.scan_ready`；后者为 false 时先查看各组件和漏洞库日期。下载未完成可稍后只重跑 `prepare-scanners`，不必复制程序或重装连接。按 Ctrl+C 取消准备；已有配置和可用旧库应保留，未确认的数据继续显示未就绪。

旧版本若下载量持续增长但300秒耗尽，可运行 `prepare-scanners --timeout 900` 延长等待。
新版默认自动续等，`--timeout`设置初始等待，`--max-wait`设置绝对上限；最多1800秒。
2026-10-13 用户真实安装中已下载 78.43/126.98 MiB（61.8%）后预算耗尽，三个检查组件
兼容但旧库仍过期，整体未就绪。这次约0.26 MiB/s的传输不能用此前隔离80秒成功代替。
当前没有断点续传，重试会重新下载；进度条改善显示，不保证下载速度或完成时间。

准备后完全退出并重启 Codex，审核宿主 Hook 信任；通过普通 MCP `get_runtime_info` 核对运行包身份。源码、CLI 和隔离 MCP 通过不能替代这个桌面步骤。真实自动 Stop 收尾验收仍按 [收尾验收](RUNTIME_CLOSEOUT_CHECK.zh-CN.md) 单独记录，人工续发消息不算自动通过。

## 开发者隔离验收

本机 Windows 的长路径仍有限制；使用短的输出和临时目录，保留失败现场，不在深层报告目录中安装版本槽。
输出目录必须是新目录，已经存在时更换短名称。

```powershell
$env:TEMP = Join-Path $env:LOCALAPPDATA 'Temp'
$env:TMP = $env:TEMP
& $python scripts/install_flow_acceptance.py --bundle $bundle --output artifacts/if-new
& $python scripts/closeout_mcp_acceptance.py --executable "$bundle/security-check.exe" --engine-root artifacts/closeout-20261012/mcp-engines --output artifacts/db-bar-20261013/mcp-r2
```

第一项使用隔离的中文/空格目录、真实安装包与普通 MCP，验证程序安装和未就绪拆分、重复安装幂等、只读检查以及包身份；不触碰真实宿主配置。可额外传入 `--tool-root` 和 `--cached-db`，复制公开旧漏洞库到隔离缓存并执行限时真实网络诊断。短预算诊断未完成不算完整在线准备通过；成功、失败、缓存保留和耗时须按真实输出记录。

要求完整在线准备时，传入 `--prepare-timeout 300 --max-wait 900 --require-ready`，验证
跨初始预算的真实自动续等；脚本等待绝对上限及有限收尾，不再按初始预算杀死有效下载。
短预算诊断不要求READY时仍使用固定等待。失败返回非零并保存回执。
只把进程成功、新数据有效且可读、最终三组件和漏洞库都就绪作为通过，100%进度不是成功证明。
`preparation-progress.jsonl` 保存固定用户反馈和实际耗时，原公开缓存单独核对不变；隔离副本只在新库验证后更新。
旧内部 `prepare-installation` 仍输出旧字段集合，兼容此前安装器；公开入口回执增加实际来源、源调用次数和访问顺序。

单元回归覆盖慢速/无进展、CR 进度行、默认不盲目重试、显式有限重试、预算共用、取消清理进程、锁忙、旧库保留、校验失败不激活及分开的退出码。本批实际结果及构建标识记录在 [开发进度](DEVELOPMENT_PROGRESS.md)；界面用户提示延迟取得不到就写“未测得”。
