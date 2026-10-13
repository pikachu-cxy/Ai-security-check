# 安装与扫描能力准备验收

更新日期：2026-10-13。程序安装、扫描就绪、真实宿主加载分别验收。旧安装、有效缓存、历史扫描和基线保留。

## 新入口及退出码

| 操作 | 行为 | 成功或未就绪 |
| --- | --- | --- |
| `install codex --bundle <bundle>` | 安装并核对程序、全局连接、Skill；只检查已有工具和缓存 | 本地安装通过返回 0；`scan_ready` 独立报告。程序/配置失败返回 2 |
| `prepare-scanners` | 单独准备缺失组件、刷新过期漏洞库 | 全部就绪返回 0；不完整返回 2；取消返回 130 |
| `prepare-scanners --status --json` | 只读核对本机工具及数据有效期，不下载 | 就绪返回 0，否则 2；不把旧回执当成当前证明 |
| `prepare-scanners --offline` | 只核对本机组件与缓存 | 过期或损坏数据继续显示未就绪 |

默认准备总预算 300 秒；数据库连续 30 秒没有新增的传输进度就停止。默认不重复下载整包。显式 `--timeout 600 --idle-timeout 60 --retries 1` 可允许一次额外尝试，但仍共用总预算。进程终止和最后缓存核对有少量收尾时间，不承诺毫秒级退出。

数据来自现有 Trivy 下载器和官方来源，不另建漏洞库下载或扫描流程。实时界面只接收固定类型、原组件身份、有限数值和脱敏原因；未知进度不伪造百分比。JSON stdout 保持单个回执，stderr 展示真实传输量、尝试、剩余预算和失败原因。默认无断点续传，重试会明确说明重新下载。

## 本地安装步骤

在项目根目录 `C:\Users\24170\Desktop\AI-security-check`，将 `$bundle` 指向本批报告记录的新目录，避免使用旧会话中的变量：

```powershell
$bundle = (Resolve-Path 'dist/install-flow-20261013-r2/security-check').Path
$exe = Join-Path $bundle 'security-check.exe'
& $exe runtime-info --json
& $exe install codex --bundle $bundle --json
$LASTEXITCODE
& $exe prepare-scanners --status --json
$LASTEXITCODE
& $exe prepare-scanners --timeout 300
$LASTEXITCODE
& $exe prepare-scanners --status --json
```

核对报告中的完整 build_id。安装返回 0 时仍检查 `installation.local_files_ready` 和 `installation.scan_ready`；后者为 false 时先查看各组件和漏洞库日期。下载未完成可稍后只重跑 `prepare-scanners`，不必复制程序或重装连接。按 Ctrl+C 取消准备；已有配置和可用旧库应保留，未确认的数据继续显示未就绪。

准备后完全退出并重启 Codex，审核宿主 Hook 信任；通过普通 MCP `get_runtime_info` 核对运行包身份。源码、CLI 和隔离 MCP 通过不能替代这个桌面步骤。真实自动 Stop 收尾验收仍按 [收尾验收](RUNTIME_CLOSEOUT_CHECK.zh-CN.md) 单独记录，人工续发消息不算自动通过。

## 开发者隔离验收

```powershell
& $python scripts/install_flow_acceptance.py --bundle $bundle --output artifacts/install-flow-20261013/frozen-r2
& $python scripts/closeout_mcp_acceptance.py --executable "$bundle/security-check.exe" --engine-root artifacts/closeout-20261012/mcp-engines --output artifacts/install-flow-20261013/mcp-r2
```

第一项使用隔离的中文/空格目录、真实安装包与普通 MCP，验证程序安装和未就绪拆分、重复安装幂等、只读检查以及包身份；不触碰真实宿主配置。可额外传入 `--tool-root` 和 `--cached-db`，复制公开旧漏洞库到隔离缓存并执行限时真实网络诊断。短预算诊断未完成不算完整在线准备通过；成功、失败、缓存保留和耗时须按真实输出记录。

单元回归覆盖慢速/无进展、CR 进度行、默认不盲目重试、显式有限重试、预算共用、取消清理进程、锁忙、旧库保留、校验失败不激活及分开的退出码。本批实际结果及构建标识记录在 [开发进度](DEVELOPMENT_PROGRESS.md)；界面用户提示延迟取得不到就写“未测得”。
