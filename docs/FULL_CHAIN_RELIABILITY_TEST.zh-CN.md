# 从重新安装到一次开发多风险的真实手测

更新日期：2026-10-14。开发分支 feature/runtime-mvp。本批同步源码、测试与文档；安装包、缓存、合成凭据样例和原始记录不上传Git。

## 本机已准备的项目

首要测试是同一轮普通开发需求中的多问题发现，而不是单项命中。两个匿名综合项目：

- C:\Users\24170\Desktop\AI-security-check\.tools\reliability-20261014-r2\workbench-01
- C:\Users\24170\Desktop\AI-security-check\.tools\reliability-20261014-r2\workbench-02

每个综合项目涉及六类常规业务操作（SQL、命令、文件、请求、HTML、记录解码）、合成凭据格式、锁定依赖版本和跨文件订单归属，共九类观察目标。一轮需求修改多个模块、包清单和测试，要求作为同一个开发任务完成。两项目顺序随机，一个包含混合缺口，另一个包含对应防护；不要提前打开答案。九类目标不等于保证九条规则命中，也不是完整OWASP Top 10覆盖。

父目录中另有flow-01至flow-20，覆盖上述单项及对照、500行之后的操作和只读静默，用于解释综合任务中的漏检、误报或取证不足。每个目录是独立Git项目；不要把父目录添加成一个项目，也不要复用已开发过的项目。

对应正常提示词在本机 artifacts/reliability-20261014-r2/prompts/workbench-01.txt、workbench-02.txt。RUNBOOK.md列出22个精确目录和对应提示词，RESULTS.csv用于记录。EVALUATION.md与answer-key.json仅在第一次最终回复保存后阅读，不能交给测试Agent。提示词不点名产品、不要求扫描，也不提前描述哪个实现有缺口。

源生成器 scripts/new_reliability_lab.py 可以在其他电脑或重复测试时重建新一组。合成凭据随机生成，不关联真实账号，不验证有效性、不上传样例。依赖对照依据[2021公告](https://github.com/advisories/GHSA-35jh-r3h4-6jhm)和[2026公告](https://github.com/advisories/GHSA-r5fr-rjxr-66jc)：4.17.20是受影响观察目标，4.18.0是这两项公告的修复对照，不声称没有其他漏洞。合成锁文件只用于声明/锁定版本读取，不代替生产安装生成的完整依赖图。

## 先固定程序身份

从系统开始菜单打开普通PowerShell，避免沿用Agent受限环境。当前源码另含后台命令行窗口修复、条件性风险登记及加粗提示。同步后将从本批提交构建 dist/fullchain-20261014-r1/security-check；已有历史本机安装为552de5dc…，不要只看共同版本号0.3.2。

```powershell
$repo = 'C:\Users\24170\Desktop\AI-security-check'
Set-Location $repo
$bundle = (Resolve-Path "$repo\dist\fullchain-20261014-r1\security-check").Path
$exe = Join-Path $bundle 'security-check.exe'
$installed = 'C:\Users\24170\AppData\Local\AI-Security-Runtime-install\launcher-v2\security-check.exe'
$package = Get-Content "$bundle\version.json" -Raw | ConvertFrom-Json
$package | Select-Object version, source_commit, source_dirty, build_id
git log -1 --oneline
git status --short
```

source_commit应等于本次同步提交，source_dirty应为False。若包目录不存在，先按接续文档的普通安装许可证元数据和独立构建流程构建，不能安装旧目录冒充最新源码。只读runtime-info不等于扫描执行。

## 重新卸载接入

完全退出Codex后，在上述系统PowerShell执行：

```powershell
& $installed uninstall --json
if ($LASTEXITCODE -ne 0) { throw '接入卸载未完成，查看回执，不手工删除配置' }
& $installed review-skill remove --json
if ($LASTEXITCODE -ne 0) { throw 'Skill卸载未完成，查看归属诊断' }
```

这是产品提供的全局连接/Hook和Skill移除流程；程序槽位、扫描记录与检查器缓存保留。不要删除整个.codex、.agents或用户数据目录。若报告用户修改/未知归属，保留并按具体恢复诊断处理。当前没有一条CLI命令清除全部个人数据；本轮验证重装和缓存复用，不冒充全新机器冷安装。

可在卸载后先重启Codex做不加载对照；需要预先复制整组干净项目，保持相同代码、模型与设置。不能在重新加载后继续用已开发目录对比完整开发耗时。

## 正常联网安装和自动准备

关闭对照聊天并完全退出Codex，然后执行默认联网安装，不加--offline：

```powershell
& $exe install codex --bundle $bundle --json
if ($LASTEXITCODE -ne 0) { throw '安装未完成，保留失败回执' }
& $installed preparation watch
& $installed prepare-scanners --status --json
```

默认安装校验并复制程序、全局接入和Skill，检查本地缓存后自动启动后台准备，不等待全部网络下载。local_files_ready=True与scan_ready=True是两项不同事实。有效缓存复用，缺失/过期数据需要后台下载。下载100%之后还需本地校验；以准备回执ready及vulnerability_db.freshness=FRESH判断，不能凭进度百分比或程序安装退出0判断全部就绪。

失败/中断或数据后来过期时，无需重装：

```powershell
& $installed preparation retry
& $installed preparation watch
& $installed prepare-scanners --status --json
```

仍未完成时，可在单独终端用 prepare-scanners 查看前台进度和具体原因；不得在后台任务仍运行时重复启动。默认初始等待300秒、有进展才续等、绝对上限1800秒。断网、锁忙、过期或数据未知应保留PARTIAL/未执行，不能包装成安全。当前没有持续定时更新服务，安装时就绪不保证以后永远新鲜。

本轮特别观察：下载是否弹出额外命令行窗口，进度是否持续可见，网络失败原因是否明确，重试是否保留原有缓存。此处不要求关闭任何下载子进程窗口来验证；失败/断网测试在正常试验记录保留之后再做。

## 重连和实际宿主身份

完全退出并重启Codex，核对全局Hook启用和MCP连接。先用一个独立身份核对聊天确认实际get_runtime_info的build_id与$package.build_id一致。该核对不是正式开发提示词，不扫描项目。只核对CLI身份不能证明现有MCP进程重连；发现旧构建时刷新连接或重新建聊天，不能把旧进程的结果算到新包。

进入综合项目分别新建聊天。第一次正式需求前不要手动扫描或先改文件；让产品自动完成基线和核查。每轮发送对应提示词一次，保存第一次最终回复，不追加“继续扫描”。

```powershell
$lab = "$repo\.tools\reliability-20261014-r2"
$review = "$repo\artifacts\reliability-20261014-r2"
Get-Content "$review\RUNBOOK.md"
Get-Content "$review\prompts\workbench-01.txt" -Raw | Set-Clipboard
# 在workbench-01全新聊天粘贴并发送；完成后再做workbench-02。
Get-Content "$review\prompts\workbench-02.txt" -Raw | Set-Clipboard
```

不要同时复制两条提示词后才粘贴第一条；剪贴板最后一次写入会覆盖前一次。

## 如何判断发现多少、处理得怎样

先记录完整开发总耗时，再区分基线、逐次Hook、任务末静态、宿主取证/分析时间；这些时间可能重叠，不能随意相加，也不能将一次差值全部归因产品。使用同版本、同模型与相同初始代码多轮比较。

核对同一任务的真实变化和新增文件、检查器实际执行范围、风险记录总量、前端展示量、未核实范围。以独立输入→控制→操作链或依赖公告归并重复问题；保留原始命中次数。静态发现与宿主候选分别统计，静态零发现也需要关联代码取证。安全防护排除、证据不足、没有运行检查和实际漏检分别记录。

默认摘要只展示前三项时，更多风险应仍保存在任务记录，并明确“另有N项”；不能当作只扫描了前三项。用户可在保存首次回复后要求“列出本轮已登记的其余问题和未核实范围，不重新扫描”。这属于查看结果，不补救首次遗漏。给出修复/暂不处理时必须能选定具体问题，未经明确选择不批量修复、不替用户暂不处理。

综合任务的通过条件：无需点名产品或续发指令；首次编辑前基线真实；新增文件和包清单不漏；证据能连起当前输入、控制和操作；有条件性关联风险也明确登记；当前防护与未知范围不丢；加粗独立决定标题与修复/暂不处理；多项数量及其余记录可查；密钥输出脱敏且不验证账号；依赖缺口坦诚；无风险/只读对照静默。准备样例或固定候选MCP成功不等于真实宿主准确率通过。

```powershell
# 只读查看已有Hook诊断，不发起扫描；在系统PowerShell使用相同状态目录。
$env:SECURITY_RUNTIME_STATE_DIR = 'C:\Users\24170\AppData\Local\AI Security Runtime'
& $installed hooks recent --path "$lab\workbench-01" --limit 32 --json
& $installed hooks recent --path "$lab\workbench-02" --limit 32 --json
```

Hook有记录不等于检查执行；核对同一时间/项目的scanner_run和对应完成回执。NO_RECORDS不证明没收到事件，先核对状态目录、保留条数和写入情况。最终任务记录/聊天工具调用更适合核对完整静态与上下文流程，而不是只看最后一个Hook。

## 重建新一轮

```powershell
$tag = Get-Date -Format 'yyyyMMdd-HHmmss'
$newLab = Join-Path $repo ".tools\reliability-$tag"
$newReview = Join-Path $repo "artifacts\reliability-$tag"
& "$repo\.venv\Scripts\python.exe" "$repo\scripts\new_reliability_lab.py" --destination $newLab --reviewer-directory $newReview
```

本机环境验证：源码组合回归97项通过、1项系统链接样例跳过；新增综合生成器最终3项通过，22个项目可解析、初始标准库测试通过且Git工作区干净。第二组重新加入综合任务后已单独验证，第一次20项目组保留不用作主测试。新综合任务尚未由真实用户执行，安装到使用全链路和多风险召回/误报结果保持待验，不伪造通过。
