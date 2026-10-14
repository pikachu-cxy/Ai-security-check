# 换电脑继续开发

更新日期：2026-10-14。开发分支：`feature/runtime-mvp`。
仓库：<https://github.com/pikachu-cxy/Ai-security-check>。

## 最新接续：闭环修复与受邀试用

先读[开发进度](DEVELOPMENT_PROGRESS.md)的最新闭环条目及[试用指南](PILOT_INSTALL_AND_USE.zh-CN.md)。四项缺口已补：漏首次收尾有界补齐、依赖声明版本原公告验证与完整图分开、原风险id逐项签名台账、长测试按需前后版本/变更范围导航。最终147项组合回归通过，之前90项定向回归有重叠。Windows原生隔离重放13项闭合为7原规则+6宿主代码复核，防护对照0项，206行测试读完；仅MCP连接和真实检查也通过。固定分析不代替新聊天或Mac真机。

同提交干净Windows包验证后，再做1人完整试用，扩3–4人前补Mac ARM/Intel构建与真机。仅MCP模式不安装Hook/Skill，配置绑定明确项目。上一提交GitHub作业执行前失败，无Mac包或可用日志；原因未确认，Mac待验。历史手测和旧包限制不追溯修改。详细下一步见[NEXT_DEVELOPMENT_PLAN](NEXT_DEVELOPMENT_PLAN.zh-CN.md)。

最新接续先读 [全链路可靠性手测](FULL_CHAIN_RELIABILITY_TEST.zh-CN.md)：本批同步所有当前源码、测试及脱敏文档，从同步提交构建dist/fullchain-20261014-r1/security-check作为干净候选。用户将亲自重新卸载接入、正常联网安装并在两个综合workbench里做单任务多风险测试；22项目生成器已验证，实际链路及多风险准确率尚待用户手测。合成凭据/答案/缓存/构建包不随Git拉取。下面保留历史批次，不以历史通过替代综合任务验收。

最新本机激活候选已更新为 dist/risk-emphasis-20261014-r1/security-check（552de5dc…），包含加粗独立风险标题和处理选项；7项相关回归及两场景原生MCP验收通过。配套Skill已升级，重启宿主后新任务使用该格式。依赖库仍过期，未启动下载，旧候选及记录保留。

2026-10-14 最新待验批次为条件性风险登记与呈现。候选 dist/conditional-risk-20261014-r1/security-check（cd4fb1b7…，source_dirty=true）在独立副本真实MCP验证现有仓储风险登记和处理选项，未改原订单项目。已离线安装激活并升级Skill，须完全重启Codex；依赖漏洞库过期、整体检查准备有缺口。本批产品任务自身上下文核查为PARTIAL，完整限制保留。接续先读 [条件性风险验收](CONDITIONAL_RISK_FEEDBACK.zh-CN.md)；新聊天使用中性命名 order-round2-01/02，不复用旧项目。确认加载同候选后再评价自动识别和最终用户提示，固定候选测试不能替代宿主验收。
## 当前批次：长文件核查与任务末统一反馈

本次同步分支为 feature/runtime-mvp。源码修复包括：80行窗口分页及未读范围、上下文请求错误分类、实际任务编辑继续检查、风险在任务结束统一呈现、保存失败的有界签名记录、检查范围变化使旧证据失效，以及后台准备期间的执行记录修正。完整受支持文件静态检查不受80行模型窗口限制。

最终受影响组合340项全部通过，耗时370.64秒；不是全仓所有测试通过声明。本轮10个改动文件的代码规则和密钥检查已执行、零提示；旧安装版本的核查会话过期且部分开始前源码未保存在预算内，因此任务上下文回执保持未完整完成。原生安装未切换，新包桌面验收仍待完成。

下一轮先读[本批开发进度](DEVELOPMENT_PROGRESS.md#2026-10-13-长文件上下文分页与任务结束统一风险反馈)和[下一步行动](NEXT_DEVELOPMENT_PLAN.zh-CN.md#下一步行动先验收本批再扩展上下文索引)：构建新的独立候选 → 按现有流程加载 → 核对MCP/Hook/Skill身份 → 新项目普通开发任务自动检查 → 长文件/快速编辑/失败记录/回退与证据失效验收 → 记录耗时与缺口。当前没有本批新原生包可直接复用，下面旧候选的历史通过记录不能替代新包验收。

函数索引、调用关系和大任务分批核查属于后续规划；当前摘要用于导航，关键权限、归属、危险操作及反证仍须读取当前代码，预算或脱敏影响判断时明确保留未知。产品每轮提供真实检查回执，不能承诺每轮均安全。存在风险时统一供用户选定修复或忽略，忽略保留记录，不扩大修复权限。

Git仅同步源码、测试和脱敏文档；本地原始回执、订单项目、构建目录和安装缓存不随拉取获取。换电脑先确认分支与工作树，再沿用本文已有构建/安装步骤并按新候选身份重新验收。

## 历史候选与验收记录

最新任务核查已替代普通 Stop 调度：先读 [任务核查验收](TASK_SECURITY_REVIEW_ACCEPTANCE.zh-CN.md)。
改文件静态 Hook 保留；当前真正待验的是宿主自动任务编排与速度，不是恢复每次聊天收尾。
本批最终包 `dist/task-security-20261013-r4/security-check`，构建 `16f299bb…`，本机已安装。
修复前快照已同步为 `67a6517`。任务盘点现按Git忽略规则自动确定项目文件，保留真实任务
开始字节并优先纳入新文件；23项任务回归及161项关联回归通过，另2项跳过。
最新独立候选 `dist/task-inventory-20261013-r2/security-check`，构建 `fcff4c7a…`，已在旧临时
文件项目和真实647文件仓库验证自动范围。未切换全局安装；加载该候选后再继续匿名手测。
实现、范围及记录见 [自动任务范围验收](TASK_INVENTORY_ACCEPTANCE.zh-CN.md)，同本批修复同步。
先读本文，再读 [开发进度](DEVELOPMENT_PROGRESS.md)、
[近期顺序](NEXT_DEVELOPMENT_PLAN.zh-CN.md) 和 [收尾验收](RUNTIME_CLOSEOUT_CHECK.zh-CN.md)。

2026-10-13 最新安装流程：`install codex` 不等待网络下载，成功后自动启动后台准备，
普通用户不需要执行前置命令。准备期间 Hook/扫描只用可用组件，原收尾任务保留缺失项；
后台通过普通 MCP 自动接续登记的任务并核对最新版本。安装成功与扫描就绪分别核对。
本批操作及验收见 [后台准备](BACKGROUND_PREPARATION_ACCEPTANCE.zh-CN.md)。
最新后台准备包为 `dist/background-prep-20261013-r2/security-check`，构建 `41b98a66041f…`，
源码 `c0cfd7bb…`，`source_dirty=false`。同包真实在线后台准备、全局普通MCP自动接续、
新编辑使旧回执失效和新鲜缓存复用已通过；真实桌面Hook/Stop仍尚未通过。
下面保留此前独立准备包的历史验收记录，不再要求新包用户执行前置下载命令。
用户已明确确认同步本批31份源码/测试/规划文件至上述私有仓库的开发分支；
同步使用已连接账号，保留远端历史并核对文件树；本地构建包、缓存和原始日志不随Git拉取。
不要照旧通过重装来刷新数据。新构建、回归和隔离验收以开发进度中的本批记录为准；
完整本地操作见 [安装验收](INSTALL_FLOW_ACCEPTANCE.zh-CN.md)。

最新 ETA 与自动续等包为 `dist/db-bar-20261013-r2/security-check`，Runtime 0.3.2。
构建为 `141cf5c0eaa9d10d27fa16222b8a693153093abb136ced6a8603a8495a040c3d`，
冻结源码为 `57f49bfe3be359ca5f01e223e4a5d709fb6eb1f3`，`source_dirty=false`。
最终同组回归 300 项在正常权限下通过，耗时 105.60 秒；受限运行中的 33 项失败经同路径
对照确定为权限原因，不把受限失败静默删除，也不称为全量套件通过。
本地 ZIP 为 `dist/experience/ai-security-runtime-v0.3.2-db-bar-20261013-r2-windows-x64.zip`，
SHA-256 为 `5aeb03a2a6ebaa717098dc4dd94e21d46e59ad9d166ebcb407335396bf9e9f9a`。

进度条按真实字节增量估算速度与剩余时间：使用约 30 秒窗口，至少 3 秒有效样本才显示
ETA；超过 10 秒未取得新增字节时移除旧估算，不做虚假倒计时。交互终端继续原位更新，
重定向每次传输仅保存最后取得的真实快照，父子事件和 stdout 回执协议不变。
公开 `prepare-scanners` 默认初始等待 300 秒、绝对上限 1800 秒，取得真实进展才可续等；
`--timeout` 指定初始等待，`--max-wait` 指定全流程绝对上限，`--fixed-timeout` 恢复固定
硬期限。默认 idle 30 秒仍生效；传输 100% 后最多等待 120 秒本地验证，仍受绝对上限
限制，不凭百分比宣布 READY。换源、重试和组件切换不重置绝对开始时间。
内部 `prepare-installation` 维持固定等待及精确旧六字段回执，普通扫描超时不随本次续等变化。

r2 真实 Windows 终端隔离在线自动续等通过，本机证据目录为 `artifacts/bt2`；
初始 60 秒、绝对上限 900 秒，最终 533.766 秒（8 分 53.766 秒）完成，超过初始等待后
继续取得真实进展，GHCR 一次来源调用。回执为 `adaptive=true`、`budget_seconds=60`、
`max_wait_seconds=900`，退出 0，三组件 READY，数据库 FRESH。捕获的 499 个可见进度
帧原位更新，下载区 LF 为 0，ETA 随实测速度变化；本次捕获无截断。原全局旧库
SHA-256 前后相同，全局安装未修改；本次隔离成功不表示用户旧全局包已完成准备。
新库 `trivy.db` 为 1,607,704,576 字节、schema 2，更新于 `2026-10-13T01:09:18Z`，
有效期至 `2026-10-14T01:09:18Z`，下载时间 `2026-10-13T06:34:46.5022507Z`；
新库验证后才切换隔离缓存，原全局旧缓存保留。
同 r2 包隔离安装首次 19.828 秒、重复 9.687 秒、首条反馈 0.265 秒，只读未就绪核对
5.485 秒；普通 MCP 的 24 项工具、构建身份与专业指导通过。ZIP 基础验收通过，
未运行全检查器发行验收。暖缓存只读READY核对5.469秒，重复默认自适应准备5.437秒、
源调用0，没有再次下载；旧内部离线入口5.235秒退出0，精确6字段兼容。
证据为本机 `artifacts/bt2/warm-result.json`，不随Git同步。
冷新机全组件准备、无代理联网、真实 Codex 自动 Hook 与用户聊天提示延迟仍未验收。

上一下载进度条包为 `dist/db-bar-20261013-r1/security-check`，Runtime 0.3.2。
构建为 `7e66ac4a44f430f8e15b7162484346470034867494ce5e6e6e4b295a821a17d4`，
冻结源码为 `6c6258713da0ec4364e111f57f68b1642a6100af`，`source_dirty=false`。
本批相关回归 123 项通过，耗时 13.61 秒；新增 15 项覆盖 30/80 列窗口、组件切换、
原位行清除、心跳、换源、失败和取消，以及独立 JSON 回执，不是全量套件通过声明。
本地 ZIP 为 `dist/experience/ai-security-runtime-v0.3.2-db-bar-20261013-r1-windows-x64.zip`，
SHA-256 为 `ffc6604ad95a2f1fffda7f88f5796dd47a77b1b399f7d0c1d6c85b16563e721b`。
交互终端原位更新同一行进度条与等待提示；文件或管道只保留每次传输最后取得的真实
快照。阶段、换源、失败、取消和最终结果另行显示；父子逐行 JSON 协议保持原样。
传输达到 100% 后仍须等待解压、有效期与数据库校验，不能提前宣布 READY。

新包的真实 Windows 终端隔离在线准备通过，手动指定 900 秒预算，493.969 秒完成；
GHCR 一次来源调用，退出 0，最终 READY/FRESH。已确认 `stderr_is_terminal=true` 与
CR 原位刷新、不逐次新增进度行；原全局旧库 SHA-256 前后相同。
证据为本机 `artifacts/bt1/result.json` 与 `terminal-output.txt`；工具曾截断部分输出，
不把已捕获的进度片段数量当作完整帧计数。这是手动指定预算的真实在线准备，尚不是自动续等验收。
新包 ZIP 基础验收通过，`full=false`，未执行全检查器发行验收。同包隔离安装通过：
首次 17.719 秒、重复 10.234 秒、首条反馈 0.297 秒；只读未就绪检查 5.609 秒。
普通 MCP 的 24 项工具、构建身份及专业指导核对通过（`guidanceVerified=true`）；
这些普通 MCP 和 ZIP 结果不代表真实 Codex 自动 Hook 链路通过。
上述普通 MCP 与 ZIP 结果和真实终端整库结果分别记录，不推定为自动 Hook 通过。

用户追加的 ETA 与受限自动续等已完成源码和相关回归，真实在线结果以上述 r2 新包
为准。不能把 r1 的手动 900 秒成功记为新能力通过，也不改写 r1 已记录的构建身份。

用户提供的 `db-online-20261013-r2` 包真实全局安装日志显示：程序已安装成功，漏洞库在 300 秒预算内
持续增长至 `78.43 / 126.98 MiB`（61.8%），随后预算耗尽；三个组件 READY，旧库 STALE，
整体 `ready=false`。该次平均报告传输约 0.26 MiB/s，网络分段原因未证实，不能把此前
隔离环境 80 秒成功记为用户本机成功。保留旧缓存与配置，不必为更新数据重复安装；
旧包此前建议手动 `--timeout 900`，本批新包可默认 `prepare-scanners` 自动受限续等。
完成后仍须核对实际状态。当前无断点续传，此次会重新下载，
更大预算不保证必然就绪，失败仍须保留原状态和诊断。

上一漏洞库在线准备包为 `dist/db-online-20261013-r2/security-check`，Runtime 0.3.2。
构建为 `34b117a79cc93e4aa6e3281bd4f0ed52efcf3534a858ac0babb2446cea25e548`，
冻结源码为 `25efd39abaf29bd0a7e155415cc93afec0de3c84`，`source_dirty=false`。
相关回归 298 项通过，耗时 115.86 秒，不是全量套件通过声明。
本地 ZIP 为 `dist/experience/ai-security-runtime-v0.3.2-db-online-20261013-r2-windows-x64.zip`，
SHA-256 为 `a252f3ff6ca16f33b1ae479eb85c13572fc41a04017e0a17328a4fe9e275dc00`。

同包真实隔离安装通过：首次 16.875 秒、重复 9.656 秒、首条反馈 0.312 秒。
Runtime 整库在线准备 80.157 秒通过，GHCR 单次取得 126.98 MiB 压缩数据；
`trivy.db` 为 1,607,704,576 字节，schema 2 与 bbolt 校验通过，有效期至
`2026-10-14T01:09:18Z`。准备退出 0，三个默认检查组件兼容、数据库新鲜。
当次隔离目录中的旧库在新库通过校验后才切换；原全局旧库摘要不变，隔离验收未修改全局安装。
普通冻结 MCP 的 24 项工具、包身份与专业指导通过；两个原凭据规则分别关闭，
收尾 6.107 秒、关闭确认 0.507 秒，重连复用及新编辑失效通过，代码覆盖仍为部分。
这属于人工独立复查和手动收尾，不是实际 Codex 自动 Hook；ZIP 仅基础验收通过，
没有启用全检查器发行验收。首次无缓存机器的引擎下载、无代理联网和真实桌面全自动
链路仍待验收，用户聊天提示延迟未测得。暖缓存只读核对 5.640 秒为 READY，
重复准备 5.500 秒通过，`source_attempts=0`，没有再次下载。
旧内部 `prepare-installation --offline` 5.469 秒退出 0，保留精确旧六字段回执；
证据为本机 `artifacts/db-on2/warm-result.json`，不随 Git 同步。

本批修复 Windows 无 CR/LF 拼接进度被丢弃导致活跃下载误杀，增加有限字节流解析；
显式按 GHCR→Google 官方镜像换源，所有尝试共用总预算。100% 只解除网络 idle，
退出码、有效期与 bbolt 校验仍决定是否激活。内部旧入口保留精确旧回执字段，
不因新增来源统计使旧安装器拒绝有效回执。直接 Trivy 诊断和第一候选 r1 的真实失败
保留；镜像样本可达，不能把旧无进度误判写成镜像服务已经证实断网。

上一安装体验批次 `dist/install-flow-20261013-r3/security-check`（构建 `e09cf28b…`，
冻结源码 `8bd960b…`）的 279 项回归和安装/MCP/ZIP 结果继续作为历史记录保留；
该包完整在线准备当时未通过，不用最新包结果改写旧包结论。
程序 ZIP 和缓存不随 Git 同步；另一台电脑按下文构建源码，或通过允许的方式带本地 ZIP。

## 本批源码已完成

1. 修正 Codex Stop 输出，只使用官方规定的继续执行决定和说明，携带原结束检查计划。
   保留原引用、执行预算和修复授权边界，不让检查计划额外授权修改。
2. 快检根据当前内容变化选择文件，保留原问题和未完成检查；结束检查复查此前实际扫描
   范围。无需再次检查的 Git 暂存文件不再仅因仍在暂存区就被重复加入。
3. 修正没有内容变化的工具调用留下待检标记的问题；只清除本次已核对事件，后来到达的
   事件仍保留。旧状态、失败、部分检查和延后检测器继续采用保守范围。
4. 依赖主检查保留上游修复版本与原始版本条件；主、备用检查归并时保留各自公告依据。
   报告、核查和修复建议同步传递，不能把各公告的选项当作已经验证的共同升级目标。
5. 修正“升级了版本号，但同一包仍报告同一漏洞”被误判解决的问题；缺失公告身份或
   检查覆盖不完整时，不能用未匹配到旧版本的结果确认风险消失。

源码回归最终相关组 239 项通过；报告、核查、功能接口和回执组 145 项通过。
分组有重叠，不能相加为全量套件结果。原生候选的准确身份和后续验收见开发进度。
这批未完成真实桌面的全自动继续验收，也未完成 Maven/Python/npm 实际依赖升级及
同组前后业务功能测试；不要从源码或冻结程序检查通过推定这些门槛已通过。

## 在公司同步源码

已有工作区时，先检查本地改动；有改动时保留现场，提交自己的工作或另建克隆，不执行
强制重置。没有未提交改动时，在项目目录执行：

```powershell
if (git status --porcelain) { throw '存在本地改动，请保留现场后再同步' }
git fetch origin
if ($LASTEXITCODE -ne 0) { throw '拉取失败' }
git switch feature/runtime-mvp
if ($LASTEXITCODE -ne 0) { throw '切换分支失败' }
git pull --ff-only origin feature/runtime-mvp
if ($LASTEXITCODE -ne 0) { throw '分支存在分叉，保留现场并核对差异' }
git log -1 --oneline
```

首次克隆时执行下面一段，随后留在新项目目录：

```powershell
$repoParent = Join-Path $env:USERPROFILE 'source'
New-Item -ItemType Directory -Force $repoParent | Out-Null
Set-Location $repoParent
git clone --branch feature/runtime-mvp --single-branch https://github.com/pikachu-cxy/Ai-security-check.git
if ($LASTEXITCODE -ne 0) { throw '克隆失败，请核对公司网络及仓库访问权限' }
Set-Location .\Ai-security-check
git log -1 --oneline
```

仓库推送同步源码、测试和文档。`.venv`、`dist`、扫描数据库、用户配置、真实项目副本、
原始验收输出和聊天不会随 Git 自动迁移。公司电脑的 Codex 聊天也需要读取本文恢复上下文。

## 准备开发环境和复验

如果公司无法访问 GitHub，可将本机 `dist/company-handoff-20261012-r1` 经允许的方式
带过去。其中 `source.bundle` 是本分支完整 Git 源码；程序 ZIP 与校验文件是本批本地
候选，未附带检查器、数据库或开发依赖。进入允许的开发目录，离线克隆源码后恢复远程：

```powershell
git clone --branch feature/runtime-mvp 'C:\approved-transfer\source.bundle' Ai-security-check
if ($LASTEXITCODE -ne 0) { throw '离线源码克隆失败' }
Set-Location .\Ai-security-check
git remote set-url origin https://github.com/pikachu-cxy/Ai-security-check.git
git log -1 --oneline
```

把示例中的传输路径换成实际位置；联网恢复后仍向同一 GitHub 分支推送。已有源码和
程序包不等于开发依赖、检查工具与漏洞数据都已准备完成，后续安装按实际结果核验。

需要 Git、Python 3.12 和可用的开发依赖下载源；独立程序打包还需 Windows GCC，或者
下文所述经过校验的现有完整程序包。按公司允许的方式准备这些依赖。
项目支持 Python 3.12 及以上，安装优化批次实际开发/打包使用 Python 3.12.10；此前
2026-10-12 批次使用 3.13.9。运行时自己管理的检查器环境独立于此开发环境。

```powershell
py -3.12 -m venv .venv
if ($LASTEXITCODE -ne 0) { throw '创建开发环境失败' }
.\.venv\Scripts\python.exe -m pip install -e '.[test,build-standalone]'
if ($LASTEXITCODE -ne 0) { throw '安装开发依赖失败' }
$testTemp = Join-Path $env:TEMP ('ai-security-dev-' + [guid]::NewGuid())
.\.venv\Scripts\python.exe -m pytest tests/test_closeout_regression.py tests/test_mutation_reconciliation.py tests/test_dependency_remediation.py tests/test_verification_equivalence.py tests/test_dependency_fallback.py tests/test_security_summary.py tests/test_task_fix.py tests/test_review_evidence.py -q --basetemp $testTemp
if ($LASTEXITCODE -ne 0) { throw '回归失败，先核对失败证据' }
```

临时目录必须放在仓库之外，并为每次运行使用新目录；否则要求普通文件夹的用例可能
被向上归属到父 Git 仓库。运行全局连接用例期间先停止编辑源码和文档，避免它们正确地
拒绝测试开始后变化的程序身份。

## 构建并安装当前源码

源码拉取不会自动替换已经安装或正在连接的 Runtime。先构建新的独立目录：
打包前使用普通安装保留完整许可证元数据，并移除测试用的 `PYTHONPATH=src`；开发可编辑
安装的元数据不能代替构建许可清单。本批曾由这项检查拒绝构建，失败目录保留。

```powershell
Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
.\.venv\Scripts\python.exe -m pip install --no-deps --force-reinstall .
if ($LASTEXITCODE -ne 0) { throw '构建用安装失败' }
$tag = 'dev-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
.\.venv\Scripts\python.exe .\scripts\build_standalone.py --output-dir "dist/$tag" --work-dir "build/$tag"
if ($LASTEXITCODE -ne 0) { throw '构建失败，不能安装旧目录冒充当前源码' }
$bundle = Join-Path (Get-Location).Path "dist/$tag/security-check"
& "$bundle/security-check.exe" install codex --bundle $bundle
if ($LASTEXITCODE -ne 0) { throw '本地安装未完成，先处理程序或配置诊断' }
& "$bundle/security-check.exe" prepare-scanners
if ($LASTEXITCODE -ne 0) { Write-Host '扫描准备尚未完成；按诊断稍后重跑 prepare-scanners，已有配置和缓存保留' }
& "$bundle/security-check.exe" prepare-scanners --status --json
```

没有 GCC 时，可以从自己保存的完整、已验证程序包复用启动器，但必须确认
`distribution/build/launcher.c` 自该包的源码提交之后没有变化。不能只复制一个来历
不明的启动器。将下面路径改成该完整包的实际位置后，先校验源码，再构建：

```powershell
$launcherBundle = 'C:\approved-packages\security-check'
$packageInfo = Get-Content (Join-Path $launcherBundle 'version.json') -Raw | ConvertFrom-Json
git diff --quiet $packageInfo.source_commit HEAD -- distribution/build/launcher.c
if ($LASTEXITCODE -ne 0) { throw '启动器源码不同或提交不可核对，请使用构建编译器' }
$tag = 'dev-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
.\.venv\Scripts\python.exe .\scripts\build_standalone.py --output-dir "dist/$tag" --work-dir "build/$tag" --launcher-bundle $launcherBundle
if ($LASTEXITCODE -ne 0) { throw '构建失败' }
```

构建器还会校验所选完整包的文件摘要。复用后的新包仍包含当前源码，有自己的构建标识。
安装成功后完全退出并重启 Codex，按宿主提示核对信任和连接，再验收真实自动行为。
同为 0.3.2 的两个包可以包含不同代码，必须核对 `version.json` 的构建和源码身份。

若公司网络无法直接下载工具或漏洞数据，安装可能只完成配置而未完成检查准备；
`--offline` 仅复用本机已有兼容缓存，不提供冷机完整离线部署。完整离线包、产品镜像
和代理入口仍列在后续规划。可继续进行已准备好的源码开发，真实依赖覆盖保持未验证。
不要删除配置、Skill 或旧缓存来处理网络失败。

## 到公司后继续的顺序和通过标准

**开始手测时先提醒用户做开发回复速度对照：先不加载产品实现一个功能，再加载产品实现同一个功能。** 使用同一初始代码的独立副本和相同提示词、模型设置，分别记录首次回复、开发完成、最终收尾及扫描等待。未加载组先于下面的安装与自动验收；本项尚未执行，详见 [手测速度对照](MANUAL_CORE_TEST.zh-CN.md#开始手测前提醒开发回复速度对照)。

1. 安装本批对应的新包并完全重启。在 Jeepay 或同规模独立 Git 项目实际修改安全注释，
   观察正常自动检查和结束检查。不得手动调用 Hook，也不得补发“继续”来替代自动验收。
   原计划自动执行、结果保存、只读复用、新改动使旧结果失效均须取得实际证据。
2. 对比真实增量范围、原问题复查及等待时间。源码夹具已验证 25 个暂存文件只检查本次
   改动的 1 个文件；Jeepay 新候选的实际耗时尚未测量，不能沿用夹具数字作性能承诺。
3. 先做 Maven 直接依赖和传递依赖案例，再扩展 Python/npm：逐公告升级依据、实际
   版本拥有者、用户选定升级、重新解析、原检查器复查和前后同组功能测试。
   缺失完整依赖图、外部 BOM、限流或解析失败保持明确限制，不猜升级目标。
4. 统一当前结果，并接通一栈实际框架的前后功能验证。现有 23 项参数测试仅为隔离样例；
   安全复查通过和功能未验证可以同时成立，不能互相替代。
5. 固定同一候选后做新人无缓存安装和完整使用预演，再扩大受邀试用。

用户已批准修复的四个 Jeepay 独立样例保持原授权；原项目其他发现未获得修复授权。
“忽略”仅表示本次不修复，风险保留；“暂不修复”不自动记录为忽略。

在公司新聊天可直接粘贴：

> 继续开发本仓库 feature/runtime-mvp。先读取 docs/DEVELOPMENT_HANDOFF.zh-CN.md、
> docs/DEVELOPMENT_PROGRESS.md 和 docs/NEXT_DEVELOPMENT_PLAN.zh-CN.md，核对最新源码、
> 本机安装的构建及待验收项。按记录的顺序继续，完成一批后更新文档并推送同一分支。
> 保留未完成的验收和覆盖限制，不把手动继续或模拟事件记作真实自动通过。
