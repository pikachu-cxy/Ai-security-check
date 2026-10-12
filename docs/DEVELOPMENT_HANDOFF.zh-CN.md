# 换电脑继续开发

更新日期：2026-10-12。开发分支：`feature/runtime-mvp`。
仓库：<https://github.com/pikachu-cxy/Ai-security-check>。
先读本文，再读 [开发进度](DEVELOPMENT_PROGRESS.md)、
[近期顺序](NEXT_DEVELOPMENT_PLAN.zh-CN.md) 和 [收尾验收](RUNTIME_CLOSEOUT_CHECK.zh-CN.md)。

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

需要 Git、Python 3.12 和可用的开发依赖下载源；独立程序打包还需 Windows GCC，或者
下文所述经过校验的现有完整程序包。按公司允许的方式准备这些依赖。

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

```powershell
$tag = 'dev-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
.\.venv\Scripts\python.exe .\scripts\build_standalone.py --output-dir "dist/$tag" --work-dir "build/$tag"
if ($LASTEXITCODE -ne 0) { throw '构建失败，不能安装旧目录冒充当前源码' }
$bundle = Join-Path (Get-Location).Path "dist/$tag/security-check"
& "$bundle/security-check.exe" install codex --bundle $bundle
if ($LASTEXITCODE -ne 0) { throw '安装准备尚未完成，按诊断处理后重试同一入口' }
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

## 明天继续的顺序和通过标准

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
