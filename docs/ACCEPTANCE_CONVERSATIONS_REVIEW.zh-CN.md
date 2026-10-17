# security-acceptance 会话检查与本次修复

审阅日期：2026-10-17。项目：security-acceptance-20261017-124434。
已读取项目内5条用户会话的完整可见记录，并核对任务收据、历史查询和聊天启动信息。
此次排查不改动验收项目，不向其他聊天发消息，不改写旧任务结果。

## 原验收情况

| 场景 | 结论 | 实际结果与原因 |
| --- | --- | --- |
| 同时改14个文件 | 通过 | 静态扫描和修改前后复核均覆盖14个文件，无告警，没有要求反复继续。 |
| 保留未提交、已暂存和未跟踪文件的已有改动 | 通过 | 本轮3个文件完成检查，已有改动保留，暂存区未被改写。 |
| 长注释、引号及随后只读查询历史 | 部分不符合 | 初次2个文件的检查完成；后来其他文件变化时，历史查询把保存结果泛化成“已失效”，即使已检查的两个文件内容未变。历史接口还漏返回已保存的复核耗时与缺口。 |
| 重命名module_020.py并删除module_021.py | 不符合 | 文件操作正确，但本轮没有启动任务安全检查。产品启动提示因短时锁冲突要求新建聊天，且指示不要补查，导致Agent跳过正常任务检查。 |
| 修改module_022.py后断线续测 | 不符合 | 初次启动没有交付聊天关联凭据，任务只属于原MCP连接；重连后的新连接不能证明归属，恢复被拒绝。Agent还自行往项目写入恢复文件，包含修改前源码副本和整份任务记录，这是引导不足导致的多余操作。 |

长注释会话的原静态检查发生于北京时间12:59:53至12:59:58，静态扫描耗时4323ms；
原复核记录保存的18548ms是复核阶段总时长，不能说成纯模型计算耗时。
没有记录的逐文件、纯模型耗时和任务总耗时应明确为“未记录”，不能估算后当实测。
上述静态与复核结果都只证明当时记录的范围，不表示当前整个项目安全。

## 已修复的原因

1. **聊天关联依赖准备成功。** 原来只有准备完成才交付会话关联信息；超时、忙或准备不足时没有关联。现在先验证身份、建立稳定关联，再进行后台准备；附加准备提示时保留关联信息。旧的无绑定连接任务仍不能追认，原记录保留。
2. **初始扫描长期占用项目锁。** 原来整仓扫描在共享锁内完成，其他聊天容易拿不到锁。现在锁内保存比较点，扫描放到锁外，发布前重新核对完整文件清单和内容，变化则拒绝发布；短操作锁允许有限等待，不无限重试。首次密钥创建改为完整且不覆盖地发布，避免并发生成不同密钥。
3. **历史与当前版本状态混用。** 历史完成状态、摘要和耗时保留，另列已检查文件、关联文件、规则配置或其他文件的变化。只读查询不重新扫描、不续期，不回写历史结论。
4. **分散改动被合并成巨大的复核窗口。** 同文件超过8个独立改动块时，原来把首尾之间所有未变代码一起读，容易用完单批额度。现在保留实际改动块；删除、重命名和真实大文件仍按真实范围检查，累计和单批限制保留。
5. **提示让Agent跳过正常检查。** 准备提示明确区分后台比较基线与本次任务核查；禁止编辑后补造基线，但不取消已建立任务的任务末核查。历史引用、修改前代码由产品私有存储维护，不让Agent往项目写原始源码或恢复凭据。

会话中还出现本机PowerShell的CET启动错误。这是终端启动问题，不能解释成项目代码出错。配套指导已要求遇到该明确错误后改用可用终端或文件工具，避免重复失败调用。

## 本次一起接通的误报反馈

用户可对指定告警回复“我认为这是误报，理由是……”。产品先保存用户意见，Agent再检查当前代码、防护、反证和缺少的上下文。
结果分别说明：仅记录用户意见、Agent复核认为误报、仍有风险、证据不足。
只有当前完整证据支持的Agent误报结论才折叠重复提醒；用户标记本身不折叠。
原告警、风险的原状态、复核依据与撤销历史保留；误报不等于已修复，不授予修改代码的权限。
相关源码、配置、规则、构建或依赖版本变化时恢复待确认。
依赖未使用、内部部署、测试文件或用户坚持都不能单独作为确认误报的依据；被遮盖的密钥内容也不能凭猜测判断。

## 安装本次新包

正常验收不需要pip，不必重建。等维护者确认本次构建完成后，完全退出Codex，在独立PowerShell执行：

```powershell
Set-Location 'C:\Users\Administrator\Desktop\ai-security\Ai-security-check'
$candidate = Get-Content '.\artifacts\dependency-fix-latest.json' -Raw | ConvertFrom-Json
$exe = $candidate.executable
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw '新安装包不存在，请保留错误输出' }
& $exe install codex
if ($LASTEXITCODE -ne 0) { throw '安装失败，请保留输出，先不要继续' }
& $exe preparation watch
if ($LASTEXITCODE -ne 0) { throw '准备尚未完成，请按输出处理' }
& $exe runtime-info --json
```

重新打开Codex，连接的构建身份应与candidate.build_id一致。旧公开下载包不包含这次工作区修复。
保持完整security-check目录，不要只复制exe；原有项目不需要重新导入。

## 重新验收的具体提示词

每一组都可以独立测试。**每组开始前重新执行下面的公共准备命令**，它会在桌面新建不同名称的项目，生成32个文件并保存Git初始版本；不会复制、删除或覆盖旧验收目录。命令中的Git姓名和邮箱仅对这一次提交生效，不修改个人Git配置。
不要要求恢复旧无绑定任务，也不要把旧任务修改后的文件重新记录成旧基线。

### 公共准备：创建全新的验收项目

在同一个独立PowerShell窗口执行，后续各组命令会使用这里的 `$caseRoot`、`$utf8` 和 `$sample`：

```powershell
$desktop = [Environment]::GetFolderPath('Desktop')
$suffix = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 6)
$caseRoot = Join-Path $desktop ('security-acceptance-' + $suffix)
New-Item -ItemType Directory -Path $caseRoot -ErrorAction Stop | Out-Null
$utf8 = [System.Text.UTF8Encoding]::new($false)
$sample = "def check_value(value):`n    return value >= 0`n"

for ($i = 0; $i -lt 32; $i++) {
    $file = Join-Path $caseRoot ('module_{0:D3}.py' -f $i)
    [System.IO.File]::WriteAllText($file, $sample, $utf8)
}

git -C $caseRoot init -q
if ($LASTEXITCODE -ne 0) { throw '验收仓库创建失败，请保留输出' }
git -C $caseRoot -c core.autocrlf=false add .
if ($LASTEXITCODE -ne 0) { throw '初始文件暂存失败，请保留输出' }
git -C $caseRoot -c user.name=RuntimeAcceptance -c user.email=runtime-acceptance@example.invalid -c commit.gpgsign=false commit -q -m "acceptance baseline"
if ($LASTEXITCODE -ne 0) { throw '验收初始版本保存失败，请保留输出' }

Write-Host "本组验收目录：$caseRoot"
```

执行成功后，在Codex打开打印出的目录并新建聊天。若某组另有准备命令，先执行该组命令，再打开项目。先确认连接的是本次新构建，再发送该组提示词。

### 1. 普通只读

发送：

> 只解释module_000.py里check_value的作用，不改文件，不运行扫描。

预期：只有解释，不额外附未执行服务或通用安全警告。

### 2. 同时修改14个文件

发送：

> 修改module_000.py到module_013.py，共14个文件。在每个check_value中增加一句用途注释，保留已有内容。完成当前任务的安全核查，分别说明静态扫描和修改前后复核实际完成的文件数。

预期：一次流程完成，不要求反复回复“继续”；未覆盖时列具体文件和原因，不能只说尚未完成。

### 3. 保留未提交、已暂存和未跟踪内容

先执行公共准备命令，再在同一个PowerShell窗口执行：

```powershell
Add-Content -LiteralPath (Join-Path $caseRoot 'module_016.py') -Value '# acceptance-existing-unstaged'
Add-Content -LiteralPath (Join-Path $caseRoot 'module_017.py') -Value '# acceptance-existing-staged'
git -C $caseRoot -c core.autocrlf=false add -- module_017.py
if ($LASTEXITCODE -ne 0) { throw '验收暂存内容准备失败，请保留输出' }

[System.IO.File]::WriteAllText(
    (Join-Path $caseRoot 'new_untracked.py'),
    "# acceptance-existing-untracked`n" + $sample,
    $utf8
)

$indexBefore = git -C $caseRoot write-tree
if ($LASTEXITCODE -ne 0) { throw '读取修改前暂存内容摘要失败' }
$indexBefore = $indexBefore.Trim()
Write-Host "修改前暂存内容摘要：$indexBefore"
git -C $caseRoot status --short
```

打开这个目录的新聊天，发送：

> module_016.py有已有未提交内容，module_017.py有已有暂存内容，new_untracked.py是已有未跟踪文件。请保留三条acceptance-existing注释和所有已有内容，在这三个文件顶部各添加一句新的用途注释，不暂存、不提交。按正常流程完成本轮安全核查，比较基准使用本次任务开始时的文件内容。

完成后回到同一个PowerShell窗口执行：

```powershell
$indexAfter = git -C $caseRoot write-tree
if ($LASTEXITCODE -ne 0) { throw '读取修改后暂存内容摘要失败' }
$indexAfter = $indexAfter.Trim()
Write-Host "修改前：$indexBefore"
Write-Host "修改后：$indexAfter"
Write-Host "暂存内容是否一致：$($indexBefore -eq $indexAfter)"
git -C $caseRoot diff --cached -- module_017.py
Get-Content -LiteralPath (Join-Path $caseRoot 'module_016.py')
Get-Content -LiteralPath (Join-Path $caseRoot 'module_017.py')
Get-Content -LiteralPath (Join-Path $caseRoot 'new_untracked.py')
```

预期：摘要比较为 `True`；三条已有注释和新注释均保留。暂存差异仍仅为提前加入的 `acceptance-existing-staged`，Agent新加的注释没有进入暂存区。这里比较的是暂存内容的Git树摘要，避免Git自身刷新索引缓存造成误判；不是要求索引文件的时间和内部缓存不变。

### 4. 删除与重命名

**重新执行公共准备命令**，使用仍包含原始module_020.py和module_021.py的新目录；不要复制已经执行过删除测试的旧目录。

打开新目录的新聊天，发送：

> 将module_020.py改名为renamed_020.py，删除module_021.py，其他文件保持不变。完成本轮安全核查；如引用删除前代码，明确标为删除前位置。

完成后在PowerShell执行：

```powershell
Test-Path -LiteralPath (Join-Path $caseRoot 'module_020.py')
Test-Path -LiteralPath (Join-Path $caseRoot 'renamed_020.py')
Test-Path -LiteralPath (Join-Path $caseRoot 'module_021.py')
git -C $caseRoot status --short
```

预期：三个存在性结果依次为 `False`、`True`、`False`。正常建立本次任务，删除前位置不冒充当前存在文件；不因后台准备忙就要求重新开聊天或取消已建立任务的核查。

### 5. 断线续测

在本组新目录的新聊天发送：

> 先保存本轮修改前记录，再给module_022.py加一句用途注释。编辑后暂停，保留同一个未完成检查任务；不要向项目写恢复文件或源码副本。

等它明确暂停后，退出并重新打开Codex，回到**同一目录、同一聊天**，发送：

> 继续原任务的检查和复核，保留原修改和任务，不新建基线。

预期：原任务续接，沿用原修改前记录和进度；不借其他聊天或旧连接任务冒认，也不向项目写任务凭据或源码副本。

### 6. 已完成记录与后来无关改动

先执行公共准备命令。在新目录的聊天A发送：

> 给module_018.py和module_019.py中的check_value各添加一句用途注释，其他文件不变。完成正常安全核查，分别说明这两个文件的静态扫描和修改前后复核结果。

等聊天A确认本轮完成后，在**同一目录另建聊天B**，发送：

> 只给module_030.py中的check_value添加一句用途注释，不修改module_018.py和module_019.py。完成本轮正常安全核查。

完成后回到**原聊天A**发送：

> 只读取刚才module_018.py和module_019.py那次检查已保存的时间、文件、版本变化和耗时，不扫描、不修改文件。区分那两个文件是否变化，以及项目其他文件是否变化；没有记录的时间说明未记录。

预期：保留原来两个文件的完成状态，明确后来是module_030.py发生变化，不谎称原文件变化；静态耗时和复核阶段耗时分开说明，未记录的纯模型或任务总耗时不估算冒充实测。

### 7. 用户提出误报、Agent复核与撤销

先执行公共准备命令，再在同一个PowerShell窗口创建一个独立静态风险样例：

```powershell
$tlsSample = "import requests`n`ndef fetch(url):`n    return requests.get(url, verify=False)`n"
[System.IO.File]::WriteAllText((Join-Path $caseRoot 'tls_sample.py'), $tlsSample, $utf8)
```

这一步只写源码文本；不执行该文件，不安装requests，也不访问样例中的网络地址。打开该目录的新聊天，发送：

> 请使用已连接的安全检查工具静态检查tls_sample.py，报告实际告警和编号。不执行项目代码，不安装依赖，不访问网络，不修复。如果没有告警，请给出实际扫描范围和未完成原因，不要虚构告警。

若出现关闭TLS证书验证的告警，使用**实际编号**发送：

> 我认为第N条是误报，理由只是这个文件位于验收测试目录。请先记录我的意见，再独立复核当前代码和防护；先不要修复。

预期：先记录用户意见；“仅在测试目录”不能证明关闭证书验证没有风险，Agent应说明仍有风险或证据不足，不能直接确认误报、折叠提醒或标为已修复。若未出现这条告警，先保留扫描回执排查，不把没有目标告警当作误报流程已通过。

随后对同一条告警发送：

> 撤销这条误报标记，保留原告警和之前的复核历史，先不要修复。

预期：该项恢复为待处理，原风险状态和历史保留，不因撤销而删除告警。

只有另有**完整、具体反证**支持时，才可以验收“Agent确认误报并折叠”分支；本例刻意保留关闭证书验证的风险，不保证也不要求它被确认误报。对实际已确认误报的告警，之后改变相关代码或防护再查看，原结论应恢复待确认。

测试数据里刻意保留的风险不能因为位于验收目录而自动归为误报。若要确认原规则是否已修复，仍走原问题复查；不能用另一任务零发现替代原风险关闭。
