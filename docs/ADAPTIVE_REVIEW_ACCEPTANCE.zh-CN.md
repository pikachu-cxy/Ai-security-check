# 自适应代码复核更新与验收

这次调整的是“自动规则扫描后，Agent 首次分析改动代码”的材料与进度管理。它和“修复漏洞后验证原问题”分别记录。

## 本次变化

- 必读范围完整建计划，按实际脱敏代码大小计算源码额度；计划导航与控制回复分别计量。
- 大文件先定位改动及附近上下文；无法可靠细分的区域保守保留。新增和删除文件仍读取可用的整份对应版本。
- 同版本路径、哈希与定位信息用引用复用，正文仍是可读代码；重复读取返回真实已发证据的回执。
- 修改前私有保存脱敏语义行的变化定位信息，敏感值变化和普通代码变化混在一起时也不遗漏；原文和定位指纹不会发给模型。值的实际含义仍按具体位置保留未知。
- 一个文件有很多处改动时，范围清单也分页，逐项校验完整覆盖。
- 有新读取或提交进展才续 15 分钟活动时间。闲置后恢复原任务、原代码版本和累计用量，不重新扫描或抹掉进度。
- 计划、预算、差异算法、传输与任务生命周期分开；结果保存独立于源码传输额度。

保留必要的资源保护：超过可承载的总资源或记录容量时，在开始阅读前说明需求与原因；不默默省略文件。修改前源码实际保留 24 小时，已丢失或过期的源码不能靠续接补造。当前源码仅执行 v3；旧任务保留原协议的只读记录，未完成旧任务不再续接。新版 Skill 连接不具备 v3 能力的 Runtime 时要求升级并停止核查，详见[兼容说明](TASK_REVIEW_V3_ONLY.zh-CN.md)。

## 安装

先关闭 Codex，在独立 PowerShell 中执行。使用最新构建指针选择实际安装包：

~~~powershell
Set-Location 'C:/Users/Administrator/Desktop/ai-security/Ai-security-check'
$pkg = Get-Content './artifacts/dependency-fix-latest.json' -Raw | ConvertFrom-Json
$exe = $pkg.executable
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw '安装包不存在，请保留完整输出' }
& $exe install codex
if ($LASTEXITCODE -ne 0) { throw '安装失败，请保留完整输出' }
& $exe preparation watch
~~~

安装完成后重新打开 Codex。无需重新导入原项目，也不需要再次安装 Python 依赖。先在新聊天中只读检查连接：

> 读取当前安全产品版本与能力，确认支持 task-review-plan-v3。只检查连接，不修改文件，不开始安全扫描。

## 体验验收

每个场景使用新聊天和独立的测试项目；已有未结束任务不换协议重置额度。下面是预期结果和可直接使用的提示词。

可先用下面命令创建独立材料，命令只写新的测试文件夹。随后在 Codex 中打开输出的目录，每个场景开始前复制一份未修改的材料，避免前一个场景影响后一个场景。

~~~powershell
$caseRoot = Join-Path ([Environment]::GetFolderPath('Desktop')) ('review-v3-' + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path (Join-Path $caseRoot 'modules') -Force | Out-Null
$utf8 = New-Object System.Text.UTF8Encoding($false)
for ($i = 0; $i -lt 130; $i++) {
    $path = Join-Path $caseRoot ('modules/module_{0:D3}.py' -f $i)
    [IO.File]::WriteAllText($path, "def guard(subject):`n    return policy.allow(subject)`n", $utf8)
}
$large = for ($i = 0; $i -lt 20000; $i++) {
    'value_{0:D5} = policy.allow(subject_{0:D5})' -f $i
}
[IO.File]::WriteAllLines((Join-Path $caseRoot 'large.py'), [string[]]$large, $utf8)
$hunks = for ($i = 0; $i -lt 16000; $i++) {
    'value_{0:D5} = policy.allow(subject_{0:D5})' -f $i
}
[IO.File]::WriteAllLines((Join-Path $caseRoot 'hunks.py'), [string[]]$hunks, $utf8)
Write-Output $caseRoot
~~~

场景 1 只修改 modules 下的文件；场景 2 可指定 large.py 的第 128、10001、19877 行；场景 3 可要求 hunks.py 从第 11 行开始，每隔 20 行替换一次 allow 为 enforce。不要在 Agent 开始本轮任务前先做替换。

1. **超过原 100 文件上限**。准备至少 130 个简短源码文件，要求统一替换同一处调用。

> 将此测试项目 130 个源码文件中 policy.allow 调用统一改成 policy.enforce。保留全部文件，不执行示例代码。开发完成后按本次真实改动完成安全检查与代码复核，告诉我实际改动文件数、完成复核文件数及具体缺口；不要把第一页当成全部。

预期：计划包含全部 130 个文件，不出现“只处理前 100 个”的情况；未读文件不能计为完成。

2. **大文件的零散改动**。使用超过 20000 行的源码文件，仅改动文件开头、中间和结尾附近的调用。

> 只修改我指定的三处调用，完成本次改动的安全检查和代码分析。核对三处修改前后的代码；需要时读取有关调用上下文。说明实际覆盖，不读取无关全文凑数量。

预期：三处改动均在必读范围，大段未改动内容不反复传输。若重复代码无法可靠区分，相关区域仍完整保留。

3. **一个文件有大量改动片段**。在至少 16000 行源码中分散修改数百行。

> 对这个测试文件按已给定的替换规则完成修改，并完成全部改动的代码复核。遍历所有范围清单片段，提交同一文件的完整阅读情况，不以清单第一页或已展示的片段数代替完成。

预期：范围清单可持续分页，单个文件的清单不会卡在一次回复大小限制上。

4. **中断后续接**。首次任务已经开始复核且有部分已读进度时，中断并等待活动时间超过 15 分钟，再在原聊天继续。

> 继续刚才原任务的代码复核。先验证原聊天归属和代码版本，恢复原计划与已读进度；不要重新开始扫描、补造修改前基线或清零累计用量。

预期：同一任务接着完成，已读材料不重置。如果原代码已经改变或历史材料已过期，应明确列出原因与范围。

5. **完整覆盖校验**。有意只读部分范围后请求提交完成。

> 核对目前已经读到和提交的范围。若还有未读项，明确保留未完成，不得仅因自动规则扫描无告警就声称全部代码已复核。

预期：保留未读范围；最终读完并逐项提交后，不再重复旧的未完成提示。
