# 0.3.5 任务复核改造与验收

这次将修改前代码、任务状态和复核传输分开管理。修改前正文保存到产品私有目录，
只保存脱敏内容；任务状态保存文件摘要和引用。完成后清理正文，未完成正文最长保留24小时。
旧项目、已有未提交文件、已暂存文件、未跟踪文件和非 Git 项目都使用任务开始时的真实代码。

新版按照固定计划逐文件复核，分批共享原任务、代码版本、截止时间、静态结果和累计额度。
漏读或漏提交的文件不能认定完成；补齐分页后，相应的临时缺口消失。
根据实际关系读取关联代码，不再用“必须读取一个未改动文件”代替关系判断。
方法说明按版本和摘要复用，不再与每次源码读取重复发送。当前源码仅执行 v3；旧协议只读保留历史，不能继续执行或迁移，新版 Skill 需要配套 v3 Runtime，详见[兼容说明](TASK_REVIEW_V3_ONLY.zh-CN.md)。

新版每次最多返回80行/16000字节，累计256000字节、160次源码读取、100个改动文件、
20个关联文件，每固定批次最多64000字节。分批、重连、重新结束任务都不能重置总额度。
已保存结果的只读查询另按每页最多3项、64000字节分页，不重开复核或增加取证额度。
限额内完成才报告完成；历史副本确实缺失、长行被截断或范围未读完时，说明具体文件和原因。

## 从正常安装流程开始

维护者已生成安装包后，不需要再次安装 Python 依赖或重新构建。关闭 Codex，
在独立 PowerShell 执行以下命令。安装路径来自本次成功构建的记录，不猜测根目录下的 exe。

```powershell
Set-Location 'C:\Users\Administrator\Desktop\ai-security\Ai-security-check'
$candidateInfo = Get-Content '.\artifacts\dependency-fix-latest.json' -Raw | ConvertFrom-Json
$candidateExe = $candidateInfo.executable
if (-not (Test-Path -LiteralPath $candidateExe -PathType Leaf)) { throw '找不到已生成的安装包，请保留本条错误' }
& $candidateExe install codex
if ($LASTEXITCODE -ne 0) { throw '安装失败，请保留输出，先不要继续' }
& $candidateExe preparation watch
```

准备完成后重新打开 Codex。安装会更新用户级接入和技能；原项目不用重新导入。
漏洞库准备与项目改动复核是不同进度，下载未完成时如实保留依赖检查缺口。

`--json` 输出使用 ASCII 转义保存中文，兼容 Windows PowerShell 5.1 的旧代码页；
`ConvertFrom-Json` 会恢复原来的中文内容。不要把终端中文乱码引起的 JSON 解析错误误认为安装失败。
若正在使用修复前的安装包，可先在当前 PowerShell 窗口执行以下命令，再重试版本信息读取：

```powershell
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding
$runtime = (& $installedExe runtime-info --json) | ConvertFrom-Json
$runtime.version
$runtime.features.task_security_review_protocol
```

## 手动验收顺序

1. 在原 Python 项目普通提问、只读查看文件；不应追加通用安全检查警告。
2. 新建聊天，在第一次修改前让 Codex正常接入检查。要求“给两个现有函数添加用途注释，保留已有改动”。
   检查应识别这次修改，并说明已检查的文件，不要求导入或重装旧项目。
3. 在一个较大的现有源码文件中修改一处注释。完成后不应仅因项目历史正文总量超过旧额度，
   就说“部分历史源码未保存”。超出实际限额时必须指出具体文件和原因。
4. 要求同时修改十几个文件中的简单注释。检查应自动遍历计划并提交批次，不需要反复说“继续”。
   最终说明静态检查和逐文件复核完成情况；未读完时不能报告完整完成。
5. 给已有文件先做一处未提交修改，再让 Codex做第二处修改。检查比较基准应是第二次任务开始前，
   不能把 Git 提交版本当作修改前代码，也不能覆盖已有修改。
6. 在专门的测试目录验证删除、重命名文件。删除前位置应明确标注，不能把历史位置说成当前漏洞。
7. 若遇到确实无法检查的文件，记录文件名和完整提示。后续当前检查完成后，不应继续附带先前的失败提示。

真实旧任务在升级前已经丢失的修改前正文无法补造。新版本会保留该任务的历史记录和具体缺口，
从安装后的新任务验证改造效果；不要为旧任务重新捕获当前代码冒充修改前版本。

## 需要自行重新构建时

只有继续开发源码或安装包记录不存在时才运行重建脚本。它先检查许可证和回归测试，全部成功才
生成新的独立包并更新安装包记录；失败时不更新记录、不自动安装。正常验收直接使用上面的安装步骤。

```powershell
.\.venv\Scripts\python.exe .\scripts\rebuild_dependency_fix.py
if ($LASTEXITCODE -ne 0) { throw '测试或构建失败，请保留输出，不要继续安装' }
```
