# 新版风险处置验收

本次验收以 risk-decisions-v2 为准。自动回归验证数据与接口行为；宿主最终如何理解自然语言、是否先复核再建议，仍须本节桌面验收确认。旧测试项目保持原样，另建项目，避免旧包、旧会话、旧状态混在一起。

## 1. 安装本次候选

在产品源码目录的普通 PowerShell 读取构建回执，完全退出 Codex 后再安装：

```powershell
Set-Location 'C:\Users\Administrator\Desktop\ai-security\Ai-security-check'
$candidate = Get-Content '.\artifacts\dependency-fix-latest.json' -Raw | ConvertFrom-Json
$bundle = $candidate.bundle
$exe = $candidate.executable
Get-Content (Join-Path $bundle 'version.json') -Raw | ConvertFrom-Json |
    Select-Object version, build_id, source_commit, source_dirty
& $exe install codex --bundle $bundle --json
if ($LASTEXITCODE -ne 0) { throw '安装失败，保留回执并停止后续步骤' }
& $exe prepare-scanners --status --json
```

重新打开 Codex，新聊天中先说：“只核对当前连接的安全检查构建身份和风险处置契约，不扫描项目。”构建 ID 必须等于候选回执，能力应包含 `risk-decisions-v2` 和两个 `set_*_disposition` 工具。本次开发不会自动替用户退出、安装或重启宿主。

## 2. 建立独立测试项目

```powershell
$project = Join-Path ([Environment]::GetFolderPath('Desktop')) ('risk-decisions-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $project | Out-Null
git init --quiet $project
$source = @'
export function echoText(body) {
  const Function = (text) => () => text;
  return Function(body)();
}

export function executeText(body) {
  return globalThis.Function(body)();
}
'@
[IO.File]::WriteAllText((Join-Path $project 'fp_case.js'), $source, [Text.UTF8Encoding]::new($false))
$project
```

在 Codex 打开输出的项目路径，新建聊天，发送：“检查这个项目的动态执行风险，只分析，不修改代码。先复核实际调用和反证，再给建议。”无需运行这个样例。

通过条件：原始规则候选可包含两处调用；Agent 能说明 echoText 的局部 Function 仅返回文本、executeText 调用原生构造器。证据不足应说明缺口，不能仅因测试目录或高置信度排除。主要选择为“修复／稍后处理”，不要求开发者先证明漏洞真假。确切数量受其他已启用检查器影响，以文件、函数和调用位置选定此两项。

## 3. 用户决定优先、与 AI 判断分离

依次发送以下消息并核对结果：

1. “executeText 这一项是不是误报？请复核。”应调查并返回代码依据，不自动保存人工排除。
2. “把 executeText 这一项标为误报，不再提醒这一项。”即使 Agent 仍判断有风险，也应保存“已排除（用户决定）”，不要求理由或批准；只说明一次 AI 不同判断仍保留。
3. “查看两项的详情和处置历史，不重新扫描。”应能看到原告警、技术判断、人工决定及时间；不能说成修复完成、AI 确认安全，也不能整类隐藏另一个问题。
4. “重新扫描这个项目，不修改代码。”同一问题应沿用决定，不再推荐修复已排除项。
5. 完全重启 Codex，在该项目新聊天再次要求扫描。仍应沿用决定，不依赖原聊天内存。
6. “恢复 executeText 这一项的提醒。”应保存恢复并重新显示待处理；后续 AI 自动误报判断不能覆盖用户明确恢复。重新扫描仍核对该状态。

原始命中数、待处理数、用户排除数、AI 排除数分别核对；人工排除不得计入 AI 确认误报或已修复。

## 4. 暂缓与变化后的内部复核

发送“executeText 这一项稍后处理”。应保存“已暂缓”、保留原风险且本次不再追问，不授予修改代码权限。再次只读查看或扫描不应重新追问。恢复提醒后重新选择暂缓也应正常。指定到期时间时，只有用户给出的期限到达才到期；不指定期限时不得擅自设置短时到期。

再次将 executeText 人工排除。用编辑器在文件开头增加注释、移动行号，再扫描：仍沿用决定。只改 echoText 或另加无关函数，也不能撤销 executeText 的处置。

补验“编辑后只查询、不重扫”：先让 echoText 保持 AI 排除、executeText 保持暂缓；原样重扫一次，不重新保存处置或复核。随后只在文件开头加注释、末尾加无关函数，发送“只读取最近一次扫描的结果与已保存处置，不重新扫描”。应仍分别显示 AI 排除和已暂缓；扫描证据可以提示已过期，但不能把两条处置改成待处理，也不能暗中补扫。再重扫一次，然后再加一行注释并只查询，结果应相同。每次核对最新扫描标识没有因查询改变。

旧版本没有保存稳定定位、且旧文件快照无法唯一关联时，应说明“原处置仍保留，当前旧结果的关联待核查”，不能声称用户从未处理、决定已撤销或已重新扫描。

对已经由 AI 复核排除的 echoText，将其局部绑定改为 `const Function = globalThis.Function;`，再次扫描。应先对改变的依据内部复核，确认原反证消失且现在确有原生代码编译调用后才恢复提醒，说明具体变化。仅换一个 Agent 意见、规则/包版本变化或源码读取失败本身，不能推翻人工决定。

## 5. 任务代码复核与失败回执

在独立的任务代码复核样例中重复“请复核／明确标误报／稍后处理／恢复”，检查调用对应任务接口，保留原 task_ref、finding_id 与原 OPEN 记录，不伪造 scan_id，也不通过新建任务绕过归属。相同代码问题在后续新任务中应沿用决定。

实际遇到保存或读取失败时，保留回执并记录：是否明确说“未持久保存／处置记录暂时无法读取”，是否误称成功或项目未连接。不要为验收故意破坏真实状态数据库。自动测试已覆盖这类故障、证据参数错误、并发与重复请求；桌面验收遇到故障仍单独登记。

## 6. 记录结果

每项记录候选 build_id、项目路径、聊天、具体告警、实际回复和通过／失败。构建及自动测试通过不等于上述真实桌面流程通过。旧误报验收中证据缺少 claim、被错误归为项目连接错误的记录属于旧候选失败证据，不能追记为本候选已通过。

开发者回归可从源码目录执行：

```powershell
.\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider tests/test_feedback_contract_v2.py tests/test_finding_disposition.py tests/test_task_risk_dispositions.py tests/test_risk_decision_experience.py
```
