# 2026-10-19 架构回归修复与桌面验收

本页用于包含本轮修复的 0.3.6 源码及配套构建。源码提交不自动更新正在运行的进程；按实际 build_id 和能力核对接入。用户正在桌面验收，尚未反馈完整结果。

## 修复边界

| 问题 | 处理方式 | 适用范围 |
| --- | --- | --- |
| 扫描输入目录过深，Windows 创建进程立即失败 | 使用短的私有输入容器，保留固定输入、权限校验和带签名清理；启动失败返回有界系统诊断 | Windows 通用路径限制，由本机目录布局触发 |
| 输入目录初始化失败后仍保留执行占位 | 初始化成功后才发布执行占位 | 通用异常恢复 |
| 扫描完成但结果发布锁繁忙，重试重复扫描 | 暂存签名发布事实；原任务按原代际和源码条件恢复发布 | 通用并发恢复 |
| 本轮风险交付误走历史摘要 | 同一查询工具区分本轮交付与历史读取；本轮需会话、完成修订和当前源码校验 | 通用交付契约 |
| 静态风险处置状态未被历史读取采用 | 复用静态与代码复核风险的现有处置逻辑 | 通用结果投影 |
| 处置记录暂时不可读导致已保存结果也不可读 | 保留检查详情，标记处置未知，暂停处置选择 | 通用读取降级 |

这些修复不改变漏洞判定标准，也不会从历史查询获得修复授权。运行中的旧进程需要退出后重新加载源码与配套 Skill。

耦合边界保持在原执行链内：扫描仍由原引擎执行；待发布日志只保存签名完成事实，不能授予执行或发布权限；本轮交付复用 `get_task_security_review` 和同一分页投影器，九项任务工具不增加。历史处置通过注入的只读扫描存储读取，不启动懒 Runtime 或迁移数据库。扫描占位状态新写 v2、兼容已签名 v1 的旧根清理，执行凭据仍为 v1。

## 自动回归记录

分组存在重叠，以下数量不相加；这些是定向产品回归，不代表重新完成全库、打包或桌面验收。

| 分组 | 最后结果 |
| --- | --- |
| 固定输入、Windows 路径、进程诊断、CLI/MCP/Hook/TASK、原规则复查、OSV、存储门槛（14 文件） | 227 通过、1 跳过；跳过原因是当前 Windows 账号不能创建测试符号链接。真实四类目录的 Windows 进程探针均执行通过 |
| 发布恢复、任务/Hook 占位、事件日志、风险投影恢复（5 文件） | 60 个不同测试通过（主组 58 项，最后补验 5 项中新增 2 项）；包含原任务预算保留、旧代际拒绝、提交/ACK 中断、只读无恢复及 Ctrl-C 不恢复成功 |
| 本轮交付、当前反馈、风险决定体验、MCP 产品/指导契约、指导目录（6 文件） | 90 项首次通过；1 项生成/bundled 字节不同，同步仓库副本后该单例通过 |
| 纯分页与 NO_CHANGES | 23 通过；另直接比较 6 个指导主题的生成及 bundled 字节，全部一致 |
| 安装、升级、Skill | 73 项通过；源码修改期间 2 项安装快照失败，冻结源码后两项复测通过 |

测试使用隔离的临时状态和合成源码；没有扫描或改动用户手工样例。普通工具沙箱的本地 socketpair/私有目录 ACL 限制，经获准的隔离测试执行排除，未为通过测试而放宽产品权限边界。`git diff --check` 通过。

本轮自动安全核查的任务建立请求未被接受，未取得有效完成回执；不能将以上回归结果描述成安全核查通过。本次只同步源码及文档，不重新打包或更新公开 Release。

## 本次同步验证

本次对 46 个测试文件执行定向回归，共 778 个不同用例。初次结果为 749 passed、2 failed、2 skipped、25 errors；两项旧契约断言分别涉及历史查询不再弹出选择及已授权测试不应被旧提示禁止，修正后两项均复测通过。按用例最后结果去重为 **751 passed、2 skipped、25 errors、0 failed**，不是全库通过。

25 项错误共用真实规则语料的 Semgrep fixture。当前系统 Semgrep 1.178.0 的版本探针成功，但完整执行在原生 socketpair 初始化失败，返回码 2、输出 missing output；直接绕过 Runtime 扫描最小合成文件也复现。该证据定位到当前执行环境中的原生引擎失败，不据此推定所有机器或实际用户聊天同样失败。这 25 项保留为错误，未改成跳过或使用假扫描替代。

两项跳过均因 Windows 账号无符号链接创建权限。初次回归耗时 786.19 秒，失败单例复测 9.39 秒。本地 JUnit 与去重摘要在忽略目录 .test-tmp/github-sync-20261019，未上传扫描输出或状态库。

文档文件与锚点链接、git diff --check 均通过。清理 34 份旧阶段文档及 4 个无引用手工实验脚本，保留自动回归所需 fixture、旧 writer 语料及历史发行说明；包内文档清单及其测试同步更新。

## 更新本机接入

完全退出 Codex 后，在源码仓库根目录打开独立 PowerShell 执行：

```powershell
$runtimePython = (Resolve-Path '.\.venv\Scripts\python.exe').Path
.\.venv\Scripts\security-check.exe install codex --dev
if ($LASTEXITCODE -ne 0) { throw 'Codex 接入未完成，请保留诊断' }
.\.venv\Scripts\security-check.exe runtime-info --json
.\.venv\Scripts\security-check.exe preparation status
```

安装成功后重新打开 Codex。新聊天先要求读取实际连接的 `get_runtime_info`，核对构建、v3 九项任务工具以及 `features.task_security_result_delivery` 中的 `task-result-delivery-v1`。命令行版本相同不能证明旧 MCP 进程已经重启。

漏洞库尚在下载时可测试 Python 代码链路；依赖检查未完成必须如实显示，不能称整个项目检查通过。无需删除缓存或重复安装扫描器。

## 建立新的手工样例

以下命令只创建新目录和样例文件，不运行样例。保留上次测试目录不动：

```powershell
$caseDir = Join-Path ([Environment]::GetFolderPath('Desktop')) ('runtime-chain-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0,6))
New-Item -ItemType Directory -Path $caseDir -ErrorAction Stop | Out-Null
@'
def can_read(user_id, document):
    return document['owner_id'] == user_id or user_id in document.get('member_ids', [])
'@ | Set-Content -LiteralPath (Join-Path $caseDir 'permissions.py') -Encoding UTF8
@'
def read_document(user_id, document_id, repository):
    return repository.get_document(document_id)
'@ | Set-Content -LiteralPath (Join-Path $caseDir 'documents.py') -Encoding UTF8
@'
from permissions import can_read

def list_documents(user_id, repository):
    return [document for document in repository.list_documents() if can_read(user_id, document)]
'@ | Set-Content -LiteralPath (Join-Path $caseDir 'sharing.py') -Encoding UTF8
@'
class MemoryRepository:
    def __init__(self):
        self.documents = {'doc-1': {'id': 'doc-1', 'owner_id': 'alice', 'member_ids': ['bob'], 'content': 'example'}}

    def get_document(self, document_id):
        return self.documents[document_id]

    def list_documents(self):
        return list(self.documents.values())
'@ | Set-Content -LiteralPath (Join-Path $caseDir 'repository.py') -Encoding UTF8
$caseDir
```

将输出目录作为 Codex 项目，在新的聊天中执行下面的验收。

开始前可用 Get-ChildItem -LiteralPath $caseDir -File | Get-FileHash 记录四个文件的 SHA256；第一轮仅新增 download.py，原四个文件不变。只读影响分析前后也应无文件差异。Git 不是 Runtime 建立真实基线的前提。

## 发现、提醒、修复、复查

1. 发送：

   > 这是一个本地文档样例。业务规则：所有者和 member_ids 中的共享成员可以读取，其他用户不能读取。请仅新增 download.py，导入 documents.read_document，实现 download_document(user_id, document_id, repository)，原样传递三个参数并返回结果。现有文件保持原样，不运行样例。

   验收：只新增包装函数，不自动修复 `documents.py`；将缺少读取鉴权识别为关联代码已有风险。回复保留具体文件和行号，以及“问题”“可能影响”“建议修复”“尚未确认”四个标签；可处置时只询问一次“修复／稍后处理”。已有列表过滤不应被当作直接读取的防护。

   静态扫描不应再因长工作目录立即报 `LOCAL_IO_ERROR`。若有其他失败，保留具体诊断和检查缺口；不能因发现了业务漏洞就称静态扫描已成功。

2. 先发送只读影响问题：

   > 如果改成只有所有者可读，会影响共享成员、列表和下载哪些正常行为？请结合原风险保存影响分析，不修改文件、不运行样例或测试。本轮只分析。

   应指出共享成员 bob 的合法访问会受损；代码保持不变。然后明确授权：

   > 现在授权修复这项文档读取权限风险，可以修改 documents.py 并新增必要测试。复用 permissions.can_read，保留所有者与共享成员的读取行为；其他用户抛 PermissionError，不存在文档保留仓储原有 KeyError。先说明修复注意点，然后完成修复，运行必要测试并复查原问题。

   验收：先确认读取链路和正常行为，复用现有权限函数，避免在下载包装层复制业务规则。覆盖所有者、共享成员、无权限用户和不存在文档；失败行为与项目约定一致。复查说明原问题是否消除、哪些检查实际完成、是否仍有未知项，不把普通单元测试等同于全部安全检查通过。

3. 发送：

   > 只读查看刚才的检查记录与当前处置状态，不修改代码，不重新扫描。

   验收：读取原记录，不主动重复询问修复或稍后处理；旧源码记录注明适用范围。历史状态、当前源码复查结果和用户处置状态分别说明。

4. 如需验证“稍后处理”，另建一个新样例，重复第一步后选择“稍后处理”，再只读查询。风险记录仍在，但不应再次追问；这项决定不能被描述成已修复或 AI 已排除。

锁竞争、过期代际、处置存储异常等故障由自动回归覆盖；桌面验收无需手动破坏状态文件或制造锁文件。

## 误报与跨聊天处置验收

本例让当前 unsafe-eval 模式产生原始候选，而实际代码只对固定数字 AST 求值，没有外部输入。分开验收扫描器命中、AI 有证据排除及用户明确排除，不预先替 Agent 登记结论。

在独立 PowerShell 中创建新目录，不执行样例：

```powershell
$fpDir = Join-Path ([Environment]::GetFolderPath('Desktop')) ('runtime-false-positive-' + [guid]::NewGuid().ToString('N').Substring(0,12))
New-Item -ItemType Directory -Path $fpDir -ErrorAction Stop | Out-Null
@'
import ast

def constant_total():
    tree = ast.Expression(body=ast.BinOp(
        left=ast.Constant(value=40),
        op=ast.Add(),
        right=ast.Constant(value=2),
    ))
    code = compile(ast.fix_missing_locations(tree), "<fixed-expression>", "eval")
    return eval(code, {"__builtins__": {}}, {})
'@ | Set-Content -LiteralPath (Join-Path $fpDir 'constant_math.py') -Encoding UTF8
$fpFile = Join-Path $fpDir 'constant_math.py'
$fpHash = (Get-FileHash -LiteralPath $fpFile).Hash
$fpDir
```

将输出目录作为独立项目，并在同一聊天依次发送：

1. “对当前目录执行一次完整项目扫描，本轮只返回原始候选，列出规则、位置、scan_id 和 finding_id，不做 AI 误报复核、不修改文件、不运行样例。”
2. “我怀疑原 unsafe-eval 候选误报，请沿原引用读取代码并复核固定 AST 是否存在外部输入。依据充分时保存 AI 误报评估，不足则说明缺口。这只是复核请求，不代表用户人工排除；不改代码、不重扫。”
3. “对同一项，我明确决定标为误报并停止重复提醒。保存为用户排除，保留独立 AI 评估和原始命中，不扩大到整个规则或项目，不改代码。”
4. “只读查看同一原始候选、AI 评估、用户处置及当前提醒状态，不重扫。”

随后在同项目新聊天中明确提供第 1 步实际 scan_id / finding_id，只读核对原决定。原始记录应保留，不再重复询问修复；用户排除不能被说成已修复或独立的技术安全证明。怀疑误报不应自动保存为人工排除。实际没有原始命中时，不能冒称该分支已验收，也不伪造 finding。

在原 PowerShell 核对整个流程未改源码：

```powershell
if ((Get-FileHash -LiteralPath $fpFile).Hash -ne $fpHash) {
    throw '误报处理不应修改样例源码'
}
Get-ChildItem -LiteralPath $fpDir -File | Select-Object Name
```

当前用户正在执行这些案例，尚未收到完整桌面验收结果；代码示例和自动回归不代替该结果。
