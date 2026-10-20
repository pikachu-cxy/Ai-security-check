# Cursor 本地自动接入与验收

2026-10-15。开发基线为 `fix/codex-acceptance-hidden-functional` 的
`3ed0841af613c1e18b908bdfb7a84f74a2129347`，开发分支为 `codex/cursor-integration`。
当前是本地测试版，尚未作为正式 GitHub 发布包提供。

## 安装

在本次候选解压目录运行：

```powershell
.\security-check.exe install cursor
```

程序安装到个人稳定目录，写入用户级 Cursor MCP、六种自动 Hook 和常规检查白名单，安装公共
`~/.agents/skills/ai-security-review`，并在后台准备检查组件。完全退出并重启 Cursor，
在工具设置中确认 AI Security Runtime 已连接。新项目无需重复填写 MCP 配置。
安装完成和检查组件全部就绪分别显示；不要把配置成功当成已检查项目。

本地指定候选和安装位置时：

```powershell
.\security-check.exe install cursor --bundle "D:\Downloads\security-check" --root "D:\Apps\AI-Security-Runtime" --json
```

`--offline` 只检查已有组件和数据，不启动下载。未准备好的范围会明确保留。
通过源码运行的开发者可显式使用 `install cursor --dev`；源码路径属于开发模式，
不推荐用于家里电脑的长期安装。普通用户使用整个独立包，不能单独复制其中一个 EXE。

当前源码的开发任务核查仅支持 v3；旧 Runtime 或缺少 v3 工具时须升级配套构建并重连，旧任务仅历史可读。详见[升级与历史处理](../TASK_REVIEW_V3_ONLY.zh-CN.md)。

## 常规检查免确认

首次安装及再次安装/修复会更新用户级 `~/.cursor/permissions.json` 的 `mcpAllowlist`，
只添加 `ai-security-runtime` 下列精确工具名，无通配符：

- `begin_security_task`、`finish_security_task`、`prepare_task_security_review`
- `get_task_review_method`、`get_task_review_plan`、`submit_task_review_batch`
- `read_task_review_context`、`submit_task_security_review`、`get_task_security_review`
- `get_task_risk_ledger`、`get_runtime_info`、`get_scan_preparation_status`、`get_security_summary`
- `get_runtime_guidance`、`get_professional_guidance`
- `get_findings`、`prepare_task_triage`、`prepare_triage`、`submit_triage`、`get_triage`
- `prepare_repair_impact`、`read_repair_impact_context`、`submit_repair_impact`、`get_repair_impact`
- `get_closeout_status`
- `prepare_finding_feedback`、`submit_finding_feedback`、`get_finding_feedback`
- `mark_finding_false_positive`、`revoke_finding_feedback`、`set_finding_disposition`
- `prepare_task_risk_feedback`、`submit_task_risk_feedback`、`get_task_risk_feedback`
- `mark_task_risk_false_positive`、`revoke_task_risk_feedback`、`set_task_risk_disposition`

这些调用可以建立开发任务检查记录、运行任务范围内的检查、读取指导、复核已有扫描结果、
读取有限上下文、保存分析与用户明确要求的风险处置。修复影响分析不会批准修复。
独立扫描（`scan_project`、`scan_diff`）、收尾检查的准备和执行、修复确认、修复准备、
生成补丁及修复复查工具不预批准。风险处置与修复继续遵守既有明确同意和原问题复查流程。

当前源码补齐了上述指导、扫描复核、影响分析和收尾状态调用；已发布的 0.3.7 包尚不包含这次补齐。
使用包含本次修复的新构建再次安装或修复接入后，旧版签名配置会补齐缺失条目。
只拉取源码不会更新已安装的独立包或用户级白名单。工具清单测试会对照实际 MCP 注册表，
要求新增工具明确归入常规调用、需确认操作或宿主事件，避免静默漏配。
已有 JSONC 注释、用户白名单、终端白名单与其他策略保留。如果原来只在 Cursor 界面设置 MCP 白名单，
安装器会先只读导入该列表，避免新增文件后覆盖原有效列表；无法可靠读取时停止并保留配置。
卸载只撤回签名记录中本产品实际添加的条目；原有授权和后来添加的用户授权保留。

Cursor 必须允许通过运行模式使用白名单；团队策略仍可要求确认。安装器不会切换全局运行模式或
改变终端、浏览器及文件保护。安装回执的 `routine_tool_approval.status=CONFIGURED` 只证明白名单已写入，
`live_no_prompt_verified=false` 表示尚不能据此宣称真实聊天已免确认。

此前 R6 在 Windows 本地 Agents、Grok 4.6 Medium 的普通新建文件任务已走通编辑前记录、修改后静态检查、
模型核查和结果保存，当时仍手动确认 MCP 调用。当前免确认候选需要在有可用额度的 Cursor 中再做同样验收。
Free 模型额度耗尽时不能完成该真实模型验收；白名单不会增加或替代模型额度。
协议依据：[Cursor permissions.json](https://cursor.com/docs/reference/permissions)。

管理连接：

```powershell
security-check integration status cursor --scope global --json
security-check integration repair cursor --scope global --json
security-check integration remove cursor --scope global --json
```

卸载只移除可证明归属的 Cursor 配置，公共 Skill 保留供其他宿主使用。
同名未知 MCP、未知旧 Hook、自定义或重复 Skill 会阻止覆盖；先查看诊断并确认如何迁移，
不要为了安装直接删除用户配置。已有可核验归属的检测模式 Hook 可升级为自动模式。
普通项目级 `setup cursor` 仍是旧兼容入口；全局自动接入使用上面的 `install cursor`。

## 组件故障、修复和恢复提示

组件缺失、版本不匹配、已安装但启动失败、权限问题、启动超时和 Semgrep 设置损坏分别诊断。
状态输出保留具体原因、受影响的检查能力和处理建议，不展示设置内容、令牌或原始错误堆栈。
未就绪组件即使没有抛出异常，也会进入失败记录；其他已就绪组件继续复用。

重复安装只自动补齐缺失或版本不符的组件。已安装组件启动失败、安装记录不完整或完整性异常时，
先保留现场并提示处理方式，不自动删除并重新下载相同组件。Semgrep 用户设置损坏时，重装程序
无法修复共享设置，因此即使显式重装也先要求处理设置。

源码开发模式下，在 Runtime 仓库目录查询当前组件：

```powershell
.\.venv\Scripts\security-check.exe tools status --json
.\.venv\Scripts\security-check.exe prepare-scanners --status --json
```

查询不下载组件或扫描项目，不再输出“正在下载/更新”的安装阶段文案。
Cursor 中的组件准备状态查询同时返回当前实测状态和历史后台回执；修复前的失败回执不能
覆盖当前状态，也不能被描述成仍在运行的准备任务。状态查询不会恢复旧的待检任务。

仅在确认 Semgrep 用户设置损坏、用户明确选择修复后执行：

```powershell
.\.venv\Scripts\security-check.exe tools repair semgrep --json
```

修复命令备份原始设置、重建默认设置，再检查组件是否能启动；不下载组件、不扫描项目。
有效设置不会被清空，无法安全读取或修复中发生变化的文件不会强行重置。自定义设置路径
遵循 `SEMGREP_SETTINGS_FILE`，默认采用 Semgrep 的用户配置目录。

若诊断明确需要重装某一个组件，由用户显式执行，例如：

```powershell
.\.venv\Scripts\security-check.exe tools install semgrep --reinstall
```

`--reinstall` 不接受 `--all`，也不会覆盖用户显式指定的外部程序。
故障和恢复提醒按组件持久化去重；跨连接重复查询同一故障不重复推送，恢复后提醒一次，
再次出现故障时可重新提醒。主动查询始终可以查看完整当前状态。安装输出及组件状态查询共享
此提醒记录，不新增桌面弹窗或定时扫描。组件恢复只证明可用性，不证明项目通过安全检查。

## 自动行为与边界

- `preToolUse` 在支持的 Write/Edit/Delete 或可能修改文件的 Shell 前记录任务基线；
  Read/Grep 和明确只读命令不创建开发任务。启动事件是非阻塞的，不能替代同步编辑前准备。
  已识别的本产品 MCP `begin_security_task` 会在调用前使用同一任务键准备记录，供实际 MCP 调用幂等复用；
  工具编号只用于脱敏诊断，不作为权限、去重或工作区路由依据。
- `afterFileEdit`、`afterShellExecution` 调用公共检查核心；`postToolUse` 只交付原任务引用及收尾要求，
  不重复计算同一次修改。不运行 Hook 输入中的命令，也不读取聊天记录。
- Agent 在正常总结前经 MCP 完成任务检查、有限源码核查及提交。普通聊天不扫描；
  编辑后的缺失基线不会补建成“编辑前”证明。
- 完成时仍有待检任务才使用 `stop.followup_message` 兜底；同任务、内容版本和阶段去重，
  每任务最多两次不同阶段交接，Cursor 的循环限制为一次。中止、错误及续跑中的 stop 不发起续跑。
- 会话持有原任务，自动续跑改变 generation 不另起任务。同一聊天完成任务后的下一项开发可建立新任务。
  其他会话或手工建立的活动任务不会被自动接管。
- 风险说明、用户选择、修复授权及原问题复查沿用公共 MCP 服务。自动上下文和续跑都不是修复批准；
  不默认安装项目依赖、构建或执行功能验证。

只声明 **Windows x64、本地单根工作区的测试接入**。Cursor 3.22.12 本地 Agents 的原生编辑、
编辑后上下文和结束续跑已在前期探针中验证；R6 普通编辑模型闭环与当前免确认候选分别验收。
其他模型、IDE 独立入口、CLI、macOS、多根、远程、子代理及第三方 MCP 写文件仍需分别验收。
失败命令或漏事件的改动由任务末实际文件比较兜底，不能据此宣称逐次检测完整。

## 可重复验证

源码回归覆盖自动任务、脏文件基线、上下文、去重、多轮任务、会话隔离、配置保留、
重复安装、冲突、失败回滚及 Codex 公共路径。写入异常可撤回本次仍匹配的文件；
外部编辑被保留并报告需要恢复。进程强杀、断电后的跨文件恢复仍需故障验收。

构建后运行显式的 Windows 进程验收（输出必须是仓库 artifacts 中尚不存在的目录）：

```powershell
python scripts/cursor_integration_acceptance.py --bundle "dist\cursor-integration-20261015-r7\security-check" --output "artifacts\cursor-acceptance-local" --diagnostic-tool-id --mcp-begin
```

它使用隔离的安装、配置、Skill 和状态目录，实际执行独立程序安装、Hook JSON 往返、
检查和 MCP 收尾。事件由脚本模拟；提交结果明确标为进程验证，不能视作模型已完成审查。
不改现有用户 Cursor/Codex 配置。测试结果留在指定输出目录。

下一道验收：用同一候选在 Cursor 新聊天完成真实开发任务，确认正常总结前检查、风险完整呈现、
无批准零修复、选定问题修复复查和第二任务恢复；再用另一模型重复。详细矩阵见
[开发测试计划](../CURSOR_INTEGRATION_PLAN.zh-CN.md) 和 [前期 Hook 实测](../CURSOR_HOOK_FEASIBILITY.zh-CN.md)。

官方协议参考：[Cursor Hooks](https://cursor.com/docs/hooks)、[MCP](https://cursor.com/docs/mcp)、
[Skills](https://cursor.com/docs/skills)。文档能力与真实候选验收分别记录。
