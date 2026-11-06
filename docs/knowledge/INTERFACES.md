# 当前接口设计

## 对外入口

| 接口面 | 源码定义 | 责任 |
| --- | --- | --- |
| CLI `security-check` | `pyproject.toml` → `security_runtime.cli:main` | 命令参数、安装、诊断、扫描与 JSON/文本输出；完整参数以当前 `--help` 为准 |
| MCP stdio | `mcp_server.py:create_server`、`global_mcp.py:create_global_server` | 对外工具声明、工作区路由及协议适配 |
| 原生 Hook | Codex MCP 的 `mcp_server.py:handle_*_event`、`codex_event_adapter.py` 及各宿主适配器 | 事件入口因宿主而异；Cursor/WorkBuddy 全局 MCP 发现隐藏这四个 Hook 工具，不代表没有原生 Hook 接入 |
| 交付启动器 | `delivery.py`、`distribution/build/launcher.c` | 读取受校验的活动槽位并运行相同构建；不把文件名或版本号当作完整性证据 |
| 本机风险页面 | `risk_dashboard.py:Handler` | 本机临时端口、带随机路径令牌的只读页面与数据；不是公共业务 REST API |

## 分组 MCP 工具的调用格式

Codex/WorkBuddy 的全局发现使用 `mcp_tool_groups.py:GROUPS` 分组；原操作保持各自参数、所有权与授权检查。其他宿主的实际工具集合由连接返回决定。

**Codex 全局模式对外是 15 个工具入口，启用可选的 `start_usage_monitor` 后为 16 个：9 个分组入口 + 6 个独立入口 + 1 个可选入口。** 依据是 `global_mcp.py:create_global_server` 的 `compact_tools` 路径和 `tests/test_mcp_tool_groups.py` 的数量断言。WorkBuddy 隐藏 Hook，Cursor 保留未压缩发现，因此不能把 Codex 数量当成所有宿主的统一数量。源码中的 86 处装饰器声明包含底层操作和条件接口，不是对外工具数。

```json
{
  "operation": "get_development_check",
  "arguments": {
    "workspace_path": "<当前项目绝对路径>",
    "session_ref": "<宿主实际提供的引用>",
    "check_ref": "<该会话原检查引用>"
  }
}
```

这是形状示例，不可直接执行占位符。工作区参数必须放在原操作的 `arguments` 中；分组不能扩大操作权限。不要根据文档猜测新字段、引用或证据编号。

Codex 和 WorkBuddy 读取专项说明时使用 `runtime_status`，传 `{"operation":"get_runtime_guidance","arguments":{"topic":"core"}}`。旧的直接调用仍可读取同一份说明，无需工作区。

该示例调用的是 `development_check` 分组工具。独立工具仍直接传自己的参数，不使用 `operation/arguments` 包装。兼容的旧操作名可由全局路由分发，但不会因此出现在压缩后的 `tools/list` 中。此处 15/16 是正常注册成功时的契约；监控模块注册异常会被 Core 捕获，实际发现结果仍以连接返回为准。

### 操作族与设计目的

Codex 普通开发分两层。宿主按事件调用四个 Hook；默认配置的干净任务由 Hook 完成。单候选的 Agent 只使用一个公开入口 `mcp__ai_security_runtime__development_review`，先执行 `get_development_risks`，再执行 `submit_development_review`。会话内部说明提供含实际工作区和会话引用的取证示例，Agent 用待办中的检查编号补齐参数。分页、缺证及修复后复查按实际需要继续。工具目录查询与产品 MCP 次数分别计量。

| 分组 | 主要用途 | 核心实现 |
| --- | --- | --- |
| `development_check` | 记录编辑、收尾、等待、保存版本与交付读取 | `mcp_tools/development_check.py`、`development_check.py` |
| `development_review` | 有界证据、扫描候选复核、业务审计、处置与复查 | `development_risks.py` |
| `security_task` / `task_review` | 严格任务生命周期及 v3 复核 | `mcp_tools/task_review.py`、`tasks/`、`task_review/` |
| `task_risks` / `findings` | 原风险与扫描发现的反馈和用户处置 | `mcp_tools/risk_disposition.py` |
| `findings` / `scan` | 显式扫描、任务状态、结果与候选处理 | `mcp_tools/explicit_audit.py` |
| `repair` | 影响证据、指定修复准备与验证 | `mcp_tools/repair.py` |
| `scan` | 明确的收尾检查准备与运行 | `mcp_server.py` → `closeout.py:CloseoutService` |
| `runtime_status` | 配置、组件准备、工作区绑定、任务隔离能力与指导状态 | `global_mcp.py`、`mcp_tools/development_check.py`、`mcp_tools/explicit_audit.py`、`mcp_tools/task_review.py` |

所有静态声明、签名及源码位置见 [MCP 目录](MCP_CATALOG.md)。该目录不是最终 JSON Schema：全局适配会补充必填工作区字段，参数模型还定义嵌套约束，部分工具只在可信嵌入模式开放。实际连接的 `tools/list` 与对应模型才是调用契约。

`get_runtime_info` 默认 `view="summary"`，不解析规则库存；需要完整库存时显式传 `view="full"`。
Codex 收到复核待办时，在 `get_development_risks` 传 `view="review"`，同页取得本批待办、扫描器原始位置与评级、有界源码和证据引用。每页最多 20 个范围项；开启业务审计时也包括本批待审路径。已复核的项保留分页位置，仅展示仍待复核的内容。沿 `next_offset` 续读同一视图，证据不够按路径和行号补读；覆盖缺口随页返回。旧的 summary/full 与 include_evidence 组合仍读取账本。候选自带覆盖完整告警位置的 evidence_refs，缺证时按完整起止行补读。提交后只回读本次扫描批次的风险与当前处置，历史账本按需查询。

本轮已确认且需提醒的风险逐项说明，技术复核判定的误报按本次扫描汇总一句。零候选且检查完整的普通开发静默；有未完成项则说明缺口。

`get_development_risks` 默认返回当前风险及复核进度，不重复附带所有历史复核批次；`include_history=true` 可读取历史。
扫描候选复核与业务审计使用独立字段，但优先在同一次提交中保存，再统一分页读取最终风险。
默认 `agent.review_scanner_findings=true`、`agent.audit_business_logic=false`；业务审计按需开启。已有显式用户配置和批次快照优先，不由新默认值改写。
普通开发结果的 `source_applicability="CAPTURED"` 只指捕获的扫描输入，收尾不重新验证磁盘源码；严格审计的 `CURRENT` 语义不变。

### 关键请求和响应约束

| 流程 | 必须保持的请求事实 | 响应解释 |
| --- | --- | --- |
| 轻量检查 | 原 `check_ref`、宿主 `session_ref`、明确工作区；补录真实路径 | `dirty_seq` / `scanned_seq` 表示版本关系；状态和 `gaps` 必须一起解读 |
| 候选复核 | `expected_seq`、原 `scan_id`、`same_issue_as`、判断与实际 `evidence_refs` | 提交原子性、错误字段及 `review_progress` 由 `development_risks.py` 定义；提交成功不保证全覆盖 |
| 业务审计 | `business_reviews` 中的路径、依据、证据引用与 `limitations` 字符串数组 | 空 observations 不证明业务审计完成；未确认保留实际缺口 |
| 严格复核 | 原任务、v3 协议、当前窗口及服务器签发证据 | `task_review/contract.py` 与 `task_review/protocol.py` 管版本；不迁移原任务来绕过检查 |
| 修复 | 用户对具体风险与范围的授权、影响证据、准备返回的允许范围 | 严重度、源码文本、工具诊断和文档示例都不授予修复权限 |
| 安装 | 已校验包、目标安装目录、目标宿主 | `local_files_ready`、`scan_ready`、`restart_required`、`live_host_connection` 分别表示不同事实 |

## 内部服务边界

| 服务 | 输入或输出入口 | 修改时要保持 |
| --- | --- | --- |
| `WorkspaceApplication` | 工作区、检查/任务引用、运行时提供者 | 会话归属、工作区边界；不保存 SDK 对象到领域服务 |
| `DevelopmentCheckService` | 编辑路径、输入版本、后台状态 | 记录不扫描，读取不重跑，后台只执行已提交版本 |
| `ScanRequest` / `ScanBinding` | 选择路径、输入来源和绑定 | WORKTREE 与 INDEX 输入语义明确；源码或规则变化不能复用错误结果 |
| `ScanAttemptExecution` | 执行租约及发布条件 | 取消、失效租约、旧版本不得提交为当前成功 |
| `SecurityRuntime` / `ScannerRegistry` | 适用扫描器、规范化发现与诊断 | 扫描器失败、未覆盖与零发现分开；不要运行被扫描源码 |
| `SQLiteStore` / `ReadOnlySQLiteStore` | 结果存取 | 查询路径不隐式迁移或创建写库；领域证据与授权保持独立 |
| `StableDelivery` | 清单、版本槽位、指针和启动器 | 所有文件校验、已有用户内容保护、实际运行身份匹配 |

## 新接口的最小交付

确定所属领域与使用场景 → 定义类型和拒绝语义 → 领域实现 → MCP/CLI 薄适配 → 分组与能力发现 → 正常、无效、越界和版本不符测试 → 更新生成目录和相应知识条目。不能只在工具描述中宣称能力而缺少领域实现，也不能只改 schema 而遗漏所有权与证据校验。

## 低成本开发复核接口

风险列表默认每页 20 条、view=summary、include_history=false；summary 只去掉 assessment 中重复 finding 和 source_hashes，保留风险、处置、版本与分页。view=full 恢复完整字段。提交成功响应默认返回保存回执、进度与 next_action，不再附风险预览；错误恢复语义不变。证据读取支持 windows 批量（最多 20 个、每个最多 80 行），与单 file_path 二选一。批量内部串行沿原校验保存，重复窗口去重，检查版本跨批变化会拒绝；失败读取可能保存部分证据收据，但从不保存复核。提交仍逐项核验证据哈希。

## 统一开发结果对象

普通开发检查的 `security_result` 嵌入签名检查记录，包含 scan_facts、原始 SCANNER observations、有效 findings、证据、复核、处置和修复历史。扫描完成时在同一个 SQLite 事务内保存这些内容与就绪状态；不存在先发布就绪、再写另一个候选库的步骤。扫描引擎的原始执行档案仍作为底层审计档案保留，不再作为开发复核的第二个可变结果来源。

MCP 收尾/等待/查询通过 `development_result` 返回扫描摘要与第一页风险，包含 `review_ready`、复核进度、处置和 next_offset。宿主直接消费第一页，后续页才调用 get_development_risks；提交后仍从 offset=0 重读最终处置。兼容领域方法保留 static_result 字段，MCP 正常统一响应移除重复字段。保存失败返回明确不可用，不以正常空列表表示零风险、不重复扫描。

旧 development-risks.db 只读兼容；首次写入在检查事务内嵌入旧对象，保留编号、证据、复核和处置，之后只写统一结果。旧文件不删除；仪表盘优先统一结果并按检查编号去重。升级必须结束旧驻留进程后重连，不能混用新旧进程同时写同一历史记录。

复核提交支持 `return_risks=true`。返回 `post_commit_read=true` 时直接使用已保存批次第一页。后续页沿 `next_action` 传回 view=batch、expected_seq 和 scan_id；输入版本变化会拒绝续页。只收到保存回执时按其 next_action 从第一页读起。确认项可随判断原子保存 report_text。宿主可直接沿用已保存段落；误报按页计数概述，暂缓和已解决项不提醒。原 finding_feedback、repair_impact、closeout_check 分组分别并入 findings、repair、scan，旧分组保留调用兼容。

自动开发可在同一工作区、同一宿主会话中复用当前检查引用；风险与处置随该引用保留。导入器按扫描 ID 导入该次扫描已保存的全部候选。Agent 按 next_offset 逐页读取（每页最多 20 条），按当前扫描 ID 和输入版本分批提交复核（每批最多 50 个判断）。累计账本超过 100 条后仍可保存新的业务审计风险；重复提交同一风险沿用原记录。


## 原生编辑与 Stop 收尾

全局 MCP 收到有效的 Stop 时，由业务路由按本次请求的工作区和空目录规则解析根路径，诊断记录直接使用该路径。复用只在本次调用内生效。收到待复核提醒后，宿主 Agent 直接读取当前待办和证据；常见单候选再调用一次提交并读取保存后的结果。用户可见的 Hook 只显示简短状态。

Codex 可从完整 `apply_patch` 补丁取得全部路径（重命名包括原路径和新路径）。此时 PreToolUse 仅准备检查，PostToolUse 记录路径，纯补丁回合在 Stop 直接按清单收尾。只读命令不启动监听。可能写入的 Shell 或路径不完整的补丁仍在执行前启动监听；随后的完整补丁保留已开启的监听，Stop 排空通知后合并路径。

监听器从写工具的 PostToolUse 开始累计静默时间，收到相关文件事件（含同一路径再次写入）时重新计时。收到 Stop 后，监听器在静默条件满足、最后一批已保存并取得空轮询后交付。未配对的写工具从 Stop 开始观察静默。Codex 自动收尾时，监听和扫描结果等待共享 Stop 的剩余预算；持续写入耗尽预算时保留已记录路径和范围缺口。静默只描述已观察的通知，不能证明后台子进程今后不会继续写入。

Codex / WorkBuddy 的会话提示声明自动收尾时，编辑 Hook 记录实际路径，Stop 消费本轮编辑标记，沿原检查提交并等待保存结果。重复 Stop 和只读回合不触发复核。等待取产品单次预算、Stop 配置预算和 18 秒上限的最小值，覆盖预算耗尽或执行失败时给出原引用与未完成提示，后台记录仍可读取。

有扫描候选或业务审计待办时，Codex 自动 Stop 的可见续接只含中文状态、检查编号和输入版本。Agent 通过当前会话读取该版本的待办和证据，复核后报告结果。WorkBuddy 仍在交接包内预取最多 8 个窗口、合计最多 16,000 字节的源码。Agent 可一次提交两类判断，直接使用提交后重读页。用户处置按风险 ID 单独保存。关闭产品 Stop 开关时，宿主按手动模式完成原检查。WorkBuddy 的命令 Hook 在每个事件后退出，直接写文件由 PostToolUse 记录路径，无法确定路径的 Shell 写入保留范围未知。

## Codex 按仓库选择 Git 提交检查

在目标仓库运行 `security-check hooks install pre-commit --commit-only --path .`。程序把选择写入该仓库的私有签名安装记录。普通 Codex 编辑在 Git 提交时运行 staged quick 检查，Agent 不主动提交收尾。显式检查仍可运行；既有检查可沿原引用完成。提交前候选与用户处置分别保存，未提交内容尚未检查。Git 的提交门禁由 --gate 决定。

`security-check hooks status pre-commit --path .` 返回当前有效的 commit_only。移除产品 Hook 用 `security-check hooks remove pre-commit --path .`；普通开发随即恢复 Stop 自动检查。只安装过旧版 Hook 的仓库沿用原配置。模式依赖有效且归属已验证的 Hook；用户管理、缺失或内容已变的 Hook 不抑制普通开发检查。
