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

**Codex 全局模式对外是 19 个工具入口，启用可选的 `start_usage_monitor` 后为 20 个：12 个分组入口 + 7 个独立入口 + 1 个可选入口。** 依据是 `global_mcp.py:create_global_server` 的 `compact_tools` 路径和 `tests/test_mcp_tool_groups.py` 的数量断言。WorkBuddy 隐藏 Hook，Cursor 保留未压缩发现，因此不能把 Codex 数量当成所有宿主的统一数量。源码中的 86 处装饰器声明包含底层操作和条件接口，不是对外工具数。

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

该示例调用的是 `development_check` 分组工具。独立工具仍直接传自己的参数，不使用 `operation/arguments` 包装。兼容的旧操作名可由全局路由分发，但不会因此出现在压缩后的 `tools/list` 中。此处 19/20 是正常注册成功时的契约；监控模块注册异常会被 Core 捕获，实际发现结果仍以连接返回为准。

### 操作族与设计目的

| 分组 | 主要用途 | 核心实现 |
| --- | --- | --- |
| `development_check` | 记录编辑、收尾、等待、保存版本与交付读取 | `mcp_tools/development_check.py`、`development_check.py` |
| `development_review` | 有界证据、扫描候选复核、业务审计、处置与复查 | `development_risks.py` |
| `security_task` / `task_review` | 严格任务生命周期及 v3 复核 | `mcp_tools/task_review.py`、`tasks/`、`task_review/` |
| `task_risks` / `finding_feedback` | 原风险与扫描发现的反馈和用户处置 | `mcp_tools/risk_disposition.py` |
| `findings` / `scan` | 显式扫描、任务状态、结果与候选处理 | `mcp_tools/explicit_audit.py` |
| `repair_impact` / `repair` | 影响证据、指定修复准备与验证 | `mcp_tools/repair.py` |
| `closeout_check` | 明确的收尾检查准备与运行 | `mcp_server.py` → `closeout.py:CloseoutService` |
| `runtime_status` | 配置、组件准备、工作区绑定、任务隔离能力与指导状态 | `global_mcp.py`、`mcp_tools/development_check.py`、`mcp_tools/explicit_audit.py`、`mcp_tools/task_review.py` |

所有静态声明、签名及源码位置见 [MCP 目录](MCP_CATALOG.md)。该目录不是最终 JSON Schema：全局适配会补充必填工作区字段，参数模型还定义嵌套约束，部分工具只在可信嵌入模式开放。实际连接的 `tools/list` 与对应模型才是调用契约。

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
