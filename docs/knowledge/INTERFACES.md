# 当前接口设计

## 风险管理链接

冻结包的后台身份复用已校验包 build_id，不读取归档中的源码路径。`start_risk_dashboard` 在全局 Codex/Cursor 接入均不要求 workspace_path；调用共享后台服务，不准入工作区、不扫描。返回 AVAILABLE 与实际 URL，或 UNAVAILABLE；不得构造假地址。报告没有 session_url 时保留实际覆盖缺口，提示链接不可用，不输出 null 或空 Markdown 链接，也不在报告读取时同步启动后台。

## Windows 用户目录

网页下载对 HTTP 502/503/504 仅在原官方资产 URL 添加随机缓存刷新查询参数重试一次；正常请求成功不增加调用和等待。其他错误直接失败，最终下载仍须通过 SHA256 校验后才能执行。下载错误与安装器迁移错误分别保留，不以重试绕过数据保护。

Windows 默认安装根目录为 `%USERPROFILE%/.asr`，版本槽位与活动指针保留原交付格式；配置、任务状态、组件/漏洞缓存分别位于其 `config`、`state`、`data` 子目录。路径解析本身没有目录创建、进程探测或迁移副作用。显式 `SECURITY_RUNTIME_CONFIG`、`SECURITY_RUNTIME_STATE_DIR`、`SECURITY_RUNTIME_DATA_DIR` 继续优先；自定义路径不自动搬迁，也不能假定处于 AppData 的自定义路径跨宿主一致。

Windows 原生安装在构造配置所有权服务前调用 `windows-user-directories-v1` 一次性迁移。配置、状态库、密钥及缓存按完整原件复制并核对，旧目录保留；程序槽位由传入的校验安装包重新建立，不复制旧活动指针。重复安装只读取小型完成回执，不遍历旧目录、不增加进程探测或启动器验证次数。非 Windows 默认位置保持原行为。旧签名任务中的扫描库路径不改写；只针对已记录迁移来源的旧默认 scans.db，在数据库打开边界解析到新库，保留原引用与证据签名。

迁移发现不同的外部/宿主私有数据时返回 `LEGACY_USER_DIRECTORIES_CONFLICT_SELECT_APPDATA`，不合并数据库。用户可以通过 `install --legacy-appdata <包含 Local/Roaming 的根目录>` 或 Windows 脚本 `-LegacyAppData` 明确选定活动来源，其他原件保留。旧服务仍运行或进程身份未知时停止迁移；源数据变化、目的目录冲突、重定向读取无法匹配真实文件时也不能报告成功。扫描旧目录时文件被并发删除或不可读返回 `LEGACY_DIRECTORY_IDENTITY_UNKNOWN`（固定诊断，不回显路径内容），同样不发布副本、不删除原件，并提示可显式指定来源。重定向场景须退出相关宿主，在普通 PowerShell 安装后重连。首次数据迁移耗时单列，不当作重复安装性能。

源码与网站脚本必须随同具备该迁移契约的原生包发布；改脚本的安装目录不代表旧发行包已支持配置和状态迁移。安装回执的 `user_directories` 与 `launcher_verification` 分别描述数据迁移及实际入口构建，不能替代宿主重连验收。

## 业务审计的开发轮次与报告版本

持续审计以 `round_id` 绑定执行授权。每轮首批实际修改通过原 `stream_prepare → stream_started` 交接新子 Agent；轮内新增文件合并队列并复用本轮执行者。Stop 封口且保存完成后授权关闭，后续开发生成新轮次与新授权，不跨轮续接；旧版本没有 round_id 的授权也不能作为新轮执行者。历史发现、提交回执和未完成事实保留，旧凭据不得写入新轮。

审计提交在原保存事务中递增报告修订号。静态报告已经返回后若同一开发回合收到晚到审计结果，Stop 只补交原扫描的最新报告，不新增扫描或重复提交；已提示的同一修订不再提示，无关只读回合不继承此资格。报告读取仍不等于用户已阅读。

迟到的 Python SQL 审计与静态复核仅在同批、同文件、同源码哈希、唯一 execute/executemany 调用位置且双方均确认时关联到一个风险，保留两份观察和判断。不同类别、多个候选位置或证据不一致时不自动合并。使用提交时已读取的证据，不增加取证调用；其他语言与类别不套用此窄规则。

产品报告统一使用 `### **漏洞标题**`，多项漏洞之间加入 `---` 分隔线；静态候选、确认漏洞和待确认漏洞共用渲染器，正文、处置选项及会话链接保留。

## 修后额外复查

`development.repair_recheck_enabled=false` 为默认。普通修复准备新增 `automatic_recheck_enabled`、`ordinary_development_closeout` 和 `followup_instructions`；旧扫描器修复准备的 `verification_plan.automatic` 明确专项验证是否自动执行。关闭时修复编辑依然触发普通开发检查，不自动补读修后证据、提交原风险复查或再调用专项扫描。显式验证接口保留，历史风险不因普通零告警扫描自动关闭。设置不改变扫描器预算、Stop 等待或普通业务审计开关。

## 开发报告与处置新契约

Observation/ScannerReview 增加可选 report_content（title/problem/impact/advice/unknowns/function_name），旧 report_text 保留；产品固定生成中文报告。INCONCLUSIVE 已保存即复核执行完成，仍是待确认风险，inconclusive_scanner_ids 单列；未提交候选才列 pending_scanner_ids。BusinessReview 增加 coverage、uncovered，pending_business_paths 不包含已审路径；真实缺口通过 business_coverage_gaps 单列，旧未分类限制不自动变完整。

set_development_risk_disposition 支持 decision 标准字段和 disposition 兼容别名，冲突拒绝；新增 reason、expected_seq、expected_revision、request_id。include_history=true 的风险读取提供 revision。旧无 reason 请求明确记录原因未填写，不虚构；无 request_id 的相同当前决定有界去重，显式编号重试复用首次 CAS 版本。返回 saved/repeated/revision/disposition，用户 EXCLUDE 不等于技术 DISMISSED。

development.stop_fallback.wait_mode 默认 bounded，可选 wait_for_result；后者仅用于 Codex，仍有核验的宿主上限，不提供虚假的无限值。Stop 安装定义 600 秒，等待预留 10 秒；旧连接仍需重连，未知配置按 18 秒回退。report_render_start/report_render_done 新增于既有复核计时回执，无新增调用。


## 退役数据流提供器

ScannerRegistry 不再构造 native-dataflow/native-go-sql，并在默认、显式和 fallback 注册时排除这些提供器；插件 ID 仍保留拒绝重名。历史结果中的 provider 名称继续可读，不删除历史确认漏洞，不把旧 PARTIAL 改成 FULL。运行时 bounded_dataflow/native_go_sql 能力为 DISABLED；健康组件为 DISABLED、optional=true，不因停用而将产品判异常。scan.dataflow 旧配置仅为格式兼容，不参与当前扫描调度，前端隐藏调节项但保存其他配置时保留原值。


## 后台展示与会话名称接口

风险读模型新增 presentation（title_zh、technical_explanation_zh、plain_impact_zh、advice_zh、unknowns_zh、content_source、source_revision、presentation_version）及 session_name/title_source/title_synced_at；原字段保留。展示内容不参与漏洞身份和签名。CSV 增加中文列与名称，SARIF 保留原始说明和展示扩展属性。

POST /api/session-alias 接收 id、alias、expected_alias；只允许现有可见会话，空别名恢复宿主名称；旧别名冲突返回 409。沿用 Cookie、Origin、CSRF。POST /api/session-titles/refresh 接收空对象，异步合并刷新，不等待扫描或模型。GET /api/entities 返回 title_sync_status 和名称来源；名称、活动时间不改变删除 CAS。扫描与 MCP 协议不增加接口。


## 当前产品范围与后续规划

全项目扫描与 Git commit 扫描列为后续支持功能，当前源码关闭公开执行入口。全项目同步入口、后台 project 提交及 CLI release 模式返回未开放说明；Git pre-commit 安装/修复与 staged 扫描同样拒绝。保留旧入口用于明确报错，旧 Hook 的状态查询与移除仍可使用。已有 pre-commit 脚本不会自动删除，调用后会收到未开放错误，需通过原移除入口清理。

普通开发继续通过编辑记录与 Stop 收尾检查涉及路径；commit-only 配置不再跳过 Stop。底层扫描实现保留供内部流程使用，不代表公开全项目扫描已开放。

后续全项目扫描需完成范围与排除规则、异步进度、取消及大项目性能验收后再开放。后续 Git commit 扫描需完成暂存区一致性、部分暂存、Hook 共存、阻断策略及迁移验收后再开放。具体版本与日期未定。本项是源码范围变更，驻留进程须重新加载后生效。


## 后台健康监控

已认证浏览器的 `GET /api/monitor` 返回 `dashboard-health-v1`；不接受查询参数，沿用本机 Host/Cookie 校验。仅页面进入或手动刷新触发，进程内互斥合并请求，30 秒复用一次结果；并发请求返回 checking 与上次快照。没有定时轮询，不由扫描或 Stop 调用。

底层工具复用 ToolManager.resolve 的版本/可执行身份校验，不安装、不下载，不传项目路径；按需组件独立标记，不影响必需组件总状态。规则展示当前配置的路径、内置包版本及模式，不能替代具体项目规则加载验收。Trivy 漏洞库展示受限元数据、格式版本、更新时间、有效期及本地结构校验；Java 索引标明按需及文件存在，不冒充执行验证。

MCP 使用产品自身启动器创建独立连接，30 秒限时；执行 initialize、tools/list、get_runtime_info(summary)，验证既有能力契约。每项区分 REGISTERED 和 READ_VERIFIED，不为健康检查执行有副作用的业务调用；宿主当前聊天连接始终单列 UNKNOWN。接口失败隐藏异常正文，保留固定失败状态。产品总状态要求必需工具、漏洞库可读且时效有效、独立 MCP 可用；不承诺全部项目和业务操作无故障。

仅健康检查完成时保存最近 16 次聚合状态与耗时；连接退出诊断最多读 32 条，包含独立探测进程。页面使用 textContent 输出本地路径/元数据，无凭据或调用参数。仪表盘正常情况下不再渲染长汇总说明、缺失项目目录提示或更新时间；真实索引缺口仍显示简短提醒及详情，底层统计和签名校验不变。

## 连接退出诊断与独立交接提示

MCP stdio 启动及退出各保存一次有界连接记录，最多保留 32 份。工具调用只更新内存中的方法名、请求/完成时间、活动数量和结果类型；不保存参数、源码、提示词或异常文本，不在扫描和 Stop 写诊断文件。退出区分正常 stdio 结束、SIGTERM/SIGINT 和未处理异常；异常仅保留类型与 Runtime 相对模块/行号。正常 EOF 不证明宿主主动正常退出，SIGKILL 或宿主端传输失败可能无退出记录；进程存在也不等于连接健康。`connection-diagnostics` 只读输出保留记录及未知边界，不扫描。

Codex 的既有 `UserPromptSubmit` 命令 Hook 与 MCP 重连入口复用 `development_recovery.resume`。只接受同一会话、同一工作区、已签名且有原生编辑活动的原检查；不盘点其他项目，不把只读输入当作新的开发任务。未提交任务由隔离后台恢复进程沿原编号提交；运行中的任务复用原工作进程；已完成结果由 Stop 或下次输入补交。短提示仍只有“正在整理安全检查结果”与原编号，详细恢复状态保存在结果页。

恢复启动有持久化租约与失败上限，启动失败最多三次；恢复校验失败停止自动尝试。工作进程已明确不存在时，回收原租约并重用原队列；权限不足或 PID 状态未知时不抢占，PID 重用保守等待租约。运行中的进程存在不等于 MCP 连接可用。已保存扫描通过原尝试、输入版本、工作区和归属核验后重新入库交接，不重新调用扫描器；未保存的执行才重启。扫描结果、复核提交、宿主实际交付和用户阅读仍是不同事实。

原生 Stop 的 `INCOMPLETE` 提示不是最终结果已交付：同批结果稍后完成可升级为 REVIEW/REPORT，并去重后补交，包括零候选完成说明。新增开发回合不会覆盖未完成批次的引用；新检查通过原引用链保留旧任务补交入口。新一批实际编辑清理已完成旧批次的监听缺口，但原交付记录保留历史未知范围。

产品设置新增 `development.stop_fallback.native_wait_seconds`（默认 18，范围 0–18）。实际单次等待为它、兼容续接预算、产品单次等待环境配置三者最小值，配置查询返回 `effective_native_wait_seconds`。不延长原 Stop 等待，扫描器独立执行预算不变；扫描器超时必须大于 0，拒绝把 0 解释为无限等待。原配置无需迁移，下一批使用新快照。

独立入口仍依赖宿主正常执行命令 Hook，安装不代替信任批准；它不能重新打开宿主已经关闭的 stdio，也不能主动唤醒闲置聊天。补交发生在下一次 Stop、会话输入或重连。读取或返回报告不等于用户已阅读，不增加模型自报交付成功的接口。

## 对外入口

| 接口面 | 源码定义 | 责任 |
| --- | --- | --- |
| CLI `security-check` | `pyproject.toml` → `security_runtime.cli:main` | 命令参数、安装、诊断、扫描与 JSON/文本输出；完整参数以当前 `--help` 为准 |
| MCP stdio | `mcp_server.py:create_server`、`global_mcp.py:create_global_server` | 对外工具声明、工作区路由及协议适配 |
| 原生 Hook | Codex MCP 的 `mcp_server.py:handle_*_event`、`codex_event_adapter.py` 及各宿主适配器 | 事件入口因宿主而异；Cursor/WorkBuddy 全局 MCP 发现隐藏这四个 Hook 工具，不代表没有原生 Hook 接入 |
| 交付启动器 | `delivery.py`、`distribution/build/launcher.c` | 读取受校验的活动槽位并运行相同构建；不把文件名或版本号当作完整性证据 |
| 本机风险页面 | `risk_dashboard.py:Handler` | 共享本机固定端口、首次浏览器授权、项目与会话筛选的只读页面与数据；不是公共业务 REST API |

## 分组 MCP 工具的调用格式

Codex/WorkBuddy 的全局发现使用 `mcp_tool_groups.py:GROUPS` 分组；原操作保持各自参数、所有权与授权检查。其他宿主的实际工具集合由连接返回决定。

**Codex 全局模式对外是 15 个工具入口，启用可选的 `start_usage_monitor` 后为 16 个：9 个分组入口 + 6 个独立入口 + 1 个可选入口。** 依据是 `global_mcp.py:create_global_server` 的 `compact_tools` 路径和 `tests/test_mcp_tool_groups.py` 的数量断言。WorkBuddy 隐藏 Hook；Cursor 保留原始操作发现，并增加仅含五项普通复核/审计操作的 development_review 分组，因此不能把 Codex 数量当成所有宿主的统一数量。该分组不包含用户处置或修复授权，拒绝这些操作仍发生在工作区访问之前。源码中的 86 处装饰器声明包含底层操作和条件接口，不是对外工具数。

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
| 候选复核 | `expected_seq`、原 `scan_id`、取证页各候选自带的非空 `same_issue_as`（等于该项 `id`）、判断与实际 `evidence_refs` | 提交原子性、错误字段及 `review_progress` 由 `development_risks.py` 定义；提交成功不保证全覆盖 |
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

历史风险列表默认每页 20 条、view=summary、include_history=false；summary 只去掉 assessment 中重复 finding 和 source_hashes，保留风险、处置、版本与分页。view=full 恢复完整字段。提交成功响应默认返回保存回执、进度与 next_action，不再附风险预览；错误恢复语义不变。证据读取支持 windows 批量（最多 20 个、每个最多 80 行），与单 file_path 二选一。批量内部串行沿原校验保存，重复窗口去重，检查版本跨批变化会拒绝；失败读取可能保存部分证据收据，但从不保存复核。提交仍逐项核验证据哈希。

对 `submit_development_review`，默认 `response_view="batch"` 沿用原返回。可选 `"final_report"` 同时请求提交后读回。完成批次返回 `contract=development-final-report-v2`、整批报告及计数、输入和扫描版本、会话链接和覆盖信息；仅超预算的报告正文分页。部分批次返回有界 `review_receipt`，保留未完成状态；读回失败时返回已保存状态及重读操作。不得用缩短回执替代版本或证据校验。

取证、补读和复核提交的正常返回附 `review_timing`。其中 `start_unix_us` 是进入工具处理函数时的 Unix 微秒，`offsets_us` 是从同一调用起点算出的单调时钟偏移。已进入提交处理且有结构化恢复结果的失败调用也带计时。工具处理前的参数拒绝和不可恢复的异常依靠宿主调用事件计时。该字段供本机事后分析，最终报告以 `report_text` 为准。

## 统一开发结果对象

普通开发检查的 `security_result` 嵌入签名检查记录，包含 scan_facts、原始 SCANNER observations、有效 findings、证据、复核、处置和修复历史。扫描完成时在同一个 SQLite 事务内保存这些内容与就绪状态；不存在先发布就绪、再写另一个候选库的步骤。扫描引擎的原始执行档案仍作为底层审计档案保留，不再作为开发复核的第二个可变结果来源。

MCP 收尾/等待/查询通过 `development_result` 返回扫描摘要与第一页风险，包含 `review_ready`、复核进度、处置和 next_offset。宿主直接消费第一页，后续页才调用 get_development_risks；提交后仍从 offset=0 重读最终处置。兼容领域方法保留 static_result 字段，MCP 正常统一响应移除重复字段。保存失败返回明确不可用，不以正常空列表表示零风险、不重复扫描。

旧 development-risks.db 只读兼容；首次写入在检查事务内嵌入旧对象，保留编号、证据、复核和处置，之后只写统一结果。旧文件不删除；仪表盘优先统一结果并按检查编号去重。升级必须结束旧驻留进程后重连，不能混用新旧进程同时写同一历史记录。

在 `submit_development_review` 的 arguments 顶层传一次取证页返回的 `scan_id`，并传原 `check_ref` 与 `expected_seq`。每个扫描候选保留 `same_issue_as`、`decision`、`rationale`、`evidence_refs`，确认项照常附 `report_text`。旧调用可继续逐项传 `scan_id`。同一事务内核对批次、当前扫描和输入版本，逐项核对候选归属及证据；批次过期、逐项编号冲突、扫描候选缺少两种形式的编号或证据无效都会拒绝整批。调用者从取证页取得编号，服务端不会代猜最新扫描。

同批重复命中可在次项填写 `decision=DISMISSED` 与 `duplicate_of`（同一批已确认的主候选 id），保留次项自身的 `same_issue_as`、理由和证据。服务校验同一文件的重叠证据位置、扫描和输入版本；关系无效整批回滚。报告将重复和误报分开计数。仅监听观察到的候选可返回 `edit_attribution=OBSERVED_ONLY_WRITER_UNKNOWN`。宿主最终回复先保留开发结果和实际验证，再附已保存的安全报告。

复核提交支持 `return_risks=true`。返回 `post_commit_read=true` 时直接使用已保存批次第一页。后续页沿 `next_action` 传回其实际 view、expected_seq、scan_id 及可选 report_digest；输入版本变化会拒绝续页。只收到保存回执时按其 next_action 从第一页读起。确认项可随判断原子保存 report_text。宿主可直接沿用已保存段落；final_report 中误报整批计数概述，暂缓和已解决项不提醒；显式 batch 视图保持原分页。原 finding_feedback、repair_impact、closeout_check 分组分别并入 findings、repair、scan，旧分组保留调用兼容。

自动开发可在同一工作区、同一宿主会话中复用当前检查引用；风险与处置随该引用保留。导入器按扫描 ID 导入该次扫描已保存的全部候选。Agent 按 next_action 逐页读取（review/closeout 省略 limit 按字节预算，历史视图或显式 limit 保留每页最多 20 条），按当前扫描 ID 和输入版本分批提交复核（每批最多 50 个判断）。累计账本超过 100 条后仍可保存新的业务审计风险；重复提交同一风险沿用原记录。


## Trivy 依赖检查提示

Trivy 成功退出、结果结构有效时，以计划清单和实际返回的包清单、包名和版本、Python 声明解析结果及漏洞库新鲜度判定本次依赖覆盖。普通诊断日志的级别不会单独触发覆盖缺口提示。清单未获得报告、包坐标无法确认、声明存在未解析项或漏洞库过期等情况仍报告限制；非零退出或无效 JSON 沿失败路径处理。这个判断的范围是本次所选清单中的报告结果。

## 原生编辑与 Stop 收尾

内部命令分类新增 `OUTSIDE_WORKSPACE_MUTATION`，仅在已有可信工作区根目录时，对有限字面量 `Remove-Item`/`rm` 目标验证：绝对路径、无链接或重解析点、与工作区互不包含；不执行命令、不解析变量或通配符，不遍历目录。PreToolUse/PostToolUse 跳过编辑记录和监听，诊断保留 `OUTSIDE_WORKSPACE_ACTIVITY`，不把外部删除声称为只读。未携带工作区的旧分类调用继续返回可能修改。路径无法核验、混合写入/未知命令、管道和动态脚本保留原采集链路。

只读识别支持同一命令内的字面量路径变量、受限 Get-Content 赋值及常量索引/范围读取；未定义变量、方法调用、动态下标和混合写入不获得只读分类。不修改已有检查、历史归属、扫描结果或原生工具的公开入参。

`development_file_watch._Window.paths` 在记录前，以归一化的绝对路径按目录层级核对项目根目录；项目外通知直接忽略，不形成编辑或采集缺口。不能使用字符串前缀判断归属。项目内路径的无链接校验仍使用原始拼写，防止归一化隐藏链接祖先；相对或不可核验的项目内通知继续保留真实缺口。

Stop 处理异常或已绑定连接的配置校验失败时，仅从已验证工作区、原会话和当前回合的签名编辑记录恢复一次 `INCOMPLETE` 交接。不放宽配置校验，不自动重试扫描，异常详情不进入报告。读取 closeout 返回完整未完成说明及已有会话链接。

同一会话重新连接时，SessionStart 只查询该 owner 的聚焦检查；存在带宿主回合号、实际输入增长且未交接的待办时，沿原编号提示一次 `STOP_HANDOFF_INTERRUPTED`。只读观察、手动检查、其他 owner、已交接版本不触发；不遍历历史、不等待、不补扫，不将提示标记等同用户已读。正常 Stop 路径没有新增存储事务、扫描或等待。

Hook 诊断仍最多每工作区 32 条、全局 1024 条，在原容量内优先保留最近 4 条 Stop；正常工具调用不能立即挤掉收尾原因。全局容量、清理和写入失败仍可能导致历史诊断不可用，缺记录不证明宿主未调用。

POSIX 源码版的全局 Codex Stop 在请求内共享已验证的构建摘要。配置校验和最终回执使用同一算法，复用前重查文件清单与状态变更时间；下一请求重新计算。源码或规则的内容、路径和成员变化会使旧摘要失效。构建身份只标识 Runtime 自身，项目扫描输入仍由扫描流程独立验证。

全局 MCP 收到有效的 Stop 时，由业务路由按本次请求的工作区和空目录规则解析根路径，诊断记录直接使用该路径。复用只在本次调用内生效。收到待复核提醒后，宿主 Agent 直接读取当前待办和证据；常见单候选再调用一次提交并读取保存后的结果。用户可见的 Hook 只显示简短状态。

Codex 可从完整 `apply_patch` 补丁取得全部路径（重命名包括原路径和新路径）。此时 PreToolUse 仅准备检查，PostToolUse 记录路径，纯补丁回合在 Stop 直接按清单收尾。只读命令不启动监听。可能写入的 Shell 或路径不完整的补丁仍在执行前启动监听；随后的完整补丁保留已开启的监听，Stop 排空通知后合并路径。

监听器从写工具的 PostToolUse 开始累计静默时间，收到相关文件事件（含同一路径再次写入）时重新计时。收到 Stop 后，监听器在静默条件满足、最后一批已保存并取得空轮询后交付。未配对的写工具从 Stop 开始观察静默。Codex 自动收尾时，监听和扫描结果等待共享 Stop 的剩余预算；持续写入耗尽预算时保留已记录路径和范围缺口。静默只描述已观察的通知，不能证明后台子进程今后不会继续写入。

跨连接监听通过签名检查的 file_watch.control 保存进程、回环端口及随机能力凭据，仅支持 touch/complete/stop；凭据不投影到公开结果。已有实例在本进程时仍走原内存路径；异进程不得根据本地实例缺失判定中断，也不得在未确认原持有者失效时抢占。并发启动在原存储事务内选定持有者，其他连接关闭未采用的原生监听并复用原实例。跨连接 Stop 仍用原剩余预算排空，成功回执后才算停止；真正中断或超时保留诊断。INCOMPLETE 将 file_watch_gaps 放入 observation_notes，gaps 只保留实际扫描/交接缺口。无新增公开 MCP 接口或 Hook 类型。


Codex / WorkBuddy 的会话提示声明自动收尾时，编辑 Hook 记录实际路径，Stop 消费本轮编辑标记，沿原检查提交并等待保存结果。重复 Stop 和只读回合不触发复核。等待统一通过 `native_wait_seconds` 计算实际单次预算，默认上限仍为 18 秒，覆盖预算耗尽或执行失败时给出原引用与未完成提示，后台记录仍可读取。

有扫描候选或业务审计待办时，Codex、Cursor 和 WorkBuddy 自动 Stop 的可见续接只含统一状态和检查编号。Agent 通过当前会话的 closeout 视图读取保存的输入版本、待办和证据，复核后报告结果。Cursor / WorkBuddy 自动模式使用与 Codex 相同的 closeout、证据预算和批量提交；旧严格任务继续使用原交接契约。Agent 可一次提交两类判断，直接使用提交后重读页。用户处置按风险 ID 单独保存。关闭产品 Stop 开关时，宿主按手动模式完成原检查。WorkBuddy 的命令 Hook 在每个事件后退出，直接写文件由 PostToolUse 记录路径，无法确定路径的 Shell 写入保留范围未知。

## Codex 按仓库选择 Git 提交检查

在目标仓库运行 `security-check hooks install pre-commit --commit-only --path .`。程序把选择写入该仓库的私有签名安装记录。普通 Codex 编辑在 Git 提交时运行 staged quick 检查，Agent 不主动提交收尾。显式检查仍可运行；既有检查可沿原引用完成。提交前候选与用户处置分别保存，未提交内容尚未检查。Git 的提交门禁由 --gate 决定。

`security-check hooks status pre-commit --path .` 返回当前有效的 commit_only。移除产品 Hook 用 `security-check hooks remove pre-commit --path .`；普通开发随即恢复 Stop 自动检查。只安装过旧版 Hook 的仓库沿用原配置。模式依赖有效且归属已验证的 Hook；用户管理、缺失或内容已变的 Hook 不抑制普通开发检查。


## 后台风险服务首批契约

MCP CLI 启动时在后台执行服务就绪检查。start_risk_dashboard 保留原工具名与返回结构，返回可复用的本机授权入口；宿主向用户交付链接。首次浏览器授权成功后，/risks 和 /api/risks 使用 HttpOnly、SameSite=Strict Cookie。读取接口仅接受 project、session、editor 参数并验证格式，会话过滤作用于验证过的保存记录。当前 project 映射工作目录身份，后续逻辑项目归并需要兼容此地址。

完整确认报告末尾附固定会话链接；统一开发结果可带 risk_management_url，宿主在有需提醒的候选时将其附在完整说明后。链接读取是本地元数据查询，服务未初始化时不阻塞复核或额外启动后台服务。扫描及风险保存独立于 Web 服务状态。

## 本机风险管理 v2 与并行业务审计

Web 使用 `/risks` 固定入口；GET `/api/session`、`/api/risks`、`/api/config`、`/api/export`。风险查询支持 project/workspace/session/editor/check/category/severity/status/archived/q、offset/limit（每页最多 200）。列表、分层统计来自同一 SQL 读事务；BUILDING/UNAVAILABLE/PARTIAL 不解释为零风险。

POST `/api/actions` 接受 items，每项为 id 和 request；request 包含 action、request_id、expected_revision、fields、reason。动作 EDIT、ARCHIVE、UNARCHIVE、DEFER、EXCLUDE、RESTORE、REPAIR、CANCEL_REPAIR；DEFER/EXCLUDE 必须提供理由。返回每项 saved/repeated/revision 或固定错误码。`/api/manual` 只允许绑定已有签名检查的 anchor_id；`/api/config` 校验 expected_revision 并原子替换，NEXT_BATCH 生效。写路由同时校验 Cookie、Origin 和 X-CSRF-Token；内部健康/受控重启另用服务凭据。

`development_review` 新增 `manage_development_audit` 操作，沿原 workspace_path/session_ref/check_ref，action 为 prepare/status/started/cancel/unsupported/failed。prepare 发出 audit_id、dirty_seq、证据、未读范围与租约；started 必须提供真实 agent_ref。`submit_development_review` 增加可选 audit_id，原顶层 scan_id 去重协议保持不变。输入版本、证据、权限和租约均在保存时校验；实际发现与覆盖提交保持原 observations/business_reviews 契约。

外部平台适配待定；没有通用任意 URL 上传接口。导出不触发扫描、复核或修复。

GET /api/entities?kind=editor|project|workspace|session|trash 返回资源和当前 revision。POST 同路径接收 action=delete|restore、kind、id、expected_revision、request_id，删除作用于当前版本集合。仪表盘 query 返回 finding_metrics.scanner/confirmed 各自 total/categories，和列表统计使用同一事务及删除过滤。

## 历史读取诊断

风险查询保留 partial/issues，新增 diagnostics（code、message、editor、workspace_id、database）及 warnings。目录不存在属于非阻断历史提示，不等同于签名失败。diagnostics 不包含密钥、原始异常或记录正文；页面可展开查看受影响范围。BUILDING 单独展示“历史索引尚未完成”。

Catalog.refresh 使用 records(complete=True) 建立完整的后台读索引；扫描库每次 fetchmany 100 行，签名历史每次 128 行，分页读取不构成总量截断。直接旧预览入口仍有显式容量边界。完整性仅指当前已接入本机状态目录的开发账本及原始扫描；严格审计和其他数据目录并未因此接入。

资源列表新增 parents（project_id、workspace_id、editor、workspace）与 workspace_count，来自同一可见记录快照。原资源 scope/ID 与删除接口不变；前端按父级身份联动筛选，不按名称关联。设置仅调整呈现，原配置字段、类型和写入接口保持不变。


## 会话流程修复接口

ReviewSubmission 原始契约现接受可选 audit_id，与分组路由和实际 submit_development_review 签名一致。未带 audit_id 的旧扫描提交兼容；不放宽 owner、dirty_seq、租约或证据哈希检查。开发期保存回执可为 WAITING_FOR_STATIC_SCAN：review_saved/post_commit_read 表达真实保存状态，最终报告等待正常 Stop，不要求模型主动轮询或重新扫描。若扫描在现有预算内尚未完成，Stop 对本轮已保存业务确认项发出一次报告兜底（stop_audit_incomplete_notice_seq），沿成功回执交付并明确扫描未完成；不追加等待或新扫描。

manage_development_audit 的 started 只增加 audit_id 和 agent_ref，不接受 expected_seq 或 scan_id；提交判断才传 expected_seq。补读参数为 start_line/end_line。审计 PARTIAL 表示已提交但存在覆盖限制，执行租约已释放，仍保留未覆盖路径；COMPLETE、PARTIAL 均在扫描发布时核验依赖证据。failed 保留 HOST_AUDIT_FAILED。

Codex 原生 Stop 在关闭复核、有风险或未完成审计时发出一次统一短提示，内部 closeout 视图指定 REPORT 分支。调用沿当前原会话读取保存批次，禁止重扫或追加判断。stop_report_notice / stop_review_notice 按输入和扫描版本去重，不等于用户已读或宿主提交报告。stop_activity_previous 在原签名检查内保存有界先前回合，避免同归属并行子回合覆盖主回合的待收尾边界。

GET /api/detail 必须带 id、revision，仅可再带 context（0–20，默认 5）。服务端由已签名风险派生文件路径，禁止任意 path 参数；校验回收站可见性、版本、相对路径和无链接文件读取。响应含 absolute_path、line_start/end、可确定的 function、historical/current 代码块及缺失提示，最多 80 行、每行 600 字符、24k 字符；不会写入取证账本或启动扫描。多行凭据先整文件脱敏再截取。版本一致只指所读代码摘要匹配，不代表重新验证漏洞。


## Codex 统一收尾提示

待复核、待报告及扫描未完成统一显示 `正在整理安全检查结果。（检查编号 …）`。提示不携带工作区、会话引用、扫描编号、JSON 或执行规则。内部会话指导使用当前连接的 session_ref 与原 check_ref，调用 `get_development_risks(view="closeout")`。服务端签名检查记录的 stop_closeout_notice 固定 dirty_seq、scan_id 和处理分支。

- REVIEW：读取本批候选和证据，沿原证据、编号及版本校验提交，保留完整漏洞报告；既有批次提交、首次保存及 final_report 语义不变。
- REPORT：只交付保存的 report_text 与 session_url。关闭复核的候选继续明确未经 Agent 确认；不补做复核、不重复提交。
- INCOMPLETE：只交付已保存的本轮业务漏洞、实际扫描未完成状态和会话链接，不等待、不轮询、不新开审计。尚未完成不得报告为零漏洞。首读时同一编辑版本的扫描恰好完成，可原子转入 REVIEW 或 REPORT；新编辑不能替代原批次。

`scope_unknown` 与 `file_watch_gaps` 保留原始诊断语义，供内部排查；不在用户报告追加采集范围未知提示。`batch_report_page` 在已完成、无实际扫描 gaps 的批次可输出“本批已记录文件的扫描已完成。”，不声明全项目覆盖。零候选完成批次不因 scope_unknown 单独触发 Stop；NO_OBSERVED_CHANGES 不声明扫描成功。INCOMPLETE 继续说明真实未完成/失败原因，不追加文件收集泛化提示。真实扫描 gaps、复核决策、会话链接和版本校验不变。

开发记录新增 `watch_paths`，只由已验证的监听写入路径生成，不能以缺少 explicit_paths 推断来源。两类记录允许交集，直接编辑优先。收尾 `scope` 及原批次交付快照增加 `explicit_paths`、`watch_paths`、`skipped_missing_watch_paths`；列表摘要仍仅返回路径计数，不扩展分页正文。后者只表示收尾原有 lstat 已确认不存在的监听补充路径，不表示扫描通过；新路径事件撤销该路径的旧跳过记录，新批次清理来源及跳过记录。旧快照不重写，来源缺失沿原严格路径处理。

分页沿 next_action，带返回的 expected_seq、scan_id 和 view=closeout；版本变化拒绝混读。末页无剩余待办时 next_action 为空。提示去重仅表示已发出交接，不写入“用户已读”或虚构“报告送达”。报告保持可独立读懂漏洞情况的完整交付，最后附本会话风险管理链接。详细规则仅放内部会话指导、工具说明和随安装分发的指导文件。


## 按数据量交付开发复核

`development.review_response_bytes` 在产品设置的“开发收尾”分类内配置，默认 65536，允许 16384–262144 字节，保存后从下一检查批次生效。已有批次使用自己的配置快照，旧快照缺字段时采用默认值。预算针对工具返回的逻辑 JSON 正文；MCP 外层以及同时发送 text/structuredContent 的重复封装另计，不能将该值解释为模型 token 数或网络包上限。历史 summary/full 仍默认 20 条，显式 limit 保持 1–20 的兼容限制。

`get_development_risks(view=review/closeout)` 不传 limit 时按响应预算规划候选页。固定扫描范围决定 offset，已提交候选不使后续位置前移；续页携带 expected_seq 与 scan_id，版本改变即拒绝。首包先保留候选完整范围，再补上下文；同文件重叠窗口在原 80 行上限内合并、跨文件轮转分配。源码正文预算最多 16 KiB，并计入整包预算。candidate.evidence_status 为 READY/MISSING；预算不足或读取失败不得当作已完成复核。超大扫描描述明确列入 metadata_omitted，编号、位置与原账本保留。

`read_development_risk_context(windows=[...])` 仍最多 20 窗、每窗最多 80 行。相关文件在各窗内传 related=true，不能绕过路径、归属和源码新鲜度校验。重叠窗合并后顺序读取，成功收据在 evidence，失败/预算不足在 errors；单窗失败不丢弃其他成功结果，批次版本变化仍拒绝整个响应。单文件旧调用保持原异常语义。读取并不保存复核结论。

`submit_development_review(response_view=final_report)` 沿原事务保存后，从同批完整账本读回并生成整批报告。误报/重复项整批汇总，确认项四段报告、覆盖缺口及 session_url 保留。仅完整报告正文超预算时按字符位置拆成可无损拼接的 report_text 片段，next_action 指向 `view=final_report`，携带 report_digest、输入和扫描版本。内容变化拒绝旧续页。不能逐片重做汇总、重新提交或根据读取声称用户已读。尚未完成复核返回有界 review_receipt 和待办数量，沿同批 review 续读；开发期 WAITING_FOR_STATIC_SCAN 保留等待正常收尾的指导，不主动轮询。保存成功但读回失败仅续读，不重提。每次提交仍最多 50 项，不能承诺任意大批次都只需两次调用。

新增窗口规划、证据准备与报告组装时间点写入现有 review_timing；只在验收显式启用磁盘 trace 和模型遥测。以上工作发生在 Stop 交接后的读取/提交中；正常扫描与 Stop 等待预算不增加步骤；自动模式的证据准备移至原结果读取，不在命令 Hook 内重复预取。

## 用户报告中的覆盖说明

最终报告保留必要的中文覆盖限制说明，不把内部 gaps 枚举直接拼接进 report_text。结构化 gaps 与原始诊断保持原值，供内部分析和后台诊断使用；该展示变化不修改扫描覆盖判定，不触发补扫或额外 MCP 调用。


## 三种配置收尾与增量审计交接

`stream_prepare` 在原回执提供 `registration`；宿主创建真实只读子 Agent 后，补入真实 `agent_ref`、父 `session_ref` 调用 `stream_started`，并回传 prepare 的 `audit_token`。started 验证凭据并返回可直接执行的 `child_call`，包含工作区、检查引用、执行者、专用凭据与 claim 动作。旧 started 不传令牌仍可读取绑定状态，但不会得到完整 child_call；持久记录只保留凭据哈希。

子任务首次 claim 返回固定批次、首批证据及从 Observation 模型生成的必填字段清单。证据足够直接 submit；不重新读取同一窗口。参数校验失败返回有界 `field_errors`，嵌套字段使用 observations.0.description 等路径；未知字段只返回合法字段列表，不回显输入值、任意键名或凭据。领取、保存和状态查询仍沿原权限边界。

`stream_failed` 由父会话携带已绑定 agent_ref 记录执行失败；不需要旧协议的 audit_id。`executor_stage` 区分未派发、已派发、已领取与失败，不能把登记成功当作审计已保存。已绑定 continuation 直接提供原执行者，无需先额外查询状态。

静态复核完成而业务审计未完成时，原提交回执仍返回完整静态报告、链接和独立 audit_continuation；`STATIC_REPORT_READY_AUDIT_PENDING` 不代表业务审计完成。候选首次响应可附同文件当前有效 `related_confirmed`，仅供判断是否同一问题。跨来源关联使用原 duplicate_of，须校验当前审计结果与覆盖扫描位置的证据；不以文件相同自动合并。相关摘要受原响应预算裁剪，不挤掉候选身份；截断明确标识。


## 命令宿主审计续接

Cursor / WorkBuddy 的编辑适配通过 host_development 请求已有审计 offer 的执行者续接提示；同一轮已有有效绑定时返回实际子任务 ID 和沿原 child_call 继续的说明，不再提示首次注册。复用原事务、去重及节流，不新增状态查询或模型调度。business_audit.offer 的 prefer_active_executor 默认关闭，Codex 原调用保持；WorkBuddy 的后台参数和 resume/实际 ID 语义只在 workbuddy_hook 适配层说明。该声明不替代真实宿主验收，当前边界见 [宿主兼容验收](HOST_PARITY_ACCEPTANCE.md)。
