# 从开发需求定位代码

## 只读与清理误触发

监听路径项目边界：`development_file_watch.py:_Window.paths`，回归 `test_development_file_watch.py`；项目外通知不写编辑账本，混合通知仅保留项目内路径。

命令内受限路径/内容变量与常量切片：`shell_classification.py`；工作区外字面量清理分类与 Pre/Post 跳过：`host_tool_events.py`、`host_events.py`、`host_event_runtime.py`、`global_mcp.py`；Cursor 两类入口：`cursor_event_adapter.py`、`cursor_tasks.py`、`cursor_automatic.py`；诊断与编辑事件准入：`recent_hooks.py`、`host_event_journal.py`。回归：`test_shell_classification.py`、`test_lightweight_hooks.py`，以及宿主事件、监听和补充路径测试。不得把任意清理脚本或所有 Shell 调用直接视为只读。

## 原生后台链接与 Agent 安装入口

后台构建身份：`dashboard_service.py`；无地址报告：`development_views.py`、`host_development.py`；无项目路径全局入口：`global_mcp.py`、`monitoring/mcp.py`。回归：`test_dashboard_service.py`、`test_report_missing_dashboard.py`。原生发行验证：`scripts/release/verify_release_smoke.py`；三平台替换流程：`.github/workflows/refresh-0314.yml`。Agent 安装指南：`website/public/install/agent.md`，首页与编辑器页面复用 `InstallRequest.vue`。

## Windows 用户目录与旧版迁移

共享路径：`user_paths.py`；一次性迁移、冲突与旧服务门槛：`windows_migration.py`；安装编排：`personal_install.py`、`cli.py`；配置/状态/组件入口：`user_config.py`、`storage.py`、`toolchain.py`；网站脚本：`website/public/install/windows.ps1`。回归：`test_windows_user_directories.py`、`test_personal_install.py`、`distribution/test_windows_web_install.py`。默认位置与迁移契约见 [接口设计](INTERFACES.md)。

## 审计轮次、晚到报告及漏洞分隔

父子开发任务 Stop 归属：`codex_turn_scope.py`、`development_stop.py`、`mcp_server.py`；测试 `test_delegated_development_closeout.py`。修后额外复测默认关闭：`user_config.py`、`development_risks.py`、`remediation.py`、`tasks/fix.py`、`repair_notifications.py` 及对应指导；测试 `test_repair_recheck_default.py`。验收与限制见 [0.3.14 验收](RELEASE_0314_ACCEPTANCE.md)。

轮内执行授权：`audit_stream_service.py`、`incremental_audit.py`、`business_audit.py`；晚到结果交付：`development_risks.py`、`development_stop.py`；同一 SQL 执行位置关联：`development_duplicates.py`；报告标题和分隔：`development_report.py`、`development_views.py`。回归：`test_audit_round_lifecycle.py`、`test_three_mode_repairs.py`、`test_uat_closeout_repairs.py`。内部指导与随包引用通过 `sync_review_skill.py` 同步。

## 开发收尾验收修复

报告：development_report.py / development_views.py / dashboard_presentation.py；用户处置：development_disposition.py / development_risks.py / risk_management.py / mcp_contracts.py；审计覆盖：BusinessReview / review_progress / business_audit.py；等待：stop_wait_policy.py / development_check.py / development_stop.py / user_config.py / codex_integration.py。测试：test_uat_closeout_repairs.py、test_stop_wait_policy.py、已有报告/恢复/安装/后台回归；见 UAT_REPAIR_ACCEPTANCE.md。

## 自研数据流停用

入口排除：scanners.ScannerRegistry/active_provider；扫描复用：scan_reuse._known_adapters；能力声明：guidance/host_guidance.py；健康与设置：dashboard_health.py/assets/risk_dashboard.html。回归：test_retired_dataflow.py、test_go_sql.py、test_scan_reuse.py、test_dashboard_health.py、test_risk_dashboard_ui.cjs。保留模型源码供历史兼容及离线单元测试，不在产品注册中使用。


## 中文说明与聊天名称

- 中文展示：dashboard_presentation.py；后台查询和导出：dashboard_catalog.py/dashboard_export.py。
- 名称同步与别名：dashboard_sessions.py；资源展示及 HTTP：dashboard_entities.py/risk_dashboard.py。
- 相关验证：test_dashboard_presentation.py、test_dashboard_sessions.py、test_dashboard_entities.py、test_risk_dashboard_ui.cjs；结果见 WEB_PRESENTATION_ACCEPTANCE.md。


所有源码简称相对 `src/security_runtime/`。先读入口及相关服务，再用测试定位预期语义；不要只改调用包装层让错误消失。

| 需求或现象 | 优先查看代码 | 应核对的测试或资源 |
| --- | --- | --- |
| 晚到结果补交、断连未提交任务恢复、工作进程退出 | `development_recovery.py`、`development_stop.py:saved_handoff`、`development_scheduler.py`、`development_check_worker.py:saved_scan` | `test_development_recovery.py`；见 [恢复验收](RECOVERY_ACCEPTANCE.md) |
| 后台健康监控、工具/规则/漏洞库信息、MCP 独立探测 | `dashboard_health.py`、`risk_dashboard.py`、`dashboard_service.py`、`assets/risk_dashboard.html` | `test_dashboard_health.py`、`test_dashboard_service.py`、`test_risk_dashboard_ui.cjs`；仅按需，不进入扫描/Stop |
| MCP 连接关闭、退出原因缺失、只读聊天恢复旧检查 | `connection_lifecycle.py`、`connection_guard.py`、`codex_integration.py:product_hooks` | `test_connection_lifecycle.py`；正常 Stop 不新增诊断磁盘写入或等待 |
| 复核响应预算、证据重叠、补读和整批报告 | `review_delivery.py`、`development_views.py`、`development_risks.py`、`user_config.py`、`assets/risk_dashboard.html` | `test_review_delivery.py`、development risk/MCP/closeout 测试、页面设置测试；不得移入 Stop |
| Stop 静默遗漏、同会话重连恢复、诊断被工具流量覆盖 | `development_stop.py:interrupted_notice`、`development_continuation.py:context`、`global_mcp.py`、`development_views.py:closeout_page`、`recent_hooks.py` | `test_stop_recovery_minimal.py`、`test_development_delivery_mcp.py`、`test_recent_hook_diagnostics.py`；已有结果补交；未完成原任务有界恢复 |
| CLI 参数、输出或退出码 | `cli.py:main` | `tests/` 中 CLI 与对应领域测试；`pyproject.toml` 命令入口 |
| 新增或修改 MCP 对外入口/内部操作 | `mcp_tools/`、`mcp_server.py`、`mcp_tool_groups.py`、`mcp_contracts.py` | `tests/test_mcp_tool_groups.py`；具体领域 MCP 测试；重建 MCP 目录 |
| 字段报错、复核提交结构 | `development_risks.py` 的输入模型与 `review_input_failure`、`mcp_contracts.py` | `tests/test_development_risks.py`、`tests/test_mcp_tool_groups.py` |
| 工作区被拒绝、会话错绑 | `global_mcp.py:GlobalWorkspaces`、`global_workspace.py`、`workspace_binding_status.py`、`workspace_application.py` | `tests/test_global_workspace_binding.py`、`tests/snapshots/test_workspace_binding_status.py` |
| 宿主命令被误当编辑 | `shell_classification.py`、`codex_event_adapter.py`、`host_event_runtime.py` | `tests/test_shell_classification.py` 与 Hook 测试 |
| 文件未采集、误采历史改动 | `development_file_watch.py`、`watch_control.py`、`development_scope.py`、`development_check.py` | `tests/test_development_file_watch.py`、`tests/test_watch_control.py`、`tests/test_development_check.py` |
| 直接编辑与监听补充分类、临时文件删除导致缺口 | `development_check.py:append/finish`、`development_scope.py:watch_only_paths/separate_directories`、`development_delivery.py:publish` | `test_supplemental_scope.py`、`test_development_file_watch.py`；来源正向记录、直接编辑优先、仅不存在的补充文件静默跳过、已保存批次来源固定 |
| 已记录文件检查完成却提示范围未知 | `development_views.py:batch_report_page/closeout_page`、`development_stop.py:native_closeout`、`development_reporting.py`、`guidance/host_guidance.py` | `test_review_delivery.py`、`test_closeout_notice.py`；采集诊断保留内部，真正扫描失败和覆盖限制仍交付 |
| 重复扫描、后台任务迟迟不结束 | `development_check_worker.py`、`development_scheduler.py`、`development_check.py` | `tests/test_development_check.py`、`tests/test_development_check_wait.py` |
| 原生自动收尾、重复 Stop 或缺少复核证据 | `development_stop.py`、`development_continuation.py`、`development_delivery.py` | `tests/test_user_config_stop.py` 、`tests/test_workbuddy_connector.py` 与 development delivery 测试 |
| 扫描范围、输入版本或取消 | `scan_request.py`、`scan_attempt.py`、`runtime.py` | `tests/test_scan_attempt.py`、`tests/test_explicit_scan_attempt.py` |
| 扫描器执行、超时、结果归一化 | `scanners.py`、`processes.py`、`runtime.py`、`models.py` | 对应 scanner、runtime、dependency 测试与隔离语料 |
| 规则选择、规则包或第三方许可 | `rules/`、`opengrep_rules.json`、`guidance/`，用符号索引找规则装载服务 | `tests/rules/`、`tests/rule_program/`；`LICENSES/` 和 `scripts/build/dependency_notices.py` |
| 风险误报、暂缓、排除与提醒 | `development_risks.py`、`risk_disposition.py`、`finding_feedback.py` | `tests/test_development_risks.py` 及 disposition/feedback 测试 |
| 严格任务证据、窗口与覆盖 | `tasks/security.py`、`tasks/preimages.py`、`task_review/` | `tests/tasks/`、`tests/task_review/` |
| 修复授权、影响评估、原问题验证 | `repair_impact*`、`mcp_tools/repair.py`、`tasks/` | 对应 impact/fix/verification 测试；勿通过新零告警关闭原问题 |
| 安装慢、重复安装、升级残留 | `personal_install.py:install_personal_codex`、`delivery.py:StableDelivery`、`install_checks.py` | `tests/test_personal_install.py`、`tests/test_install_efficiency.py`、`tests/test_delivery.py` |
| 启动器指向旧构建 | `delivery.py`、`distribution/build/launcher.c`、`distribution/build/entry.py` | 同时核对包、活动指针、配置命令、实际进程；`scripts/performance/install_windows.py` |
| Codex 配置冲突或 Skill | `global_integration.py`、`review_skill.py`、`owned_json.py` | `tests/guidance/`、全局集成测试；使用实际配置中的状态目录 |
| Cursor 或 WorkBuddy 接入 | `host_lifecycle.py` 能力声明、`host_development.py` 共享交付上下文、`cursor_automatic.py` / `workbuddy_hook.py` 事件翻译；复用 `development_stop.py`、`development_recovery.py` 与审计领域服务 | `test_host_development_parity.py`、`test_cursor_automatic.py`、`test_workbuddy_connector.py`；真实状态见 [宿主验收](HOST_PARITY_ACCEPTANCE.md) |
| 下载脚本、原生包与发布 | `website/public/install/`、`scripts/build/`、`scripts/release/`、`.github/workflows/` | `tests/distribution/`；构建、上传、发布授权分开 |
| 计时缺失或时间口径 | `performance_trace.py`、`scripts/performance/measure.py`、`scripts/performance/report.py` | `tests/test_performance_trace.py`；区分安装、扫描、复核与宿主时间 |
| 普通开发收尾和 MCP 固定开销 | `development_check_worker.py`、`scan_attempt.py`、`workspace_application.py`、`global_mcp.py` | `tests/test_lightweight_closeout.py`；检查 CAPTURED、失效租约、工作区解析和版本缓存复用 |
| 仅显式授权的 BYOK 复核 | `triage_providers.py`、`triage.py`、`cli.py` | 相关 triage 测试；不得与默认宿主 Agent 复核混为一谈 |
| 风险仪表盘显示 | `risk_dashboard.py`、`assets/` | `tests/test_risk_dashboard.py`、`tests/test_risk_dashboard_ui.cjs` |
| Go 原生包缺少规则身份资源 | `go_sql.py`、`distribution/build/security-check.spec` | `tests/distribution/test_standalone_identity.py`；原生包最小 Go 扫描 |
| 用户配置和 Stop 预算 | `user_config.py`、`development_stop.py` | `tests/test_user_config_stop.py` |
| 本知识库与索引 | `docs/knowledge/`、`scripts/maintenance/knowledge_index.py`、`AGENTS.md` | 索引 `--check`、本地链接检查、实际符号查询 |

## 搜索方法

```powershell
python scripts/maintenance/knowledge_index.py --find StableDelivery
rg -n 'install_personal_codex' src tests scripts -g '*.py'
rg -n 'INSTALLED_LAUNCHER_IDENTITY_MISMATCH' src tests
```

先搜固定错误码或接口名，再搜调用方。带星号的模块族表示搜索线索，不是一个真实文件路径。索引中的行号会随代码变动，需要重新生成；修改前始终读取当前文件。

复核读取与调用成本：`development_views.py`、`mcp_tools/development_check.py`；回归见 `tests/test_development_risks.py`。索引无变化重写见 `scripts/maintenance/knowledge_index.py` 与 `tests/test_knowledge_index_writes.py`。

统一结果及旧数据兼容：`development_result_store.py`、`development_risks.py:publish_scan`、`development_check_worker.py`、`risk_dashboard.py`；测试 `tests/test_development_result_store.py` 与 `tests/test_development_check_wait.py`。

普通开发的会话归属与重复命中：编辑工具路径处理在 `host_tool_events.py`，取证及分组汇总在 `development_views.py`，同批关联与证据校验在 `development_risks.py`。纯删除的输入绑定与覆盖状态分别在 `runtime.py`、`development_check_worker.py`。对应回归在 `tests/test_lightweight_hooks.py`、`tests/test_development_risks.py`、`tests/test_development_check.py`；真实双 worktree 数据见[开发场景验收](DEVELOPMENT_ACCEPTANCE.md)。


后台风险服务生命周期、批次链接与存活探测位于 `dashboard_service.py`，HTTP 读接口与写入防护位于 `risk_dashboard.py`，批次归属与时间倒序索引位于 `dashboard_records.py:batch_keys` 与 `dashboard_catalog.py`（`risk_batches` 表、`activity_at` 列）；MCP 启动入口在 `cli.py`，完整报告链接在 `development_views.py`，统一结果链接在 `development_check.py`。相关回归为 `tests/test_dashboard_delivery.py`、`tests/test_dashboard_service.py`、`tests/test_risk_dashboard.py`、`tests/test_risk_dashboard_ui.cjs`、`tests/test_development_risks.py` 和 `tests/test_development_delivery.py`。

## 风险管理与并行业务审计

| 修改方向 | 源码 | 验证 |
| --- | --- | --- |
| 后台生命周期/认证/API/页面 | dashboard_service、risk_dashboard、assets/risk_dashboard.html | test_dashboard_service、test_risk_dashboard、test_risk_dashboard_ui.cjs |
| 项目与 worktree、查询/导出 | project_identity、dashboard_catalog、dashboard_records、dashboard_export | test_dashboard_management、官方 SARIF schema、隔离万级/十万级记录 |
| 用户处置、修复通知、设置 | risk_management、repair_notifications、development_risks、user_config | test_dashboard_management、test_user_config_stop |
| 开发期审计、预算、收尾 | business_audit、audit_leases、codex_mcp_hook、global_mcp、development_stop、development_views | test_business_audit、test_lightweight_hooks、test_development_review_completion |

同步修改 host_guidance 与 development_check_guidance 后运行 sync_review_skill.py；索引刷新不启动扫描。安装后分别核对源码、启动器、新连接和桌面驻留状态。

资源删除与恢复：dashboard_entities.py、dashboard_catalog.py、risk_dashboard.py；测试 test_dashboard_entities.py。分类占比：dashboard_records.py 提供事实标记，catalog 聚合，页面渲染；不会新增 Stop 操作。

历史目录删除、扫描截断或签名提示：`dashboard_history.py`（只读历史身份、分批读取与固定诊断）、`risk_dashboard.py`（聚合及非阻断目录提示）、`dashboard_catalog.py`（后台完整索引及密钥变更失效）、`assets/risk_dashboard.html`（诊断范围）。回归入口：`tests/test_dashboard_history.py`、`tests/test_dashboard_service.py`、`tests/test_risk_dashboard_ui.cjs`。不放宽 `DevelopmentCheckStore` 的活动工作区校验。

资源父子关系及导航：dashboard_entities.py 的 parents/workspace_count；assets/risk_dashboard.html 的 resourceNavigate、enterChildren、renderResourceContext。设置功能折叠：configForm/configInputs。对应 test_dashboard_entities.py 与 test_risk_dashboard_ui.cjs。

真实会话验收当前问题见 [FLOW_ACCEPTANCE](FLOW_ACCEPTANCE.md)：审计提交契约优先对齐 development_risks.ReviewSubmission、mcp_contracts 原始校验与 mcp_tools/development_check 提交签名；关闭复核后的报告交接检查 development_stop.native_closeout 与 hook_adapters；详情代码展示检查 dashboard_records.enrich 和页面 detail，不将复核理由当作原始代码片段。修复需覆盖 MCP 完整入口和用户可见交付，不只测领域服务。

具体开发拆分及验收门槛见 [FLOW_REPAIR_PLAN](FLOW_REPAIR_PLAN.md)。报告续接去重不等于宿主已提交报告；可信回调沿 development_delivery.acknowledge，不能增加模型自报成功的确认入口。详情代码读取按需进行，不调用开发复核写接口。


本期修复验证见 [FLOW_REPAIR_ACCEPTANCE](FLOW_REPAIR_ACCEPTANCE.md)。并行回合资格由 development_check.note_activity 与 development_stop.fallback 维护；详情代码 GET 由 dashboard_detail.detail、risk_dashboard.Handler 和页面 renderCode 负责。专项为 test_flow_repairs、test_business_audit、test_development_delivery_mcp 和 test_risk_dashboard_ui.cjs；不要把源码展示接入扫描热路径。

左侧折叠导航：`assets/risk_dashboard.html` 的 nav-group 原生 details/summary 与 showView 自动展开；项目、工作区、会话筛选仍由原 resourceNavigate/enterChildren 维护。

安装目录与编译产物范围：scope_policy.py 定义轻量共享策略；target.py 在大小限制之前排除确认的编译文件；development_file_watch.py 在记录事件前应用；development_scope.py/development_check.py 在显式编辑与收尾入口过滤。测试 test_scope_policy.py、test_development_file_watch.py 与 test_development_check.py。


短提示收尾：`development_stop.py` 保存分支与批次；`development_views.py:closeout_page` 解析、处理扫描完成竞态、分页并附会话链接；`tasks/ownership.py`、`guidance/` 与 `review_skill.py` 提供内部操作规则。回归：`test_closeout_notice.py`、`test_flow_repairs.py`。

OpenGrep macOS 载荷复用：`opengrep_payload.py` 在安装/显式准备时从固定校验和的官方启动器导出私有载荷，`toolchain.py` 解析及校验；`install_readiness.py`、`personal_install.py`、`cli.py` 只在安装/准备入口启用。`--status`、普通扫描和 Stop 不进行解压安装。回归：`test_opengrep_payload.py`、`test_install_readiness.py`。


## 三种配置验收修复入口

- 排队任务与工作进程租约：`development_check.py::projection`；只检查 RUNNING 且 ticket 匹配的租约。回归 `test_development_check_wait.py`。
- 旧判断隔离：`development_risks.py::current_assessment/current_risk`；复用当前版本判断，历史记录不重写。
- 完整报告与跨来源重复项：`development_views.py`、`review_delivery.py`、`development_risks.py::_submit`；只在结果读取与保存阶段处理。
- 子任务交接与字段错误：`audit_stream_service.py`、`audit_stream_adapter.py`、`business_audit.py`、`mcp_tool_groups.py`；回归 `test_three_mode_repairs.py`、`test_audit_stream_mcp.py`。
- 普通零候选回复：`tasks/ownership.py::session_context` 与 `guidance/development_check_guidance.py`；不自行预告待返回报告。
