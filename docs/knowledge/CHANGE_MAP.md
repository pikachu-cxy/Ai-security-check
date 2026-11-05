# 从开发需求定位代码

所有源码简称相对 `src/security_runtime/`。先读入口及相关服务，再用测试定位预期语义；不要只改调用包装层让错误消失。

| 需求或现象 | 优先查看代码 | 应核对的测试或资源 |
| --- | --- | --- |
| CLI 参数、输出或退出码 | `cli.py:main` | `tests/` 中 CLI 与对应领域测试；`pyproject.toml` 命令入口 |
| 新增或修改 MCP 对外入口/内部操作 | `mcp_tools/`、`mcp_server.py`、`mcp_tool_groups.py`、`mcp_contracts.py` | `tests/test_mcp_tool_groups.py`；具体领域 MCP 测试；重建 MCP 目录 |
| 字段报错、复核提交结构 | `development_risks.py` 的输入模型与 `review_input_failure`、`mcp_contracts.py` | `tests/test_development_risks.py`、`tests/test_mcp_tool_groups.py` |
| 工作区被拒绝、会话错绑 | `global_mcp.py:GlobalWorkspaces`、`global_workspace.py`、`workspace_binding_status.py`、`workspace_application.py` | `tests/test_global_workspace_binding.py`、`tests/snapshots/test_workspace_binding_status.py` |
| 宿主命令被误当编辑 | `shell_classification.py`、`codex_event_adapter.py`、`host_event_runtime.py` | `tests/test_shell_classification.py` 与 Hook 测试 |
| 文件未采集、误采历史改动 | `development_file_watch.py`、`development_scope.py`、`development_check.py` | `tests/test_development_file_watch.py`、`tests/test_development_check.py` |
| 重复扫描、后台任务迟迟不结束 | `development_check_worker.py`、`development_scheduler.py`、`development_check.py` | `tests/test_development_check.py`、`tests/test_development_check_wait.py` |
| Stop 反复续接或结果未交付 | `development_stop.py`、`development_continuation.py`、`development_delivery.py` | `tests/test_user_config_stop.py` 与 development delivery 测试 |
| 扫描范围、输入版本或取消 | `scan_request.py`、`scan_attempt.py`、`runtime.py` | `tests/test_scan_attempt.py`、`tests/test_explicit_scan_attempt.py` |
| 扫描器执行、超时、结果归一化 | `scanners.py`、`processes.py`、`runtime.py`、`models.py` | 对应 scanner、runtime、dependency 测试与隔离语料 |
| 规则选择、规则包或第三方许可 | `rules/`、`opengrep_rules.json`、`guidance/`，用符号索引找规则装载服务 | `tests/rules/`、`tests/rule_program/`；`LICENSES/` 和 `scripts/build/dependency_notices.py` |
| 风险误报、暂缓、排除与提醒 | `development_risks.py`、`risk_disposition.py`、`finding_feedback.py` | `tests/test_development_risks.py` 及 disposition/feedback 测试 |
| 严格任务证据、窗口与覆盖 | `tasks/security.py`、`tasks/preimages.py`、`task_review/` | `tests/tasks/`、`tests/task_review/` |
| 修复授权、影响评估、原问题验证 | `repair_impact*`、`mcp_tools/repair.py`、`tasks/` | 对应 impact/fix/verification 测试；勿通过新零告警关闭原问题 |
| 安装慢、重复安装、升级残留 | `personal_install.py:install_personal_codex`、`delivery.py:StableDelivery`、`install_checks.py` | `tests/test_personal_install.py`、`tests/test_install_efficiency.py`、`tests/test_delivery.py` |
| 启动器指向旧构建 | `delivery.py`、`distribution/build/launcher.c`、`distribution/build/entry.py` | 同时核对包、活动指针、配置命令、实际进程；`scripts/performance/install_windows.py` |
| Codex 配置冲突或 Skill | `global_integration.py`、`review_skill.py`、`owned_json.py` | `tests/guidance/`、全局集成测试；使用实际配置中的状态目录 |
| Cursor 或 WorkBuddy 接入 | `cursor_connector.py`、`workbuddy_integration.py` 及对应 Hook 模块 | `tests/test_cursor_automatic.py`、`tests/test_workbuddy_connector.py` |
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
