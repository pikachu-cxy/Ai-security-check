# 失联任务与并发改动归属

新任务只在捕获修改前基线之前记录失联证据。旧任务必须同时满足：属于不能跨连接恢复的 connection 范围、协议为 v3、仍处于未完成静态检查前的 ACTIVE、完整活动租约已经过期、原进程确已退出或 PID 已被不同进程复用。新任务结束时，旧任务的代次、归属和进程身份必须保持一致，且失联状态仍可确认，才不再把它计入本次并发时间窗。

这个判断只影响新任务的归属限制，不会关闭、删除、接管旧任务，也不会清理旧风险、改变原任务基线或重置复核额度。重复 begin 沿用原记录；在结束时才发现旧进程退出，不能补建开始时的失联证据。

Codex/Cursor 的聊天会话可以在 MCP 重连后继续，短命 Hook 进程也不是编辑任务的所有者。因此聊天任务、未知进程状态、缺失元数据、旧协议和正在检查或复核的任务仍保留并发归属限制。历史 Hook 任务缺少可靠会话结束信号时，不能仅凭长时间无活动自动排除。相同/不同文件上的真实并发均保持原有保守规则。

回归入口：`python -m pytest tests/test_task_disconnection.py tests/test_task_ownership.py tests/test_task_attribution_presentation.py tests/test_task_review_invariants.py tests/test_task_review_v3_state.py tests/test_task_review_revisions.py tests/test_task_scan_attempt.py tests/test_task_risk_dispositions.py tests/test_task_risk_ledger_watermark.py`。

覆盖修改前失联与任务期间失联、进程存活/未知/PID 复用、租约边界、开始捕获时竞态、后续 Hook 或任务活动、重复开始、会话隔离、真实子进程退出与 MCP 路由。相关复核与风险回归继续验证未完成范围不得标成完整核查，部分覆盖不得关闭历史风险。模拟扫描器回归与真实进程检查各自说明证据范围，不冒充双宿主人工实机验收。

2026-10-20 本地验收：以上关联回归 137 项通过；额外运行 `tests/test_task_security.py tests/test_cursor_automatic.py`，82 项通过，共 219 项。实际退出子进程及真实 MCP 路由用例已执行；检查器结果与宿主提交由测试夹具模拟的部分仍按其原证据范围解释。
