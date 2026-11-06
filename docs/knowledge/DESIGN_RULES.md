# 当前设计约束与目的

这些条目解释当前实现为何这样组织，并给出修改时应保留的性质。它们不保存演进历史，也不构成新的操作授权。

| 设计约束 | 目的 | 对应代码与修改要求 |
| --- | --- | --- |
| 路径记录与扫描分离 | 避免每次写入都累积重扫，减少开发等待 | `development_check.py`、`development_file_watch.py`；记录阶段不盘点全项目、不启动扫描 |
| 原引用与输入版本绑定 | 防止把另一任务或旧源码结果当成本轮结论 | `workspace_application.py`、`tasks/ownership.py`、`development_check.py`；保留 owner、工作区和序号校验 |
| 轻量检查查询与执行分离 | 让刷新状态的成本和副作用可预期 | `development_check.py` 的保存结果读取与等待不扫描、不重哈希源码；不能推广成所有 `get_*` 接口都不做版本核验，例如 `closeout.py` 会验证当前版本 |
| 文件监听记录时间窗而非作者身份 | 支持工具子进程与同工作区并发写入 | `development_file_watch.py`；不能声称证明是谁修改，也不能把未触碰的旧脏文件全纳入 |
| 有界 Stop 与后台交付 | 保留未完成事实，同时避免相同终态无限续接 | `development_stop.py`、`development_delivery.py`；当前输入版本已有终态结果且所需复核完成（或按配置全部跳过）时，覆盖限制本身不触发 Stop 续接。保留 PARTIAL 与缺口并如实报告；FAILED 同一输入版本只发一次非阻塞提示且跨重连去重；放行不表示用户已看见，新编辑仍需收尾 |
| 协议层薄、领域层负责授权 | 防止不同宿主形成几套不一致行为 | `mcp_contracts.py`、`mcp_tools/`、`workspace_application.py`；分组只适配路由 |
| 证据、判断、处置、修复分别保存 | 保留审计依据与用户决定，防止误把排除当修复 | `development_risks.py`、`risk_disposition.py`、`tasks/risk_ledger.py`；零告警不能关闭原风险 |
| 指定修复先核对影响和范围 | 避免工具建议或模型判断越过用户选择 | `repair_impact*`、`mcp_tools/repair.py`；实际修改不得超出准备与授权范围 |
| 固定输入和租约约束结果发布 | 防止并发、取消或源码变化造成过期结果覆盖 | `scan_request.py`、`scan_attempt.py`；条件发布不可被普通锁或缓存命中替代 |
| 普通开发轻量收尾 | 编辑结束后避免重复读取输入和生成语义定位快照 | `development_check_worker.py` 使用 `CAPTURED` 表示捕获版本；只检查任务/租约，后续编辑由序号保持待检查，不证明磁盘未变化；严格审计和修复验证保留原逻辑 |
| 安装包逐文件校验与实际启动器验证 | 防止包损坏、路径错配或旧启动器让版本显示失真 | `delivery.py`、`distribution/build/launcher.c`、`personal_install.py`；并行可以改执行方式，不能省校验项；本地哈希证明完整性，不单独证明发布者身份 |
| 原生启动器按内容选择，避免覆盖运行中旧文件 | 允许已有安装升级并保护正在运行的连接 | `delivery.py`；旧连接可继续存在，新连接必须走已验证新构建 |
| 安装关键路径延后旧槽位清理 | 避免清理耗时或误删使用中的构建 | `personal_install.py` 返回显式维护提示；`delivery.py:cleanup_after_reconnect` 另保留受 frozen/MCP 启动、活动构建及 `cleanup_ready` 限制的维护入口，不能描述成任何情况下都只手动清理 |
| 性能数字绑定测量口径 | 防止通过排除真实工作或重复计算等待产生虚假提速 | `performance_trace.py`、`scripts/performance/`；保留失败、缓存、构建、样本与未知时间 |

对这些边界有新需求时，先说明当前行为、拟改变的行为、影响的调用者和验收标准；不要以“统一架构”名义重写无关模块。

**开发会话归属**。工具明确给出的完整编辑范围可用于收窄观察。Shell 时间窗只证明某个工作目录内发生过变化，不能据此认定写入会话。在同目录并发及父子 worktree 重叠观察中保留不确定路径的检查。重复证据关联限于扫描批次与输入版本，不跨会话查询或合并账本。
