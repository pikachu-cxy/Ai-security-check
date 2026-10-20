# 项目文档

更新日期：2026-10-20。当前资料已合并过时阶段教程和重复验收记录，旧版本通过 Git 历史查阅。

| 目标 | 入口 |
| --- | --- |
| 安装当前源码、日常使用 | [项目 README](../README.md)、[详细安装指南](PILOT_INSTALL_AND_USE.zh-CN.md) |
| 当前实现、验证及缺口 | [开发进度](DEVELOPMENT_PROGRESS.md)、[近期计划](NEXT_DEVELOPMENT_PLAN.zh-CN.md) |
| 架构、流程与历史冻结交付 | [架构实施记录](ARCHITECTURE_UNIFICATION_COMPLETION.zh-CN.md)、[技术架构](ARCHITECTURE.md)、[总计划](ARCHITECTURE_UNIFICATION_PLAN.zh-CN.md) |
| 本轮发现、修复、复查与误报手测 | [当前验收](RUNTIME_CHAIN_REGRESSION_ACCEPTANCE.zh-CN.md) |
| 持久化、版本与诊断 | [恢复清单](PERSISTENCE_TRANSACTION_RECOVERY.zh-CN.md)、[v3 升级](TASK_REVIEW_V3_ONLY.zh-CN.md)、[核查诊断](ARCHITECTURE_REVIEW_DIAGNOSIS.zh-CN.md) |
| 宿主与平台 | [支持状态](HOST_SUPPORT.md)、[Cursor 安装](guides/CURSOR_INSTALL_AND_TEST.zh-CN.md)、[操作指南](guides/README.md) |
| 恢复开发 | [开发交接](DEVELOPMENT_HANDOFF.zh-CN.md)、[项目上下文](PROJECT_CONTEXT.md) |
| 规则、设计及性能 | [设计导航](design/README.md)、[性能数据](ARCHITECTURE_PERFORMANCE.zh-CN.md) |
| 上下文开销与实际 token 对比 | [监测、导入与实验方法（当前源码）](guides/CONTEXT_COST_MONITORING.zh-CN.md) |
| 实时消耗可视化与采集开关 | [独立页面、任务窗口、计量边界与移除方式](guides/LIVE_MONITORING.zh-CN.md) |
| 产品和企业边界 | [产品规划](PRODUCT_ROADMAP.md)、[功能验证](FUNCTIONAL_VERIFICATION.md) |
| 旧发行说明 | [历史发行](archive/2026-10/README.md) |

源码回归、安装包、当前运行连接和真实桌面验收分别记录，不相互继承通过。自动回归需要的合成 fixture 和旧 writer 兼容语料保留；临时测试目录、扫描数据库、原始聊天、缓存及构建包不提交。
