# 设计与开发参考

先读[当前架构与流程](../ARCHITECTURE_UNIFICATION_COMPLETION.zh-CN.md)、[技术架构](../ARCHITECTURE.md)和[宿主支持](../HOST_SUPPORT.md)。

| 主题 | 资料 |
| --- | --- |
| 核心原则 | [架构决策](DECISIONS.md)、[扩展接口](EXTENDING.md) |
| 开发核查 | [核查契约](SECURITY_REVIEW.md)、[任务设计](TASK_SECURITY_REVIEW_DESIGN.zh-CN.md)、[会话归属](TASK_SESSION_OWNERSHIP_20261016.md) |
| 运行及恢复 | [证据与恢复](RUNTIME_EVIDENCE_AND_RECOVERY.zh-CN.md)、[持久事务](../PERSISTENCE_TRANSACTION_RECOVERY.zh-CN.md) |
| 修复与影响 | [修复授权](SMART_AUTO_REMEDIATION.md)、[影响评估](REPAIR_IMPACT_ASSESSMENT_DESIGN.zh-CN.md) |
| 规则范围 | [规则基础](RULE_FOUNDATION.md)、[规则计划](RULE_PROGRAM.md)、[覆盖矩阵](RULE_COVERAGE_MATRIX.md)、[来源](RULE_SOURCE_INVENTORY.md) |
| 规则质量 | [发现质量](FINDING_QUALITY.md)、[迭代边界](RULE_QUALITY_ITERATION.md)、[第三方准入](THIRD_PARTY_RULE_ADMISSION.md) |
| 接入与范围 | [Codex 接入](CODEX_INTEGRATION.md)、[目标选择](SCAN_TARGET_SELECTION.md) |

旧轮次实验报告已从当前树清理，其冻结版本仍可通过 Git 历史查阅。当前验收入口统一为[手工验收](../RUNTIME_CHAIN_REGRESSION_ACCEPTANCE.zh-CN.md)，不以历史设计中的待办描述覆盖最新实现。
