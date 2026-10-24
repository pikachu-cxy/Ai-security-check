# 设计与开发参考

当前实现先读[技术架构](../ARCHITECTURE.md)；能力边界见[产品覆盖](../PRODUCT_COVERAGE.zh-CN.md)，宿主接入状态见[宿主支持](../HOST_SUPPORT.md)。本目录记录设计契约及其依据，阶段计划不覆盖当前实现。

| 主题 | 资料 |
| --- | --- |
| 核心原则 | [架构决策](DECISIONS.md)、[扩展接口](EXTENDING.md) |
| 开发核查 | [核查契约](SECURITY_REVIEW.md)、[任务设计](TASK_SECURITY_REVIEW_DESIGN.zh-CN.md)、[会话归属](TASK_SESSION_OWNERSHIP_20261016.md) |
| 当前改造计划 | [大项目L0契约](WORKSPACE_SNAPSHOT_L0_2026-10-24.zh-CN.md)、[V3 原文证据](RAW_SOURCE_EVIDENCE_V3_2026-10-23.zh-CN.md)、[统一扫描与风险归属](unified-scan-attribution-v1.md)、[任务收尾](task-closeout-v1.md)、[后台收尾与隔离](task-dispatch-isolation-v1.md) |
| 运行及恢复 | [证据与恢复](RUNTIME_EVIDENCE_AND_RECOVERY.zh-CN.md)、[持久事务](../PERSISTENCE_TRANSACTION_RECOVERY.zh-CN.md) |
| 修复与影响 | [修复授权](SMART_AUTO_REMEDIATION.md)、[影响评估](REPAIR_IMPACT_ASSESSMENT_DESIGN.zh-CN.md) |
| 规则范围 | [当前产品语言覆盖](../PRODUCT_COVERAGE.zh-CN.md)、[历史规则基础](RULE_FOUNDATION.md)、[规则计划](RULE_PROGRAM.md)、[历史质量矩阵](RULE_COVERAGE_MATRIX.md)、[来源](RULE_SOURCE_INVENTORY.md) |
| 规则质量 | [发现质量](FINDING_QUALITY.md)、[迭代边界](RULE_QUALITY_ITERATION.md)、[第三方准入](THIRD_PARTY_RULE_ADMISSION.md) |
| 接入与范围 | [Codex 接入](CODEX_INTEGRATION.md)、[目标选择](SCAN_TARGET_SELECTION.md) |

旧轮次实验报告已从当前树清理，其冻结版本仍可通过 Git 历史查阅。当前验收入口统一为[手工验收](../RUNTIME_CHAIN_REGRESSION_ACCEPTANCE.zh-CN.md)，不以历史设计中的待办描述覆盖最新实现。

## Skill 维护来源

| 内容 | 维护来源 |
| --- | --- |
| 核心入口、扫描工作流、修复影响方法 | `src/security_runtime/guidance/host_guidance.py` 中对应常量 |
| 风险交互方法 | `host_guidance.py` 组合 `risk_decision_guidance.py`、`risk_presentation.py` 的共享规则与分支指导 |
| 修复字段与调用示例 | `src/security_runtime/review_skill.py` 的 `repair_impact_reference()` |
| 开发 v3、深度审计方法及 UI 元数据 | `src/security_runtime/skills/ai-security-review/` 下对应原始文件 |

前四项生成的 `SKILL.md`、`references/runtime-workflow.md`、`references/risk-decisions.md`、`references/repair-impact.md` 是随包提供的副本，不单独手工维护。在线指导和安装内容统一调用 `review_skill.generated_skill_file()` 渲染；方法按意图加载，入口只保留导航和必要安全边界。

修改来源后，在项目已配置的 Python 环境执行：

```sh
python scripts/maintenance/sync_review_skill.py
python scripts/maintenance/sync_review_skill.py --check
python -m pytest tests/guidance/test_guidance_catalog.py tests/guidance/test_review_skill.py tests/guidance/test_mcp_discovery_guidance.py
```

同步脚本只写仓库中的四份生成副本，`--check` 只读并在不一致时返回非零状态；不会安装 Skill 或修改用户宿主配置。已有测试核对在线返回、仓库副本和隔离安装的字节及摘要一致性。指导摘要变化不代替 Runtime 能力、原任务版本或修复授权检查。
