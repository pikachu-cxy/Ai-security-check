# 项目文档

更新日期：2026-10-23。先按目标选择一个入口；当前产品能力以 [0.3.9 产品覆盖](PRODUCT_COVERAGE.zh-CN.md)为准。

## 安装与使用

| 目标 | 唯一导航入口 |
| --- | --- |
| 安装、日常操作与平台指南 | [使用指南](guides/README.md) |
| 当前语言、检测范围与限制 | [产品覆盖](PRODUCT_COVERAGE.zh-CN.md) |
| 产品规划与版本方向 | [产品路线图](PRODUCT_ROADMAP.md) |

## 当前开发与维护

| 目标 | 入口与职责 |
| --- | --- |
| 恢复开发 | [项目上下文](PROJECT_CONTEXT.md)：产品职责与关键约束；[开发交接](DEVELOPMENT_HANDOFF.zh-CN.md)：接手步骤 |
| 判断完成情况、安排后续 | [开发进度](DEVELOPMENT_PROGRESS.md)：证据与缺口；[近期计划](NEXT_DEVELOPMENT_PLAN.zh-CN.md)：后续顺序 |
| 理解实现与维护契约 | [技术架构](ARCHITECTURE.md)、[设计导航](design/README.md) |
| 维护脚本、测试与仓库引用 | [脚本导航](../scripts/README.md)、[测试导航](../tests/README.md)；迁移时同步校验调用路径、CI 和源码清单 |
| 验证与诊断 | [链路验收](RUNTIME_CHAIN_REGRESSION_ACCEPTANCE.zh-CN.md)、[核查诊断](ARCHITECTURE_REVIEW_DIAGNOSIS.zh-CN.md)、[事务恢复](PERSISTENCE_TRANSACTION_RECOVERY.zh-CN.md) |
| 协议与宿主兼容 | [v3 兼容边界](TASK_REVIEW_V3_ONLY.zh-CN.md)、[宿主支持](HOST_SUPPORT.md) |

## 阶段记录与历史

[架构总计划](ARCHITECTURE_UNIFICATION_PLAN.zh-CN.md)、[架构实施记录](ARCHITECTURE_UNIFICATION_COMPLETION.zh-CN.md)、[性能记录](ARCHITECTURE_PERFORMANCE.zh-CN.md)及[历史发行说明](archive/2026-10/README.md)保留各自时间、版本和验收范围，不作为当前操作入口。旧版本通过 Git 历史查阅。

## 维护约定

用户操作从使用指南进入，设计细节从设计导航进入；本页不重复展开两份子导航。产品覆盖、开发进度、后续计划分别维护能力事实、验证证据和待办，其他文档链接对应来源，避免复制状态结论。

Skill 的维护来源、生成与校验方法统一见[设计导航中的 Skill 维护约定](design/README.md#skill-维护来源)。设计文档解释背景，宿主执行规则以对应的版本化 Skill 方法为准。

源码回归、安装包、当前运行连接和真实桌面验收分别记录，不相互继承通过。临时测试目录、扫描数据库、原始聊天、缓存及构建包不提交；回归所需 fixture 与旧 writer 兼容语料保留。
