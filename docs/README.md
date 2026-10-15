# 项目文档

更新日期：2026-10-15。先看当前状态和下一步，再按需要进入设计或历史记录。

## 从这里开始

| 你想了解什么 | 阅读入口 |
| --- | --- |
| 下载、安装和开始使用 | [项目 README](../README.md) → [详细安装与故障处理](PILOT_INSTALL_AND_USE.zh-CN.md) |
| 当前完成了什么、还有哪些缺口 | [开发进度与验收状态](DEVELOPMENT_PROGRESS.md) |
| 下一阶段先做什么 | [近期开发计划](NEXT_DEVELOPMENT_PLAN.zh-CN.md) |
| Cursor、Qoder、WorkBuddy / CodeBuddy 接入 | [宿主支持与接入计划](HOST_SUPPORT.md) |
| 个人版和企业版怎么分工 | [产品规划](PRODUCT_ROADMAP.md) |
| 功能验证为什么隐藏、企业版准备怎么做 | [功能验证状态与企业研发](FUNCTIONAL_VERIFICATION.md) |
| 换电脑或新聊天继续开发 | [开发交接](DEVELOPMENT_HANDOFF.zh-CN.md) → [项目上下文](PROJECT_CONTEXT.md) |
| 个人版试用的通过条件 | [试用清单](PILOT_V1_CHECKLIST.zh-CN.md) |

当前个人版保留检测、风险解释、用户批准修复和原问题安全复查；功能验证的默认提示和入口已在源码隐藏。
下一阶段扩大宿主接入；企业深度验证属于开发规划，尚未实现。

## 按主题查阅

- **整体架构**：[Runtime 架构](ARCHITECTURE.md)、[架构决策](design/DECISIONS.md)、[扩展接口](design/EXTENDING.md)。
- **宿主与修复**：[Codex 接入](design/CODEX_INTEGRATION.md)、[修复授权与复查](design/SMART_AUTO_REMEDIATION.md)。
- **安全核查与规则**：[核查契约](design/SECURITY_REVIEW.md)、[任务核查设计](design/TASK_SECURITY_REVIEW_DESIGN.zh-CN.md)、[检查范围](design/SCAN_TARGET_SELECTION.md)。
- **检测质量**：[规则基础](design/RULE_FOUNDATION.md)、[能力矩阵](design/RULE_COVERAGE_MATRIX.md)、[规则计划](design/RULE_PROGRAM.md)、[规则来源](design/RULE_SOURCE_INVENTORY.md)、[发现质量](design/FINDING_QUALITY.md)。
- **使用与手测**：[指南目录](guides/README.md)。
- **历史候选与验收**：[2026 年 10 月归档](archive/2026-10/README.md)。历史记录保留原版本和失败事实，不代表当前源码或安装包已通过验收。

## 维护约定

- 当前事实记入开发进度，近期工作记入开发计划；跨宿主结论统一记入宿主支持页。
- 设计资料放在 design，操作参考放在 guides，阶段性回执和旧交接放在 archive。
- 源码回归、原生包、CI 和真实宿主使用分别记录；配置能生成不等于已经支持该宿主。
- 临时测试输出、扫描数据库、原始聊天、缓存和构建包留在忽略目录，不提交进 docs。
- 目录调整时同步修正相对链接；保留历史证据，不把旧失败改写成通过。
