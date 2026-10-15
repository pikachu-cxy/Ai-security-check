# 0.3.3 Developer Alpha 候选发行说明

本补丁版本收敛受邀试用范围，仍为试用／预发布版本。发布前须取得同提交完整 CI 和现有三平台原生验收证据；当前说明不表示已发布，也不表示真实 Codex 桌面验收通过。

- Git pre-commit 为默认关闭、常规 CLI 帮助隐藏的高级可选能力。已有显式安装、状态、修复、移除命令及 strict/report 参数兼容，默认安装不创建或删除用户已有 Git Hook。
- 核心试用流程继续保留 Codex 生命周期 Hook、MCP、Skill、任务结束后的安全检查、用户明确选择修复／暂不处理及修复后复验。安全反馈不要求 git commit；任务检查继续使用 Git 元数据和 diff。
- 原生 `--hooks` 继续验 Codex 生命周期，Git 提交分派只在显式指定 `--git-pre-commit` 时执行。未请求的 Git 验收在回执中记录 SKIPPED 与原因，后续 Codex integration 验收继续运行。

本批定向源码回归覆盖默认安装保留、显式兼容入口、验收拆分与顺序、Git staged 门禁和 Windows Git shell；具体真实结果与未测项见开发进度。源码／模拟夹具、原生 CI 和真实桌面试用分别记录，不把跳过当成全量通过。

后续计划考虑 Windows 优先、Mac 独立验收后补发；本批继续使用现有 Windows x64、Mac ARM、Mac Intel 三平台流程，不改发布架构。
