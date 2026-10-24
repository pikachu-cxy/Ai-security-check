# 回归测试

从仓库根目录使用已安装 `.[test]` 的 Python 环境运行；pytest 配置是共享 helper 路径的唯一入口。

| 目录 | 范围 |
| --- | --- |
| `guidance/` | 指导、Skill 交付与风险呈现 |
| `task_review/` | 任务复核协议、证据窗口、预算与交付 |
| `tasks/` | 任务归属、快照、风险和恢复 |
| `snapshots/` | L0契约/旧限制刻画，L1页存储，1001文件任务及Hook基线，worktree窄准入与全局只读绑定诊断；不代替10万规模或真实宿主验收 |
| `distribution/` | wheel、独立包、安装引导、平台发布和恢复 |
| `rules/`、`rule_program/`、`triage/`、`corpus/` | 规则、评估和合成语料 |
| `performance/`、`benchmarks/` | 性能回归与测量依据 |
| `fixtures/` | 共享测试资源；旧 writer 冻结语料保持原样 |
| 当前根目录 | 尚未归组的核心、宿主与集成回归 |

建议先运行改动所属目录，再按实际调用关系增加集成回归。完整测试仍使用 `python -m pytest -q tests`。

```powershell
python scripts/maintenance/check_repository_layout.py
python scripts/maintenance/sync_review_skill.py --check
python -m pytest -q tests/distribution tests/test_repository_layout.py
```

测试临时目录必须在仓库外。默认 pytest 临时目录符合这一要求；若使用 `--basetemp`，选择一个专用、可清理且不在任何现有 Git 项目中的目录。嵌套在本仓库内的合成项目会被工作区解析器识别成当前 Git 项目，导致扫描记录和归属断言失真。Windows 应使用较短的临时目录；过长的测试前缀叠加会话私有状态路径可能使合成初始化失败，应保留原诊断并用短路径复核。

CI 使用 runner 的临时目录。测试应使用隔离状态、合成源码与合成宿主配置，不修改真实 Codex 安装。源码回归、隔离安装和当前桌面连接验证分别记录，不继承历史通过结论。
