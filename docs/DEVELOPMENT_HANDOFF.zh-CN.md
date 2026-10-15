# 开发交接：换电脑或新聊天继续

更新日期：2026-10-15。仓库：https://github.com/pikachu-cxy/Ai-security-check
开发分支：feature/runtime-mvp；源码版本：0.3.4。

## 先读这四页

1. [开发进度](DEVELOPMENT_PROGRESS.md)：已完成、验证结果和未完成范围。
2. [近期计划](NEXT_DEVELOPMENT_PLAN.zh-CN.md)：下一阶段优先扩大宿主接入。
3. [宿主支持](HOST_SUPPORT.md)：Cursor、Qoder、WorkBuddy / CodeBuddy 的实际状态与门槛。
4. [产品规划](PRODUCT_ROADMAP.md)：个人版闭环与企业深度验证边界。

旧候选路径、构建回执和此前交接均已归入[历史交接](archive/2026-10/DEVELOPMENT_HANDOFF.through-2026-10-14.zh-CN.md)，不直接沿用为当前安装身份。

## 同步源码

先检查工作树；存在自己的未提交改动时保留现场，不强制重置。工作树可安全同步时执行：

~~~powershell
git status --short
git fetch origin
git switch feature/runtime-mvp
git pull --ff-only origin feature/runtime-mvp
git log -1 --oneline
~~~

首次获取：

~~~powershell
git clone --branch feature/runtime-mvp https://github.com/pikachu-cxy/Ai-security-check.git
~~~

Git 仅同步源码、测试及文档。扫描数据库、原始聊天、真实项目、构建包、工具缓存和本机配置不会随拉取迁移。

## 开发与验证

使用 Python 3.12 及以上，并在项目独立虚拟环境安装开发依赖：

~~~powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e '.[test,build-standalone]'
~~~

测试临时项目放在仓库外并为每次运行使用新目录；非 Git 用例放在仓库内会被向上识别为父 Git 项目。
Windows 沙箱、目录链接和进程权限造成的失败应保留记录，并用相同用例在可用环境对照，不能放宽安全断言。
全局集成测试运行期间保持源码身份稳定。

当前关键回归入口：

- 功能隐藏：tests/test_post_fix_functional_prompt.py、tests/test_host_orchestration.py。
- 启动和并发：tests/test_global_startup_wait.py、tests/test_codex_hook_contention.py。
- 宿主就绪与任务反馈：tests/test_hook_readiness_feedback.py、tests/test_task_hook_deferred_feedback.py。
- 每个新增宿主需补自己的适配、隔离和真实使用验收，见[宿主支持](HOST_SUPPORT.md)。

## 构建与安装分开认定

从当前提交构建新的独立目录，并保留提交、源码摘要和构建身份；沿用 scripts/build_standalone.py、
scripts/verify_package.py 与 scripts/verify_artifact.py 的现有门禁，不用旧包冒充当前源码。

重新安装并完全重启宿主后，核对 MCP、Hook、Skill 与实际包身份，再做真实开发任务。
安装与准备操作以[详细安装指南](PILOT_INSTALL_AND_USE.zh-CN.md)为准。
源码拉取和测试通过都不等于原生程序已升级或桌面验收通过。

## 接续边界

- 个人版功能验证已隐藏，原问题安全复查保留；深度验证作为企业版开发项。
- 下一阶段是多宿主适用范围扩展，不在本次同步中宣称新增适配完成。
- 既有不完整安全核查、平台待验和数据新鲜度限制继续保留，见开发进度。
