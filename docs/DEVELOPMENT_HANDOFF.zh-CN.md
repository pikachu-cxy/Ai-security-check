# 开发交接：换电脑或新聊天继续

当前交付：架构前最新源码与规划先同步为 a51a58d；本批完成公共编排/装配首批、v3 唯一开发核查、历史保留与安装清理，并同步 README 和进度。相关回归去重 1719 项通过，原始失败及复测分开保留。当前版本安全核查请求更新未成功，旧部分复核不适用于最新源码；未更新运行中安装、未发布新包。细节见[实现记录](ARCHITECTURE_UNIFICATION_IMPLEMENTATION.zh-CN.md)和[v3 升级说明](TASK_REVIEW_V3_ONLY.zh-CN.md)。

更新日期：2026-10-18。仓库：https://github.com/pikachu-cxy/Ai-security-check
开发分支：feature/runtime-mvp；源码版本：0.3.6。

此前 A2 修正阶段的验收记录如下（源码已纳入架构前检查点 a51a58d，并不代表新包已发布）：本轮三个回归回执按 `classname + name` 去重并取最后结果为 **295／295 项通过**，最窄新分级及真实四文件恢复组为 **65 项通过，29.55 秒**。完整候选回归与打包按随后对应 `run.json` 和最新指针判定，不由定向回归推定；安装和 A2 新包桌面复验仍为 `PENDING_USER`。最新已实测场景仍是 A2 修复阻塞、B3 与 C2 各自场景通过，不能改写旧 A/B/C 或 B2 的失败记录。已实测的 `55977e7e…` 不包含本轮新增 `repair-impact-unknowns-v1`；版本仍为 0.3.6，不能仅凭版本号或定向测试通过认定新包已交付。

本轮统一判据由 `repair_impact_policy.py` 的常量供工具和宿主方法复用，安装 `repair-impact.md` 与 MCP 指导同源生成。显式 `classification` 只接受 `BLOCKING_CONTEXT`／`SCOPE_LIMITATION`，均需非空且不超过 800 字符的 `decision_basis`；阻断项还需本评估实际签发的证据，且与 `critical` 一致。未读材料的 PARTIAL 仍可保守使用 legacy `critical=true`，不能编造证据。当前具体正常路径的结果无法确定时，UNDETERMINED 仍阻断；只因外部实现未提供的范围未知不能同时放入它。旧 live 能力缺失时不发送新字段，也不自动改写旧记录或放宽门槛。

## 先读这四页

1. [开发进度](DEVELOPMENT_PROGRESS.md)：已完成、验证结果和未完成范围。
2. [近期计划](NEXT_DEVELOPMENT_PLAN.zh-CN.md)：先关闭修复影响的当前阻断，再扩大宿主接入。
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

- 修复影响与参数契约：tests/test_repair_impact*.py；原生流程：tests/test_native_repair_intent.py、tests/test_native_repair_impact_context.py、tests/test_task_risk_fix_mcp.py；同源指导与安装方法：tests/test_review_skill.py、tests/test_repair_impact_presentation.py。本轮按用例去重取最后结果为 295／295 通过，不用此前证据契约的 51／34／8 项结果替代。
- 功能隐藏：tests/test_post_fix_functional_prompt.py、tests/test_host_orchestration.py。
- 启动和并发：tests/test_global_startup_wait.py、tests/test_codex_hook_contention.py。
- 宿主就绪与任务反馈：tests/test_hook_readiness_feedback.py、tests/test_task_hook_deferred_feedback.py。
- 每个新增宿主需补自己的适配、隔离和真实使用验收，见[宿主支持](HOST_SUPPORT.md)。

任务候选提交现使用 typed schema：`primary_evidence`／`task_evidence` 为本任务实际签发的证据 ID 字符串，`evidence_refs` 为这些字符串组成的数组，不能传路径／行号对象或 `source_ref`。错误通过安全 `field_errors` 指明字段；仅在原活动任务、原复核会话及原源码版本中纠正可恢复参数错误，不扫描或重新建立基线。`INCOMPLETE` 终态不因改正 JSON 自动恢复，三版快速方法和 packet 的示例也不是真实风险或已签发证据。

初始化实际结果：A2 首次对象格式失败、第 2 次改字符串后 `COMPLETE / 1 finding`；C2 前两次对象格式失败、第 3 次改字符串后同样保存成功；B2 三次对象格式失败后 `INCOMPLETE`。保留 B2 目录、聊天和失败记录，不自动重开。后续独立 B3 已完成影响与保留共享成员的修复、原风险复查；C2 已完成影响保存、DEFER 和历史回读。A2 仍因范围未知被过宽升级而阻塞，按本轮新能力在原归属下续验，不重建编辑前基线或重新索取同一批准。具体边界见[验收步骤](REPAIR_IMPACT_ACCEPTANCE.zh-CN.md)。

分级正例是四文件已读、仅复用已有 `can_read`、保留所有者和共享成员及参数返回关系。未提供外部仓储、身份来源或异常显示本身只限制结论范围，不等于全项目兼容证明缺失就必须停下局部修复。真实阻断对照需有当前正常路径的具体依据，例如合法记录确有精简投影缺少权限字段，而当前调用所选分支未明，或方案要改变跨边界身份来源却未核对该来源；必须说明答案如何改变方案及必要下一步，不能笼统写“上游未提供”。

本轮原始回执保留：`artifacts/a2-classification-targeted-20261018.xml` 为 196 通过／2 失败，`artifacts/a2-classification-verification-20261018.xml` 为 242 通过／2 失败，`artifacts/a2-classification-recovery-final-20261018.xml` 为 65 通过。汇总位置为 `artifacts/a2-classification-validation-20261018.json`，以 `classname + name` 去重取最后状态得 295／295 通过；不可把各轮数量相加，也不能删除前两轮的历史失败。

## 构建与安装分开认定

从当前提交构建新的独立目录，并保留提交、源码摘要和构建身份；沿用 scripts/build_standalone.py、
scripts/verify_package.py 与 scripts/verify_artifact.py 的现有门禁，不用旧包冒充当前源码。

本功能使用 scripts/rebuild_repair_impact.py 纳入实际工作树和新增回归，记录六工具与冻结 schema 检查，失败不覆盖 latest。用户首个重建批次在回归收集阶段失败，旧失败保留；修正后的回归、冻结探针及新候选分别按实际回执认定。旧批次 repair-impact-20261018-034812-775f80、构建 d6ac9d9e…d4d2b5 不含验收后的修正；同为 0.3.6 时也须比较新 build_id。具体命令与新起点案例见[修复影响安装验收](REPAIR_IMPACT_ACCEPTANCE.zh-CN.md)。

本轮未知分级修正的完整候选回归与构建按随后对应 `run.json` 和最新指针判定，已有 295／295 的去重定向最后结果不代替该门槛；新包身份以 `artifacts/repair-impact-latest.json` 的成功状态、对应 run 回执和源码 manifest 核对，再与实际安装及连接比较。实际连接还须声明 `features.repair_impact_unknowns=repair-impact-unknowns-v1`。此前 `d6ac9d9e…`、`dd571d41…`、`55977e7e…` 都不能证明这轮修正已打包；不虚构新 build_id，不把源码定向通过或安装命令成功写成桌面验收通过。

检查异常反馈已在源码共用 CHECK_OPERATION_BOUNDARIES：用户明确要求或原开发任务包含的测试、构建与验收照常执行，无需重复确认；检查状态本身不授权额外执行，伪造结果、重放事件和补建编辑后基线仍禁止。验证及实际交付按本轮回执认定，旧安装或仍运行的旧连接不会因源码修改自动更新。

重新安装并完全重启宿主后，核对 MCP、Hook、Skill 与实际包身份，再做真实开发任务。
安装与准备操作以[详细安装指南](PILOT_INSTALL_AND_USE.zh-CN.md)为准。
源码拉取和测试通过都不等于原生程序已升级或桌面验收通过。

## 接续边界

- 个人版功能验证已隐藏，原问题安全复查保留；深度验证作为企业版开发项。
- 下一阶段是多宿主适用范围扩展，不在本次同步中宣称新增适配完成。
- 既有不完整安全核查、平台待验和数据新鲜度限制继续保留，见开发进度。
