# Runtime 升级与扫描入口优化

下一阶段先解决两件事：更新 Runtime 后能稳定继续试用，以及用户要求扫描整个
项目时能正确进入本产品并得到真实覆盖范围。现有 Hook、MCP、证据复核和签名
归属机制继续保留。以下保留开发需求，并在本节记录当前实现与验收边界。

## 本轮实现状态

已新增 `upgrade diagnose/plan/apply/recover`：只读定位有效配置层，计划包含
具体子树、托管 Hook、文件指纹和 900 秒有效期。未知同名 MCP 的移除必须单独
提供 `--approve-user-managed`，未知 Hook/别名、无效签名及自定义 Skill 默认保留。
应用先比对完整计划与当前文件，签名本地操作记录在每次写入前持久化恢复意图。
`recover` 仅恢复该操作记录的配置/归属/Skill 文件；并发编辑或签名 key 改变时
拒绝。签名 key、扫描 DB、policy 保留，不恢复旧 triage/session/修复授权。

`delivery activate/status/rollback` 为新原生包提供固定 launcher、不可覆盖的
build-id 版本槽和签名活动指针。先验证完整文件清单、来源字段、schema/契约与
CLI+真实 stdio 能力，再切换。保留上一槽；进程须重连才能载入新版本。
完整性 hash 不证明发行者身份，只适用于用户明确提供的可信本地包。
旧 R2.2 ZIP 没有完整清单，不能直接作为新 delivery 版本槽激活；现有签名
安装可通过新包的升级计划迁移。中断复制的无效槽会拒绝覆盖，需用户审阅处理。

`trial create/status/run` 统一建立独立 state、Codex home、Skill、引擎数据目录
和合成工作区，清理继承的 Runtime/引擎绑定并默认 offline。不自动清理已有
目录、不修改真实安装，不声称 CLI profile 等于 Desktop 独立用户环境。
试用 setup 固定为 Codex，拒绝其他编辑器入口及缩写参数，防止目标路径校验旁路。

源码 Skill 与规范工作流已将整库 `scan_project`、增量 `scan_diff`、续办原
task_ref 分开。summary 新增 `scan_context`，包括模式、时间、实际文件/语言、
scanner 执行和 keyed 全库源新鲜度；新增/未跟踪文件同样会使结果过期。
只读 summary 不执行引擎或重验漏洞 DB，因此目前保守地将整库可复用标记为
false；整库请求新扫描，不能只凭源新鲜而复用。已有任务仍可继续，不逐句扫描。
保留 implicit invocation；未添加未经验证的本地 stdio UI 依赖声明或虚假 URL。

Git pre-commit 改为有界 index blob 快照及同版本 context；NUL 文件列表支持
空格/Unicode、初始提交、重命名/删除和 worktree。新增 `--gate strict|report`：
0 为按策略放行、1 为原风险策略阻止、2 为 strict 检查未完成。普通 CLI 退出码
兼容；report 未完成时明确警告。status/repair/remove 仅管理签名自身 Hook，
不自动组合或覆盖用户 Hook。目录预算、链接/子模块、冲突 index 等无法完整
投影时 fail closed，不 stash/checkout/修改 index。仅 quick 模式支持 staged。

最终源码已完成全量回归：同一用例清单分六个互不重叠组，2070 项中 2034 通过、
10 跳过、26 为既有预期失败，零意外失败；新增边界的关联补测为 107 通过、1 跳过。
原生双构建激活/协同升级/回滚、密钥保留、未知 MCP 独立授权及兄弟配置保留、
冻结程序试用子进程与参数隔离、真实 Semgrep/Gitleaks 的 index 门禁均通过。
本地 ZIP 的离线 CLI/MCP 与安装生命周期验证通过，不安装引擎或访问网络。
无 Hook 的真实 stdio `scan_project` 已执行 release 合成四文件项目：Semgrep 与
Gitleaks SUCCESS，覆盖为 PARTIAL（离线依赖数据库不可用），不代替全仓安全审计。

Desktop 普通提示词选 Skill、显式无 Hook 全库体验及 Hook 可见性仍为 PENDING；
不继承旧 PASS。用户最短验收：重启确认当前 Runtime/Skill，关闭演示项目 Hook 后
显式请求整库扫描并核对覆盖，审核信任并启用演示 Hook 后观察编辑自动反馈。
完整六步核查/续办/修复验证见 [Windows 体验说明](../../guides/WINDOWS_EXPERIENCE.zh-CN.md)。
P2 规则扩展、Release/CI、真实用户配置迁移不在本次执行范围。

## 开发前基线与代码依据（保留用于对照）

以下记录开发前 `feature/runtime-mvp` 的 `b7e73b8`；当前实现与验收见上节。
基线已有 R2.2 本地安全核查体验，
不是正式 Release；新构建的 Desktop 体验不能沿用旧版本的验收结论。

| 能力 | 现有实现 | 当前边界 |
| --- | --- | --- |
| Codex 全局安装 | 签名 sidecar、语义指纹、CAS 写入、已托管旧项目迁移 | 未认证的同名配置必须拒绝，缺少面向用户的完整冲突处理流程 |
| Hook 自动检测 | 宿主事件、内容变化核对、CORE 扫描、策略和受限修复验证 | 不是聊天意图路由，也不是全库扫描证明 |
| 无 Hook 核查 | `scan_project`、summary、分批证据、triage、原扫描器验证 | 工具可用不表示自然语言一定选择本 Skill |
| 整库扫描 | `scan_project` 调用 `release` 模式，手动 MCP 使用完整 registry | Skill 的首句、默认提示和复用规则仍偏向已有发现 |
| Skill 生命周期 | 独立签名托管 install/status/upgrade/repair/remove | 与 Runtime 安装分开，尚无一次升级协同检查 |
| 检测质量 | R1 评测、独立 HUMAN 质量评审、R2.1.1 脱敏证据 | 跨函数、跨文件、包装 API 等仍有限，不能宣称全面审计 |
| Git 提交 Hook | 已能安装 `pre-commit`，调用 quick staged CLI | 暂存内容一致性、安装路径和失败退出码需要完善 |

主要代码入口：

- [全局安装](../../../src/security_runtime/global_integration.py)、
  [签名归属与探测](../../../src/security_runtime/codex_integration.py)、
  [TOML 有界修改](../../../src/security_runtime/global_toml.py)。
- [全局工作区路由](../../../src/security_runtime/global_mcp.py)、
  [工作区与 bootstrap](../../../src/security_runtime/global_workspace.py)、
  [状态存储](../../../src/security_runtime/storage.py)。
- [Skill](../../../src/security_runtime/skills/ai-security-review/SKILL.md)、
  [界面元数据](../../../src/security_runtime/skills/ai-security-review/agents/openai.yaml)、
  [Skill 安装管理](../../../src/security_runtime/review_skill.py)、
  [规范工作流](../../../src/security_runtime/host_guidance.py)。
- [MCP 扫描工具](../../../src/security_runtime/mcp_server.py)、
  [已有扫描摘要](../../../src/security_runtime/security_summary.py)、
  [扫描主流程](../../../src/security_runtime/runtime.py)。
- [Git Hook](../../../src/security_runtime/hooks.py)、
  [暂存文件选择](../../../src/security_runtime/git.py)、
  [扫描器内容来源](../../../src/security_runtime/scanners.py)、
  [CLI 退出码](../../../src/security_runtime/cli.py)。

## 用户试用暴露的问题

普通请求“检查当前项目的安全风险”曾直接选择另一款安全扫描 Skill，而未调用
本产品。显式选择 `ai-security-review` 后进入了正确工具链，但目标项目核查
在扫描启动前失败。前一次返回 `OWNERSHIP_INVALID`，后续当前全局 Runtime
返回 `MCP_CONFIGURATION_CONFLICT`；两者不能归为同一个已证实的内部原因。

本地检查确认：目标项目还保留指向开发仓库 `.venv` 的同名项目级 MCP，而全局
MCP 指向新 Windows 原生体验包。前者是 `generic-mcp` 配置，没有可直接认领的
托管标记。代码必须拒绝未知归属；仅重连不会移除磁盘上的配置冲突。不要据此
猜测签名密钥损坏，也不要把该失败误报成“扫描没有风险”。

当前实现已有 `repair --path` 对已证明归属的旧配置进行迁移，不能把任务写成
“从零实现迁移”。缺口是未知配置的用户确认处理、稳定的安装入口、跨组件升级
恢复，以及能重现新装与升级差异的隔离测试。

Git 门禁另有两个代码级问题：

1. `staged=True` 改变 Git 文件和行选择，但适配器仍读取工作区文件；目录镜像也
   从工作区复制。合成探测中，暂存区为 `INDEX_ONLY`，扫描上下文读取到
   `WORKTREE_ONLY`。这证明内容来源不一致，不是实际漏洞检测率的测量。
2. CLI 仅在 `release_status=BLOCKED` 时返回 1。合成 `PARTIAL / MINIMAL /
   UNAVAILABLE / REVIEW` 结果返回 0。现有提交 Hook 因而不能把“检查未完成”
   与正常放行区分。是否阻止未知结果应有明确门禁策略。

## 开发优先级

| 顺序 | 优先级 | 工作包 | 完成条件 |
| --- | --- | --- | --- |
| 1 | P0 | 冲突诊断与迁移计划 | 准确定位配置层；已托管可修复，未知归属需显式确认 |
| 2 | P0 | 安装入口与升级恢复 | 新旧构建可切换、失败可恢复，状态和签名不丢失 |
| 3 | P0 | 本地试用隔离 | 开发测试不污染真实配置，新装与升级分别可重放 |
| 4 | P0 | Skill 与整库扫描语义 | 显式使用稳定；整库请求不能复用增量结果冒充全库 |
| 5 | P1 | Git 提交门禁完善 | 检查真正的 index 内容，失败策略与退出码明确 |
| 后续 | P2 | 检测质量与规模体验 | 独立评测推动规则改进，不阻塞本阶段可用性闭环 |

诊断契约可以先确定，升级和隔离测试随后并行推进。不要在本阶段同时扩展规则
数量、引入 Runtime 内置 LLM、改写修复策略或启用 Release/CI 工作。

## P0 冲突诊断与迁移计划

把“检查环境”和“修改环境”分开。设计只读诊断以及可审阅的迁移计划，再执行
有归属或用户明确授权的有限变更。命令名由开发确定，新增命令不得提前写成
已可运行的使用方式。

- 检查当前项目及其有效祖先配置层、全局配置、Runtime 启动入口、Skill 状态。
  不遍历所有项目或整个用户目录。不要执行未知配置中的任意 command。
- 区分未知同名配置、已托管但过期、无效签名、DEV 启动器、缺能力、连接未刷新、
  bootstrap 未就绪、引擎缺失和状态目录权限问题；不要统一建议重新连接。
- 计划列出具体层、将修改的 MCP 子树及托管 Hook、预期指纹和恢复方式。诊断
  输出只保留必要的本地定位信息及固定原因，隐藏 env 值、密钥和原始异常文本。
- 已签名旧安装沿用现有归属和 CAS 验证。未知 generic 配置默认保留；提供由
  用户明确批准的移除或接管流程，不能因同名、路径相似或字节相同而自动认领。
- 未知配置处理要单独授权，不能把“扫描项目”解释成修改宿主设置的许可。计划
  过期、文件被并发修改、链接或非预期层变化时拒绝应用。
- 跨全局配置、旧项目配置和 Skill 的升级需要可恢复的操作记录。任一阶段失败
  不得假报完成；恢复不能覆盖用户在失败后作出的修改。
- 不重置签名密钥，不清空扫描 DB，不编辑宿主 Hook 信任，不删除其他 MCP、
  插件、marketplace、项目设置或用户 Skill。
- 无效签名仍 fail closed。若没有可信恢复证据，只提供用户审阅后重新部署
  目标配置的路径，不能自动重新签名来洗白旧状态。

重点扩展现有 `test_global_integration.py`、`test_global_ownership_v2.py` 和
`test_owned_block_semantics.py`。原有保护性拒绝测试必须保留。

## P0 安装入口与升级恢复

Windows ZIP 当前把实际 EXE 路径写入全局配置。移动包或换解压目录需要 repair；
`current_runtime()` 也直接使用当前 executable。generic MCP 的解析器已有有限
的包管理器 alias 支持，但不能据此认定全局 ZIP 升级已经具备稳定启动器。

推荐采用固定产品入口、分版本包目录和可验证的活动版本指针；可以提出更小的
等效方案，但必须先满足以下契约，再决定具体实现。

- 从固定入口启动，不覆盖正在运行的 EXE；保留上一可用版本，明确何时刷新
  MCP 连接。新进程加载新版本不等于已运行进程自动更新。
- 新包激活前验证完整性、版本与构建来源、需要的能力及资源文件。全局与项目
  启动配置共用明确的启动器解析规则，保留原生包无需开发 Python 的体验。
- `version.json` 已有 source commit、dirty 标志和体验契约；让诊断/MCP 提供
  可比对的构建身份。两个包同为 `0.3.1` 不证明功能相同。
- state、ownership、keys、baseline 和用户 policy 不放在可删除的版本包目录。
  Runtime 与 Skill 的契约兼容性纳入升级状态，不再只说明“重启再试”。
- 激活使用锁、原子切换和路径边界检查；拒绝越界目录、链接、无效活动指针。
  不能把稳定入口变成从任意路径执行程序的通道。
- 对确实需要迁移的状态采用明确 schema/兼容版本和事务；保持现有数据和密钥。
  未知旧状态不能静默丢弃，回滚不得让旧代码读取不兼容的新 schema。
- 回滚应针对安装与兼容状态，不恢复已失效的连接内修复授权、过期 triage
  session 或扫描证明；重新连接后的引用继续遵循当前刷新规则。
- 正常升级后只需必要的宿主重启/重连及信任审核，不要求用户手工找散落配置。

优先复用现有安装、包校验、签名和回滚原语，不重写完整安装系统。

## P0 本地试用隔离

`SECURITY_RUNTIME_STATE_DIR`、`CODEX_HOME`、`SECURITY_RUNTIME_CODEX_HOME` 和
`ReviewSkillManager` 的目标目录参数已经存在。围绕这些基础增加统一试用入口
与测试 harness，不要仅增加一个说明用户自行清理环境的文档。

- 区分日常已安装 Runtime、源码开发环境、原生包体验环境。源码更新不自动
  修改日常全局安装；DEV 测试须显式启用并使用专用配置与状态。
- 每次新装测试创建独立且有界的 sandbox root，容纳合成用户配置、Skill、
  state、工作区和操作记录。清理只能删除本次明确创建的目录。
- 升级测试必须复用上个版本的状态、签名和配置，然后切换新包；不能每次删除
  环境后把新装成功当成升级成功。测试集覆盖多个连续构建，不只一次升级。
- 子进程显式设置/清理相关 env，防止继承日常 GLOBAL、WORKSPACE、STATE、
  CODEX_HOME、引擎路径而误用另一个环境。生产安装保持原样。
- 模拟工具测试默认无网络、使用合成配置及 scanner fixture；真实 scanner
  验收另用预置引擎/数据库，并准确标明缺失条件。禁止借测试自动大规模安装。
- Windows 原生包用独立输出目录构建，保留许可证和 notices。测试包须标明
  源码提交、dirty、包校验信息，不只记录 `--version`。
- 若当前宿主不支持独立配置启动，把该 Desktop 测试标记为受限；不要声称 CLI
  sandbox 等于真实 Desktop 隔离，不暗改真实用户配置去伪造通过。

## P0 Skill 与整库扫描语义

优化源码中的 Skill、UI 元数据和规范工作流，再经托管 `review-skill` 流程升级；
不要只直接改用户安装目录里的副本。用户自定义修改仍须保留。

1. 将“用 AI Security Runtime 扫描当前项目/全部代码并报告实际覆盖”置于
   description 前部。short description 和 default prompt 不再只强调已有
   findings。保留复核、继续任务和授权修复的原有能力及清晰边界。
2. 保持 implicit invocation，核对 MCP 依赖元数据对本地 stdio 的支持；若宿主
   不支持对应声明，明确说明，不添加假的 HTTP URL。
3. 分开全库新扫描、增量检查和继续已有任务。全库使用 `scan_project`；增量
   使用 `scan_diff`；继续已有任务遵循原 task_ref。summary 本身不能暗中扫描。
4. 只有范围、源版本、规则/能力及所需 scanner 证明匹配时才复用整库扫描。
   quick/Hook 的 `FULL` 不能代表 release 全库覆盖；旧版本、增加文件、未跟踪
   文件或新规则均需纳入新鲜度判断。没有可验证依据就按授权重新扫描。
5. 用户要求“重新扫描全部代码”时执行新扫描，不以已有 review 替代。不得在
   所有普通聊天或只读操作上自动全库扫描。
6. 在只读 summary 中增加可判定的扫描模式、范围/时间或源版本、新鲜度及
   实际执行信息，保持旧接口兼容；coverage 仍来自 Runtime，不由模型改写。
7. MCP 缺失或冲突时报告本产品未执行和下一步；不能无声切换另一款 scanner
   并继续称为本产品结果。用户明确指定另一产品时应尊重该选择。
8. 最终报告分开请求范围、实际文件/规则/语言、scanner 执行、未覆盖原因、
   原始发现、已复核范围和未知项。分页限制是展示/复核边界，不是 scanner
   只扫描了第一页；反过来全库 scanner 完成也不表示所有发现已复核。

隐式 Skill 是模型基于元数据选择，不存在本产品可保证的全局优先级。官方
[Skill 文档](https://learn.chatgpt.com/docs/build-skills)要求将主要触发场景前置；
这支持优化方向，不能代替多 Skill 共存的真实验收。显式选择始终提供稳定入口；
项目默认偏好只能由用户选择启用，不能自动禁用竞争插件或改写项目 AGENTS。

## P1 Git 提交门禁完善

保留已有 `pre-commit`，先修正正确性，再考虑额外事件。`pre-push` 作为后续
可选扩展，不把本阶段范围扩大成新的 Git 平台。

- 扫描实际 index 内容，而不是工作区同名文件。使用只读的暂存快照和有界
  路径映射，不能临时 stash、checkout、重写工作区或修改 index。
- 文件名使用安全的 Git 输出格式；覆盖空格、Unicode、重命名、删除、部分
  暂存、初始提交和 worktree。context、变更行过滤和证据坐标必须指向同一版本。
- Hook 使用可验证的稳定产品入口，正确处理 Windows/Git Bash 路径和引号。
  PATH 找不到产品时必须给可操作错误，不能误报正常检查。
- 明确退出码契约，至少区分策略阻止、检查未完成和允许提交。保留 CLI 兼容性
  时可以新增门禁模式，不应悄悄改变所有现有调用者的退出码。
- 对 PARTIAL、scanner unavailable、timeout、无法读取 index 等未知情况提供
  明确 strict/report 策略；strict 不把“不知道”当通过。report 放行也必须提示
  实际未完成，NO_CHANGES 不等于全项目安全。
- 已有用户 Hook 默认保留；若支持组合，必须显式 opt-in，验证原 Hook 退出码
  传播和安全链式执行。status/repair/remove 仅管理自己的内容。
- 用真实 `git commit` 加固定本地 scanner 验证风险阻止和安全提交；合成测试
  只证明控制流。不要自动在用户业务仓库安装门禁。

## 必须通过的验收

| 场景 | 验收要求 |
| --- | --- |
| 全新安装 | 无旧配置也可使用；不修改测试目标项目的安全代码 |
| 连续升级 | 已托管上一版本到新版本，state/keys/policy 保留，重复执行幂等 |
| 同版本不同构建 | 正确识别包身份及新能力，不能仅凭版本号判断最新 |
| 已托管项目配置 | 迁移到全局后不重复启动/扫描，其他 MCP 和 Hook 原样保留 |
| 未托管 generic 配置 | 默认只读失败；显式批准后才执行有界变更 |
| 无效签名与并发修改 | 拒绝并保留用户数据，不重新签名洗白 |
| 中断与回滚 | 逐阶段失败可恢复；不覆盖失败后用户修改，不复活旧授权 |
| 开发与原生包并存 | 测试与日常配置隔离，真实用户配置/state/Skill 不变 |
| 无 Hook 显式全库请求 | 正确产品、`scan_project`、真实执行与覆盖报告 |
| 多 Skill 共存的普通请求 | 记录真实选择结果；不得把误路由标为本产品通过 |
| 已有 quick 扫描再请求全库 | 不能复用 quick/Hook FULL 冒充全库 |
| 新鲜度与恢复 | 新增/修改文件、新规则和连接重建后结论/引用正确刷新 |
| Hook 编辑体验 | 原生反馈保持可见；只读/无变化不触发额外全库扫描 |
| Git 部分暂存与失败 | 检查 index 版本；策略阻止及不完整结果返回正确退出码 |

自动测试、真实 scanner、Windows 原生包和 Desktop 用户验收分别记录。
Desktop 尚未亲测就保持 PENDING；不得用日志、手动工具调用或旧 PASS 代替。
本阶段提交代码不等于发布 Release，不修改既有 capability maturity 或声称
生产安全。完整回归和包验证失败必须解释，不能删除失败测试或放宽校验。

## 交给 Codex 的开发请求

将下面内容作为下一轮的用户请求，并在同一仓库执行。文档中的工作包是需求，
不是当前实现状态；实际代码和新增测试决定最终结果。

```text
请开发 AI Security Runtime 的升级与扫描入口优化。
先读 docs/PROJECT_CONTEXT.md、docs/UPGRADE_AND_SCAN_USABILITY.zh-CN.md、
docs/CODEX_INTEGRATION.md 和 docs/SECURITY_REVIEW.md，核对当前 Git 状态。
按清单依次完成 P0 冲突诊断、升级恢复、测试隔离、Skill 与整库扫描语义，
再完善 P1 Git pre-commit 的 index 内容和门禁失败处理。
P2 检测规则扩展不在本轮开发范围。

先给出精简实现安排，再直接开发并持续同步进度；不只提供设计。
复用已有签名归属、CAS、旧配置迁移和 Skill 生命周期，先补复现/回归测试。
使用合成配置及独立测试状态；不要直接改我的真实 Codex 配置、Hook 信任、
用户 Skill 或业务项目，不删除旧密钥/DB，不绕过 OWNERSHIP_INVALID。
需要处理未托管真实配置、外部安装或真实 Desktop 操作时说明范围并取得授权。
保留原始发现、实际覆盖、AI 复核和原扫描器证明的边界。

分别运行针对性测试、完整回归、包验证和条件允许的真实 scanner 验收。
使用独立输出目录构建 Windows 本地体验包，保留 notices，提供源码/构建身份。
Desktop 需要我亲自操作的项给出最短清单并标记 PENDING，不伪造通过。
更新 PROJECT_CONTEXT、当前使用文档和本清单中的实现状态，不添加历史输出快照。

开发完成且相应代码验证通过后，自动提交并推送到
origin 的 feature/runtime-mvp 分支。提交前核对 origin 为
https://github.com/pikachu-cxy/Ai-security-check.git；只提交本任务的源码、
测试与维护文档，不上传个人配置、密钥、源码证据、扫描 DB、临时输出或原生包。
保护已有未提交修改，不 force push，不修改全局 Git 配置，不创建 tag/Release，
不启动暂停的 Release/CI 工作。按完成的逻辑工作包提交清晰 commit。
若远程前进导致无法安全推送，先检查差异；不能擅自覆盖或重写他人提交。
若当前工作是另一分支、权限不足或验收失败，说明具体状态并请求必要方向。
提交并推送前不要声称已同步 GitHub；结束时给出 commit、push 结果、测试结果、
包位置、剩余 Desktop 验收与已知限制。
```

自动提交是开发任务的收尾要求，不是新增后台计划任务或自动发布服务。
本清单不授权未来 Agent 修改无关项目、绕过提交门禁或代替用户信任宿主 Hook。
