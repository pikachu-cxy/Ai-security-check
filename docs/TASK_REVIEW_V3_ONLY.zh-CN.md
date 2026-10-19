# 开发任务核查：仅支持 v3

更新日期：2026-10-18。源码版本仍为 0.3.6；这是当前分支的破坏性协议收敛，不代表已发布新包或升级当前连接。

## 决策与调用链

开发任务核查只执行 v3。v1 的基础流程和 v2 的固定额度流程已移除；明确传入 1、2 或非法协议返回不支持说明，不静默改成 3。Skill 安装归属、风险决定、证据标识和数据库格式是独立契约，不能按名称里的 v1/v2 全局删除。

| 层 | 当前权威与约束 |
| --- | --- |
| Skill 源文件与方法 | 只交付 quick-task-review-v3；普通聊天、只读、无改动不启动核查，静态零告警仍需代码复核 |
| 能力与 MCP | get_runtime_info 声明 ONLY_V3、默认 3、旧任务仅历史；prepare 参数 schema 仅允许 3，原始输入先于 SDK 解析和工作区路由拒绝旧协议 |
| 任务服务 | begin 在真实修改前的同一事务中保存 review_protocol=3；finish、skip、prepare、read、plan、method、batch、submit 及已绑定修复恢复检查原记录协议 |
| 计划与证据 | TaskReviewCoordinator → task_review_plan → budget/windows/transport；按必读范围分配额度，只复用同任务、源码、归属与累计账本；缺失权威账本不能用重复视图恢复 |
| 持久化与恢复 | 原签名任务与真实预像保留；选择可执行任务前筛选协议 3；历史查询走纯投影，不重扫、不重放、不迁移、不写入历史 |
| 生成与安装 | review_skill.skill_files 组合 Skill 源文档与 host_guidance 动态方法；安装清单签名及逐文件 hash 决定更新归属，升级按固定退役文件名单清理 |

~~~mermaid
flowchart TD
    START[实际开发需求] --> CAP{同一 Runtime 支持 v3 和九项任务工具?}
    CAP -->|否| UPGRADE[提示升级 Runtime 并重连；停止核查]
    CAP -->|是| RECORD{已有原任务?}
    RECORD -->|旧协议| HISTORY[只读历史；说明未完成范围，不迁移]
    RECORD -->|v3| RESUME[校验归属、原基线、源码、证据和累计额度]
    RECORD -->|无| BASE[首次修改前显式 begin，持久化协议 3]
    BASE --> EDIT[宿主按原开发授权编辑与测试]
    EDIT --> FINISH[同一任务 finish]
    RESUME --> FINISH
    FINISH --> CHANGE{实际变化?}
    CHANGE -->|无| QUIET[无扫描、无模型核查、无通用提示]
    CHANGE -->|有| STATIC[有界静态检查]
    STATIC --> PLAN[v3 方法与全部必读计划]
    PLAN --> READ[真实修改前后证据、必要关联源码]
    READ --> BATCH[逐批提交覆盖与缺口]
    BATCH --> SUMMARY[保存核查结果；修复状态分别报告]
~~~

## Runtime 升级门槛

新版 Skill 要求实际声明 task-review-plan-v3，并提供 begin_security_task、finish_security_task、prepare_task_security_review、get_task_review_method、get_task_review_plan、read_task_review_context、submit_task_review_batch、submit_task_security_review、get_task_security_review 九项工具，来自同一连接环境和构建。缺少任一项时明确要求升级并重连；不回退旧方法、不伪造完成。

源码 0.3.6 已实现 v3；同版本有多个历史候选构建，因此不以版本字符串单独判定兼容，也不编造 0.3.7 等最低版本。现有 v0.3.4 发布包不能与本分支新版 Skill 混用。使用包含本次源码的完整新构建及配套 Skill，通过既有安装/升级入口更新，再核对实际连接的 build_id、工具与能力。此次没有打包、替换系统安装或重启宿主。

## 旧任务和历史

已完成旧任务保留当时协议、完成状态、摘要、风险和证据；历史 COMPLETE 不代表当前项目通过。未完成旧任务不能 finish、skip、prepare、读取复核上下文或提交，不会被自动改写为 3，也不补造修改前源码、清空额度或伪造旧证据。

同一 task_key 不能认领或替换旧记录。无关的后续开发可在下一次修改前显式使用新的 task_key 开始 v3；该基线只覆盖后续改动，旧任务的已有修改仍是历史缺口。公共选择器不会让旧活动记录永久阻塞新任务，也不会按最近活动猜测另一任务归属。旧任务已绑定的修复工作不能借恢复入口取得可编辑状态；风险处置与修复授权仍按其独立契约处理，历史风险可以经过明确选定与影响评估建立新的、仅覆盖未来修复的 v3 任务。

原生修复意图是独立约束：绑定旧任务的意图不会自动取消。Runtime 明确提示旧任务不能继续；用户已经明确暂停修复或切换工作时，沿原引用调用现有取消入口解除阻塞，再为后续工作使用新任务键。取消不改变风险、处置或既有授权。

保留原 SQLite 记录格式、签名和独立风险账本，不清空用户历史。既有任务记录与预像留存期限继续适用，不新增永久归档或永久任务键墓碑，也不通过升级刷新旧记录期限。协议缺失的旧记录也按历史处理；不能假设它是 3。只读投影可展示不支持继续的原因，不对旧记录回写字段。

## 持久化容量约束

原任务库把所有记录合计限制为 32 条，升级时 32 条旧历史会占满新任务位置。现保留 v3 任务原有的 32 条额度，为旧历史保留额外有界空间，总记录最多 64 条；准入按已验证签名的记录判定协议，不信任未签名列，也不删除旧记录腾位。v3 第 33 条和总记录第 65 条仍拒绝。历史与活动查询的上限同步为 64，原有 24 小时 TTL 和每记录 4MB 限制保留。

代价是最坏有界记录读取输入由 32×4MB 增至 64×4MB（JSON 对象另有开销）；活动查询仍先筛活动阶段，正常无旧历史时额度仍是 32 条。这是保留升级历史的有限增量，不是新执行协议或无限归档。

## 旧方法清理与用户内容保护

仅清理产品归属记录确认的 references/quick-task-review.md 和 references/quick-task-review-v2.md。签名清单必须有效，当前文件必须仍与原受管 hash 相同；删除前再次比较，避免升级期间覆盖用户修改。中断的 UPDATING 状态保存清理意图，后续在原归属下恢复，不随意接管未知路径。

用户改过的退役方法原样保留并解除产品归属，回执通过 preserved_retired_files 告知；它不会继续成为新版 Skill 的执行方法。用户修改仍在交付的 Skill 入口或其他当前文件时继续按 USER_MODIFIED 保护，不用新内容覆盖。新安装只包含 v3 方法。

保留 security-review-skill-v1、task-security-v1、task-review-submission-v1、risk-decisions-v2、风险反馈/影响评估、host-event-v1 及各类引用的独立含义。这些名称不是旧开发任务核查执行支持。

## 验收

必要测试覆盖默认 3、显式旧协议拒绝、原记录各恢复入口拒绝且无扫描/写入/基线变化、旧任务历史和新任务并存、真实 v3 取证与累计额度、缺失权威账本拒绝、旧 Runtime 升级提示、安装清理/自定义文件/中断与并发保护。测试回执及当前覆盖限制统一记录在[架构实现记录](ARCHITECTURE_UNIFICATION_COMPLETION.zh-CN.md)。
