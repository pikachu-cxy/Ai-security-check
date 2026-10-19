# P3 持久化事务、恢复与旧写入程序围栏

本实现保存既有检查事实与待交付义务，不授予修复权限，不重建历史基线，不把宿主的测试声明升级为 Runtime 执行证明。开发任务仍仅执行 v3；历史协议记录仍只读。

## 权威事实与交付边界

| 权威来源 | 同一提交保存的内容 | 后续目标与重复保护 |
| --- | --- | --- |
| 开发任务签名记录 | 原检查结果、任务到风险账本的投影意图 | 风险行版本及 projection ID；成功后才 ACK 原任务 |
| Scanner feedback SQLite | feedback 审计与 assessment/撤销 effect | disposition SQLite inbox、来源单调序号、目标 assessment/choice 版本 |
| Native risk authority | feedback 审计与 MATERIAL_CHANGE effect | disposition inbox；迟到评估不能重开新的用户选择 |
| disposition SQLite | 用户选择与精确 native intent 释放模板 | impact SQLite 同事务取消精确 owner/source/完整 intent 版本并保存签名 inbox |
| verification journal | 实际原扫描器复查结果、来源哈希、目标版本及双目标意图 | ledger 和 closure 各自保存事实与 inbox，再分别 ACK 来源 |
| Closeout SQLite | 实际扫描及原探测器复查结果、公开 pending receipt 与签名 outbox 同事务 | closure 事实与 inbox 先提交；原结果摘要、generation、owner 状态及目标技术水位一致后才 ACK |
| closure authority | 当前原探测器关闭事实、逐 session 缓存意图 | 精确原文件名、host、session、workspace、缓存版本 CAS |

目标已提交但来源 ACK 失败时，重试读取目标 inbox；目标失败则来源义务继续 pending。新源码、较新目标事实、较新用户选择或较新缓存不能被旧 effect 覆盖。原扫描 JSON 与 triage 记录保持原样。prepare 和普通查询不迁移、不建库/密钥、不消费 pending、不重跑扫描器。

Verification journal 的未完成交付恢复还会重查已 ACK 目标：ledger 绑定该事件实际选中风险行的版本及事件标记，closure 绑定技术 records 水位。旧 inbox 或部分 ACK 不足以证明目标仍是当前状态；较新事实使旧义务 `SUPERSEDED`，不会覆盖较新事实。无关风险行及缓存 ACK 不改变该 ledger 事件的目标水位。已经整体 `APPLIED` 的来源历史保留，不据此宣称当前风险仍已解决。

历史 `task-verification-journal-v1` 缺少 `input_context` 时不补固定输入证明；仍核对已保存的 `input_hashes`，缺少该字段时才沿原 `before` 哈希恢复交付语义。其 `APPLIED` 表示历史交付完成，不是新固定输入证明。恢复不会补造 `input_id`、原始输入哈希或执行证据，也不会续跑旧 quick-task v1/v2 协议。

Closeout 使用 `closeout-persistence-v1`。`finish` 在同一 SQLite 提交中保存实际结果与独立 outbox，先返回 `NEEDS_RETRY` 和 `persistence_sync=PENDING`，强完成标志均为 false；这表示源结果已保存、目标尚待同步，不是扫描提交失败。只有 closure 目标保存事实和 inbox，且当前技术 records 水位仍等于该回执水位，源端才按原 pending receipt HMAC 条件确认。缓存 ACK 不改变技术水位；历史 inbox、缺失水位或较新技术事实不能冒充当前关闭证明。源端确认不会覆盖同 generation 的新 owner 或新 receipt。

`get` 只查询；`run` 优先有界恢复该原引用，不重新执行扫描器。恢复核对原源码/上下文、计划、原 pending 序号、活动快照及目标版本；只允许识别自身条件完成的待办删除，不清除新序号。原会话缓存仅按原稳定版本清除已执行的 deferred providers。目标迁移中断仅由合法 `run` 恢复，查询不修补。源 ACK 与最终呈现前分别核对目标技术水位及当前版本，较新状态使旧义务 `SUPERSEDED`，保留原执行历史。

Scanner 链的实际来源是 `SQLiteStore.save_finding_reviews`：feedback 审计与 `finding_effects` outbox 在同一 SQLite 事务写入，由 `feedback_effects.py` 管理；目标为 `RiskDispositionStore.apply_effect` 的 assessment/撤销/choice 变更和 inbox 同事务。来源 effect 使用稳定 authority/issue 身份及单调 revision；目标保存来源水位，既允许同一来源的连续 pending 正常推进，也拒绝不同来源或较新用户选择之上的旧覆盖。来源审计保留，inbox 重放不新增用户决定。mutation 恢复按 attempt 次序有界轮转，1000 条 pending 上限内，前面失败的 16 条不能永久饿死后方健康交付；attempt 只表示交付调度，不是技术事实或授权。查询不更新该轮转元数据。

用户决定独立于技术评估。处理 EXCLUDE/DEFER 时若无法验证当前 intent，只保存带未知版本的阻塞义务；用户选择仍保存成功，恢复不得猜测后来 intent 或取消较新的修复流程。明确提示交付未完成即可，不再要求用户重新作同一个决定。

Native release 队列在 SQL LIMIT 之前先按 owner 与已知精确 intent 摘要过滤，foreign owner 和未知版本义务仍保留但不阻塞后方可执行交付。单条目标或 ACK 失败时保留该项、继续有界处理其他项，返回当前 owner 的 pending 数。队列读取或计数失败时返回 `PENDING` 与未知数量，不假称零 pending，不修改坏库或用户选择；已有 intent guard 继续生效，显式取消后的普通开发不因后台恢复异常而被再次阻塞。默认只读查询仍可观察全部 pending 与未知项。

## 扫描完成后的待发布事实

scan_publication 使用独立、有界的签名 SQLite 日志保存 TASK / Hook 完成结果及原 lease、源码与事件依据。它不保存原始源码，不授予执行、发布或编辑权限。扫描完成后先 stage，取得工作区锁并核对原条件后由原服务保存权威结果，最后 ACK 日志。

发布锁繁忙时返回 SCAN_ATTEMPT_PUBLICATION_PENDING；同一原任务重试先恢复事实，不重复扫描或消耗第二次预算。目标提交后、租约完成前或 ACK 前中断均幂等恢复。过期、新代际、源码/辅助配置/Hook 序列变化及取消结果不能恢复为成功；旧 worker 不能结束新 worker 的 lease。

新事件在登记新 pending 序号前尝试恢复，原事件去重回执可读取已恢复事实。只读事件和查询不消费日志。日志上限为 32 条、单条 8MB、总计 32MB；在真实工作区锁下按已签名执行代际有界回收确定失效事实，避免不同旧 scope 永久占满。

扫描占位状态新写 workspace-scan-attempt-v2，兼容验签的 v1 查询及旧 scan-inputs 根清理；执行 receipt 仍为 v1，旧 writer 不能误解释新目录义务。固定输入的短私有根保留 ACL、链接拒绝、inode/device 及签名清理校验。

## 账本分区与容量

旧全局 1000 行限制会使一个新任务耗尽全部历史共享额度。现在使用按 `origin_task_ref` 分区的不可变签名文件，单分区仍限制 1000 行、2 MB；最多 256 个历史分区。固定哈希文件名及签名 index 同时校验内容、workspace、原任务、行数与字节数。view 可局部读取原任务；完整 read 保留全部历史。

写入先产生全部不可变候选分片，最后一次签名 index CAS 发布；读者不会看到部分新分区。分片目录最多 512 个文件，允许一次最多 256 个旧分片与 256 个候选分片并存，最坏约 1 GB；index 单文件另有 2 MB 上限。已发布的 pending 意图及目标 inbox 存放在 index 内，不引用已退役分片。仅在真实 workspace 锁下，且文件名、内容哈希、签名及归属均通过时，才清理当前 index 未引用的产品分片。未知或改动文件保留并停止；不会为腾空间删除历史或 pending。

容量不足给出 `TASK_RISK_LEDGER_*_CAPACITY`、count 与 limit，不冒充配置错误，不清空历史，不盲目扩大共享额度。真实 finish 已提交源结果后若投影遇到该异常，返回 `risk_ledger_sync=PENDING`，并在本次响应的 `capacity_failure` 中说明容量和源结果已保存；诊断不另写历史，恢复沿原任务重放且不重新扫描。到达分区总量、journal 或回执上限仍需受控后续存储策略；这些是明确的剩余运维上限。

## 旧写入程序的真实围栏

单纯变更 JSON contract 不能阻止已经缓存旧 rows 的裸 save。迁移后，旧固定路径 `task-risk-ledger.json` 与 `closures.state` 成为带签名 receipt 的非空目录，新事实分别写入 `task-risk-ledger-v2.state` 与 `closures-v2.state`。旧 reader 不能读取该目录，旧原子文件替换也不能覆盖该目录。

审计与子进程验证覆盖 ledger 的 `v0.3.4`、`a51a58d`、`b352731`：主要写入路径使用同一 workspace 锁；即使旧类缓存 rows 后绕过锁裸 save，也被固定路径围栏拒绝。这只保证已审计支持集合及其固定路径读/原子替换行为，不保证任意古老未知程序或主动删除围栏目录的外部程序。旧构建在该 workspace 的相关账本写入会拒绝，需升级；旧历史保留。

迁移只由既有合法写入触发，在实际持有 OS workspace 锁的线程执行。`lock_held` 只是互斥证明，不是用户授权。顺序为：验证旧数据及 key → 签名 PREPARED journal → 复制并验签/验哈希旧备份 → CAS 核验并移动原固定文件 → 建立目录围栏和签名 receipt → 写新 authority seed → COMMITTED → 发布目标事实。签名备份和移动备份均保留；没有源码或授权材料写进围栏 receipt。

Hook 会话 retention 与确认恢复只枚举固定 `64hex.json` namespace，并继续拒绝其中的链接、非普通文件及损坏状态。共享目录中的历史 ledger JSON、closure 状态和迁移围栏不参与会话数量/TTL，也不能被误当作新的宿主证明。恢复仍保留原 scan 唯一性、原任务/成员/源码/策略绑定及保存前的第二次证据校验。

每个已归属阶段可在后续合法写入恢复。只读遇到未完成迁移明确失败，不自动修理。未知文件、变化过的旧原件、坏签名或不匹配备份保留为冲突并停止；不清目录、不覆盖、不从当前源码重建旧事实。目录沿原私有 state 目录继承访问边界。

全局 `runtime-state-v1` 保留表示既有安装与历史读取入口兼容，并不表示业务 state 可无损降级。固定路径围栏能保护数据，但旧 Runtime 降回后可能无法使用相关账本。发布 metadata 必须声明实际读/写 state formats、单向 writer fence 及回滚所需能力；签名 launcher pointer 固定当前槽的 build_id；新版管理器核验该槽的包 metadata，并以其中 storage_contracts 派生单调能力下限，activate/rollback 要求目标声明覆盖当前集合。pointer 没有另存一份格式能力字段。安装探针另行核对 Runtime 基础能力；fresh-profile probe 看不到真实 workspace 的迁移，也不证明各私有 writer 的实现正确，不能单独证明降级安全。缺少声明的旧包不自动回滚；外部直接启动未知旧 binary 或旧 launcher 不受新增 metadata 单方面控制，仍由每个 store 的真实围栏防覆盖。

不将签名 v1 备份自动恢复成可写旧路径，不反向重建基线、历史审查或批准；必要的源码回滚须配套支持已启用存储契约的兼容构建。安装升级的 config/Skill 恢复 journal 仍只恢复自己管理的配置，不撤销业务 authority/fence，不恢复临时授权。

## TTL 与恢复入口

过期开发任务删除前，同一个 SQLite 事务将 pending 投影的签名元数据归档；最多保留 32 项，满则回滚当前清理/写入而不丢失义务。原 task_ref 仍过期，历史任务不会恢复为可执行，源代码前像及语义证明仍按各自 TTL 删除。归档去掉前像文本、语义证明与临时 packet，只保存恢复目标所需原事实和版本。terminal 归档可按 TTL 清理，pending 不受 TTL 清理。

`task_projection.reconcile_pending`、native feedback effects、native release、verification journal 和 closure cache 都是有界、持锁、变更入口的恢复操作；查询入口不调用它们。verification journal 最多 512 个来源记录，每条遵守既有 impact 私有记录 1 MB 上限，pending 不清理；inbox 回执与 ledger/closure 变更同一目标提交。任何容量/存储失败都保留已提交事实并报告交付缺口，不能宣布全部完成。

Closeout outbox 最多保留 2000 条签名来源记录，每条 1 MB，同时 pending 最多 512 条；终态来源保留，pending 不按 TTL 清理。容量满时停止新的源确认，不删除历史腾空间。新增表独立于原 `closeouts` 行，旧式该行替换不会删除同步义务；这不代表旧 binary 能理解新恢复协议，新版管理器须拒绝缺少该 storage contract 的降级。

Closeout 的独立来源 lease 目前为 600 秒；workspace scan lane 的续租不会延长该来源 lease。超过此限制的结果保守拒绝发布并保留待处理状态，本实现不承诺任意时长的后台续跑。

验收收据包括 `p3-ledger-fence-20261018.xml`、`p3-native-release-recovery-20261018.xml`、`p3-verification-recovery-20261018.xml` 及最终 P3 组合回归。它们是自动化故障注入与协议测试，不代表 Codex/Cursor 双宿主实机验收。
