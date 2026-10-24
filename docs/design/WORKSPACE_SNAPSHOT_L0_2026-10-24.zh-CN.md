# 工作区快照 L0 契约与实施边界

日期：2026-10-24。主计划：[大项目完整基线与可恢复扫描](../NEXT_DEVELOPMENT_PLAN.zh-CN.md)。

本页锁定设计并记录分批实施。首批L0仅交付纯类型契约；随后L1/L2已接入新任务分页存储/跨1000文件捕获、Hook基线、worktree窄准入及全局只读诊断，再补充新域受管GC。`development_capabilities()` 当前返回 `L1_L2_PARTIAL`，分别声明新TASK_CLOSEOUT、GLOBAL_MCP诊断及新GC合同SEALED捕获范围；产品epoch、活来源恢复、扫描分片、分页复核及可信宿主能力仍为false。旧任务保持原读写契约、表示策略与限制。

## 1. 全链路读写方与容量清单

下表记录L0初始盘点，首批实现差异见第7节和主计划实施记录；MB/KB 以下均为十进制字节量。分页响应保护可以保留，不能冒充项目完整性上限。路径、字典、正文和导航整体驻内存的问题必须与容量一起改。

| 环节与函数 | 当前容量/整体操作 | 主要读写方与后续落点 |
| --- | --- | --- |
| `hook_runtime.capture_snapshot`、`global_workspace.source_snapshot` | 1000 文件、20 MB、单文件 1 MB；Git 清单在内容类型排除前限数；整体 `file_digests` | SessionStart/Hook reconciliation；L2 改读版本引用，不再独立大快照包 |
| `tasks.security._inventory`、`tasks.inventory.non_git_inventory` | 20,000 路径/目录项、路径名总量 256 KB、2000 目录、深度 12；非 Git 忽略项也消耗枚举预算 | `security.capture`；L2 流式枚举及持久化目录队列 |
| `tasks.snapshot.SnapshotPolicy/collect_snapshot` | 1000 文件、20 MB 读取、512 KB 内联正文；先全量构造 `names/ordered/selected` 再 `selected[:max_files]`；缺口明细样本 100 条 | 准入、结束捕获、新鲜度检查；L1/L2 分页条目/统计与缺口索引 |
| `tasks.preimages.TaskPreimageStore.writer`、`_PreimageWriter._persist_sanitized` | 1000 引用/任务、正文 2 MB/文件、24 MB/任务、96 MB/工作区、数据库 128 MB；32 个 before 任务，end 命名空间 64；引用 8192 B、路径 4096 B | 开始/结束前像写入及 `read`；当前整个 `yield` 持有写事务，L1 改对象与页短事务 |
| `tasks.preimage_fingerprints` | 证明 2 MB/文件、8 MB/任务、16 MB/工作区 | 前像语义写入/读取；L1 保留表示及证明语义，不能只扩正文 |
| `tasks.baseline_inputs._Writer.start/put/seal` | 20 MB/输入、1 MB/文件、96 MB 工作区配额；hash 字典及独立原文目录 | `security.begin` 改前扫描原文、`risk_attribution.compare`；L1/L2 版本引用 |
| `tasks.queued_inputs.QueuedInputs.capture/open/discard` | 20 MB/输入、1 MB/文件、96 MB；`open` 全目录读哈希，校验/清理均限 30,000 文件及目录项 | `queued_closeout` 结束输入；L3 引用固定 end 版本，分页完整性验证与回收 |
| `tasks.activity.record` | 1000 路径/64 KB；事件重放窗口 256；每次重写累计路径，超限转未知范围 | 编辑事件、结束捕获；L3 路径索引与起始 invocation 路由 |
| `tasks.security._finish`、`tasks.risk_attribution.compare` | 静态目标 `eligible[:1000]`；before 风险目标超过 128 时整次比较不可用 | 收尾扫描/归属；L4 持久化分片与逐风险待比较状态 |
| `target.TargetDetector.detect` | 10,000 文件、2000 目录、深度 12、单文件 1 MB；整体列表，超限抛错 | 扫描发现及非 Git Hook；L2/L4 固定范围索引与有界分析输入 |
| `scan_input.ScanInputLimits/capture_scan_input/_index/_inventory` | 10,000 条、128 MB、4 MB/文件、8 MB index；manifest/inventory/index 整体驻内存，多次全量重验 | scanner execution 与 reuse；L4 输入引用、语义分片与覆盖回执 |
| `tasks.security_state.TaskRecords.save/decode` | 单 task JSON 4 MB；32 活跃 v3、64 历史、32 retained projections；Hook failure 1000 路径/128 KB，封装 160 KB | baseline/end/changes/review 同条记录；L1/L5 拆任务头、索引与证据页 |
| `tasks.durable.SignedRecords._put/_all` | 4 MB/记录、128 条、数据总量 96 MB、数据库 128 MB；候选全量加载验签 | before/queued inputs、queue、workspace registry、cache；L1/L4 索引分页 |
| `scan_artifacts.save_result/original_project` | 完整结果和 input_hashes；再次读取全部输入；遍历完整候选；继承 SignedRecords 配额 | 当前事实复用及改前比较；L4 按输入/语义身份索引分片事实 |
| `git.GitService._run_bytes/_paths`、`hook_runtime._git` | stdout 通常 4 MB/10 秒；一次读取并按 NUL 切分 | inventory/index/diff；L2 流式 NUL 解析与持久化进度 |
| `task_workspaces.snapshot/prepare/manifest` | 10,000 文件、64 MB、8 MB/文件、2000 目录；全部原文先放 dict，再生成 manifest | 独立目录种子准备；L2 流式物化，宿主实际切入另验 |
| `task_review.plan._build_adaptive`、`budget._policy/create_ledger` | 全量生成 units/windows/sources；10,000 units、100,000 reads；source96/navigation16/control16 MB；仍受 task JSON 4 MB 限制 | 复核计划、阅读、提交；L5 存储分页与累计账本 |
| `hook_state.HookStateStore.load/save`、`closeout_state` | Hook JSON 2 MB、64 sessions；Hook另有2000 families/10000 occurrences/1000 proof rules；closeout 单记录1 MB、每工作区512条 | Hook状态、回执及恢复；L2/L5 只存引用并保留有界元数据保护 |
| `task_review.results`、`task_review.contract` | 结果每页64 KB/3 findings；单次提交 findings10/attributions100/limitations30 | RPC保护，保留并分页累计；不等同于项目/任务覆盖总上限 |

`local_evidence` 当前还限原文件 1 MB、窗口 80 行、上下文 20 行、行显示 600 字符、摘录 24,000 字符。窗口和响应限额可保留；原始正文是否可存、扫描器是否支持、agent 是否交付完整必须分别判断，不因显示截断宣称完整覆盖。

## 2. 两类基线、首次接入与范围封口

| 类型 | 确定时机与允许用途 | 禁止推导 |
| --- | --- | --- |
| `PRODUCT_COMPARISON` | 产品封存接纳条目后发布 epoch，可晚于首次接入并包含捕获期间修改；作为后续比较参照 | 不证明用户最初项目状态、任务前像或作者 |
| `TASK_BEFORE_EDIT` | 实际首次编辑前完成该任务真实起点准入，绑定原 task/owner/root/source/表示策略 | 不用较早产品 epoch、编辑后的正文或另一会话基线补历史 |

首次接入、产品基线可比较、扫描完成、任务核查完成分别呈现。多会话已开发时先接入和建路由，不要求所有会话停写；旧任务保留原记录及前像缺口。工作区身份、任务身份和版本身份分开，同仓库不同 worktree 不能合并。

捕获开始固定根身份与纳入/排除策略，默认不跟随目录链接、禁止越界，并按目录身份防循环。持久化捕获代次逐条接纳、读取及封存；到达有限时间/重试预算后关闭本代次成员集合。持续新增不能不断重开已封口页；不稳定/拒绝读取的路径保留缺口，未知正文不等于空文件。

普通活目录正常遍历结束不证明某个瞬间清单完整。已遍历目录新增、目录移动、无连续事件日志时记录覆盖未证明；可以封存 `OBSERVED_ONLY` 比较参照，但不能包装成原子版本或跨文件真实运行状态。后发现路径进入后续比较义务；先后未知标为“首次发现、先后未知”，不直接认定封口后新增。新 epoch 不覆盖旧正文、任务绑定、队列或累计用量。

## 3. 纯类型契约与持久化对象

当前纯类型模块定义 `BaselineKind`、`CaptureState`、`SourceConsistency`、`SnapshotCompleteness`、`SnapshotStatus`、`CaptureBatchBudget`。它们能拒绝自相矛盾的计数，不能证明采集事实、身份、权限或来源连续性。

- `SEALED` 仅说明接纳条目/缺口记录不可变；`comparison_available` 是封存参照可用，不保证任意路径正文可比。
- `complete` 要求确切清单分母、全部哈希/所需正文及零缺口；`OBSERVED_ONLY` 即使计数完整也不等于强一致。
- `strict_task_preimage_eligible` 还要求 `TASK_BEFORE_EDIT`、编辑前捕获及冻结来源/写屏障；调用者仍须验证 owner/root/version 与真实宿主证据。
- 批预算初值256文件/8 MB/200 ms，任一达到即续页；不是项目总量上限，阻塞的单文件操作不承诺200 ms内可中断。机器磁盘、并发和管理员配额独立保留。

以下是完整存储职责契约；首批已实现签名header、条目/对象和固定字节来源游标，产品epoch、持久枚举作业、完整任务绑定及扫描/复核分页仍待实施：

| 对象 | 最小职责 |
| --- | --- |
| `snapshot_header` | 引用、根/来源身份、两类基线、epoch、策略/表示版本、观察时间与间隔、封口序号、完整性/一致性、状态及根摘要 |
| `snapshot_entries/pages` | `(snapshot_ref, normalized_path)` 索引、类型/长度/对象引用、缺口或排除原因、页摘要；分页列举无需全量列表 |
| `content_objects` | 私有不可变字节或分块对象，安全域内去重；内容哈希/句柄本身不授权读取 |
| `capture_jobs/cursors` | 原来源、持久化目录/Git流进度、已提交页、尝试预算、租约与fence；游标不能靠排序后活目录偏移恢复 |
| `task_snapshot_bindings` | 原task/owner/root/路由代次、真实before、可选产品epoch、固定end；共享字节不共享证据ID或处置 |
| `activity/scan/review` | 路径和事件索引、固定partition计划/回执、复核unit/window/evidence及累计账本，各自分页 |

对象先写私有临时文件，完成哈希/身份验证后原子封存；短事务同时提交页、引用和游标。读取、复制、哈希不包在长SQLite写事务内。最后短事务发布SEALED，其摘要覆盖策略和全部页；失败/失效worker不得发布。磁盘不足转 `WAITING_CAPACITY`，不截前缀伪报完成。

冻结任务恢复只续原有效来源；原来源丢失保持 `HISTORY_UNAVAILABLE`。产品观察恢复可保留间隔续做，但记一致性降级，不能拼成旧时点。GC按活动引用和状态保留原源，TTL不直接删除活动输入；孤儿宽限期与存储代次防GC竞态。不通过可写硬链接把内容库暴露给工作区或扫描器。

## 4. 扫描 `partition_contract` 的安全语义

这是待L4实现的adapter契约。每个计划绑定同一来源版本、目标/上下文集合、配置/规则/引擎/数据身份，保存分片语义、闭包摘要、逐片状态及覆盖回执；能力未知默认不允许任意分片。

| 引擎语义 | 调度约束 |
| --- | --- |
| 文件局部/密钥 | 按字节或预计耗时分片；保留相对路径、配置与忽略作用域 |
| 跨文件/模块 | 按依赖闭包提供上下文，必要时合并交叠闭包；不能因分片截断source→sink路径 |
| 依赖图 | manifest/lockfile/父级及workspace配置组成单元，一单元一次；原引擎图不完整限制仍保留 |
| 全项目或未声明能力 | 固定版本整项执行；容量不足等待/报缺口，不偷偷切文件列表 |

完成要求计划已封口且全部必要片有有效回执；队列空、零告警或一片成功不等于完成。失败只重试同版本失败片；旧租约不得发布。129+风险文件保持逐风险待比较，改前没扫不能推断风险新引入。缓存按输入/闭包/配置/规则/引擎/数据身份复用事实，不共享agent结论/证据，也不把PARTIAL合并成FULL。

## 5. 旧 v3 兼容与 worktree 关联

旧任务继续原合同、原表示版本和原限制。只有完整且可验证的旧对象能投影为只读分页，保留原时间、摘要、owner与权限；漏掉的第1001文件不能从当前目录补进旧基线。新能力显式协商，旧客户端不得把新产品基线理解为任务前像；旧构建不支持新存储时明确拒绝，不能破坏状态。

worktree窄准入与全局绑定只读诊断已实现；跨根宿主握手仍待实现，契约见主计划L0专项。目录准入不能整体放开Codex配置/凭据，诊断不能触发扫描/注册/基线创建。来源目录、实际执行根与检查版本须有证据对应；创建副本不等于宿主已切入，仍不承诺OS写沙箱。

### 5.1 可信宿主与绑定诊断能力矩阵

| 能力 | 当前事实 | L0要求与后续验收 |
| --- | --- | --- |
| Codex/Cursor Hook claims | 可验证字段、路径声明及事件参数一致性；Codex另有连接内重放校验 | 这些都是claims，不是宿主原生证明；不能据此断言当前聊天身份或真实cwd |
| 签名 `session_ref` | 校验签发凭据的owner/root/有效期一致性 | 保留凭据完整性；持有有效凭据不自动证明请求来自当前聊天，不能升级为宿主attestation |
| 会话与根目录绑定 | 内部记录可绑定同根，跨根会返回不匹配 | 新绑定代次需可靠握手；没有可信宿主证据时标“无法确认”，不选最近访问目录 |
| 公开只读绑定诊断 | 全局MCP已实现；局部MCP无此入口 | 预检拒绝也能返回固定原因；签名路由匹配不升级为当前聊天/执行根证明，无注册/扫描/写Runtime状态副作用 |
| 跨根宿主握手 | 尚未实现 | 开始调用绑定invocation/根/代次；切根不搬迁原任务，迟到事件沿原路由；宿主实际cwd另证 |
| 原生冻结来源/写屏障 | 均未实现 | 分平台证明固定来源或覆盖全部写入者；共享目录锁、mtime、双遍哈希不替代此能力 |
| OS写沙箱 | 尚未实现 | 独立worktree只隔离文件副本，不能证明进程被禁止写其他目录 |

原误拒绝有**两道禁止来源**：环境Codex home和pool.integration.home可能不同。当前两层统一使用窄准入校验，将真实保护边界规范化；包含 `..` 或配置符号链接别名也不能绕过。Git双向指针/注册和目录身份不符则拒绝，保留配置、凭据、Runtime状态和容器根保护；**禁止删除整个home保护或仅凭路径包含 `worktrees` 放行**。

`tests/snapshots/test_l0_workspace_admission.py` 的真实临时Git linked worktree回归已覆盖：外部根/项目子目录解析、环境home与pool home窄准入、伪造/损坏/链接指针拒绝、保护路径别名、特殊字符路径及同会话跨根不改原绑定。它只在临时目录创建Git夹具，不启动桌面会话、不扫描；不等于Codex/Cursor实际新聊天或移交验收。Git查询超时10秒，退出后最多读取/解析1 MB；匿名系统临时输出不是严格1 MB磁盘写入限额。

## 6. L1—L6 依赖与验收

| 阶段 | 前置及交付 | 必须验证 |
| --- | --- | --- |
| L1 | 本页契约→分页存储、对象引用/短事务/GC | 10万条不塞单JSON；内存随批大小；对象/提交强杀、磁盘满不seal；旧任务可读 |
| L2 | L1→inventory/Git/Hook/begin、两类基线、范围封口与种子物化 | 1001/10000/100000无前缀丢弃；持续写入有界；原来源恢复；不能证明强一致就保留限制；worktree准入另验 |
| L3 | L1/L2→活动索引、起始路由、固定end与队列 | 三会话交错/切根/迟到事件不串用；未知Shell保留未知；排队后修改不换源 |
| L4 | L2/L3→语义分片、比较回执与索引缓存 | 整体/分片覆盖等价、跨文件/依赖图不丢、129+比较、单片恢复、失效worker不发布 |
| L5 | L1/L3/L4→分页复核与覆盖发布 | 大量units不重写task JSON；读/提交幂等、未完页不COMPLETE；旧证据权限及累计额度保留 |
| L6 | 已闭环路径→性能/故障/Codex与Cursor实机 | 冷热耗时/RSS/锁时间/公平性有记录；首次接入/持续编辑/切根与诊断实测；安装/重连单独确认 |

新增 `tests/snapshots/test_l0_capacity_characterization.py` 仅刻画旧限制：1001小文件默认读取1000、pending=1；末文件优先时换另一个遗漏；私有writer独立拒绝第1001条。使用临时目录、不scanner、不调大上限；它通过也不表示容量问题已修复。

2026-10-24执行记录：`python -m pytest -q tests/snapshots tests/test_runtime_info_summary.py tests/test_host_lifecycle_contract.py` 为57项通过。扩展到原快照/归属/隔离/工作区绑定回归首轮132项通过、1项在夹具准备时返回 `GLOBAL_CONFIGURATION_NOT_READY`；该失败项独立重跑1项通过，随后 `python -m pytest -q tests/test_global_workspace_binding.py` 整组40项通过。原因未据此确定，不隐去首轮失败。规模、故障和桌面验收仍属未来工作。本轮5个改动源码/测试文件的静态检查及必需窗口阅读完成，但项目盘点仍受1000文件上限影响，91个其他路径无法比较，任务核查保留部分覆盖。

后续完整验收须把10000/100000跨页、持续新增有界退出、原来源恢复、回收及强杀纳入断言。L1/L2首批不能替代L1—L6闭环，也不能凭设计文档或1001夹具宣布任意规模与真实宿主兼容完成。

## 7. L1/L2 首批已接入路径与剩余边界

新普通TASK_CLOSEOUT（`BATCHED_FILES_V1`）取消捕获/新鲜度/静态目标的1000前缀；每256文件checkpoint，原文引用采用必须校验seal的新合同，未seal及缺seal行/表/MAC均拒绝。原任务的缺失前像不补建，旧reader明确拒绝新原文合同。

`snapshot_store.py` 在项目外私有目录保存签名头、页与去重对象；`tasks/snapshot_pages.py` 将baseline/end映射拆出task控制JSON。相同不可变来源摘要可续页，容量等待不丢既有游标，不用活目录换源。seal只代表仓库页封存，不能抹掉原capture缺口或证明单一时点来源。过期风险投影不保留页/正文引用，但保留end哈希及原basis，恢复风险不依赖已失效源页。

Hook SessionStart也取消1000文件前缀，保留2 MB状态保护、20 MB读取及有限目录/Git预算。各路径仍会整体构建兼容字典/路径集合；首批无GC，随后新增新域受管GC，旧域及未封存捕获仍保守保留，128 MB达到后明确容量等待。任务清单20,000条/256 KB路径名、任务正文24 MB/工作区96 MB、扫描10,000文件、控制/复核JSON等预算仍存在，未完成项继续按主计划实施。

实现回归包括1001任务基线及结束版本的新增/修改/删除、原文不可变、私有页恢复/幂等/配额/并发读取、旧数据兼容、seal缺失拒绝、过期风险投影、Hook不启动扫描及只扫描编辑文件、工作树窄准入及只读诊断。正式测试执行记录在最终稳定代码上追加；此前广回归226通过/1失败（并发页读取的初始目录身份问题），已修复并单组55项通过。不得把首轮失败从记录中删除。

最终稳定源码定向回归：`.venv/bin/python -m pytest -q tests/snapshots tests/tasks/test_task_snapshot.py tests/tasks/test_task_preimages.py tests/tasks/test_closeout_lifecycle.py tests/tasks/test_closeout_queue.py tests/tasks/test_task_ownership.py tests/task_review/test_task_review_closeout.py tests/test_runtime_info_summary.py tests/tasks/test_task_capacity_diagnostics.py`：**250项通过，266.68秒**。未执行全仓库全套或10万规模测试。

目录/宿主兼容回归：`.venv/bin/python -m pytest -q tests/test_global_workspace_binding.py tests/test_global_workspace_root_regression.py tests/test_codex_host_claims.py tests/test_host_lifecycle_contract.py`：**83项通过，292.74秒**。两组合计333项通过，`git diff --check`通过；这些仍是临时夹具与源码测试，不代表当前桌面进程已加载新代码。
