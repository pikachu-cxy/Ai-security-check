# 第一阶段：耗时测量与验收方案

## 2026-11-05：开发流程计时补充

保持五步操作：记录编辑 → 执行检查 → AI 复核 → 用户决定如何处理 → 修复后复查。本节为本次源码变更；下方早期基线和构建记录仅保留作历史参考，不代表当前安装版本。

复用现有计时开关和报告命令，无新增操作步骤。Windows 不再使用 Unix 权限位决定是否丢弃计时事件；日志目录应使用当前用户的系统临时目录。

报告新增以下字段（单位均为毫秒）：

| 字段 | 含义 |
| --- | --- |
| `mcp_timing.observed_window_ms` | 本次采集中首个已闭合调用开始，到最后一个已闭合调用结束；包含调用间空档 |
| `mcp_timing.active_call_ms` | 服务器处理调用的时间并集，重叠调用不重复相加；包括等待后台的时间 |
| `review_windows[].first_evidence_to_complete_ms` | 同一检查版本首次读取证据，到扫描器复核和业务审计均完成或按配置跳过的首次保存；包含宿主和模型等待 |
| `model_thinking_ms`、`first_call_to_final_reply_ms` | 保留未知；需要宿主会话时间戳才能测量，不由服务器猜测 |

具体操作分别展示为 `mcp.complete_development_check`、`mcp.read_development_risk_context`、`mcp.submit_development_review` 等阶段。复核提交调用的服务器耗时不等于整段 AI 复核耗时。尚未完成的复核窗口保留未知；空提交、读取结果或提交成功本身不代表复核完成。

复核参数错误会返回具体字段、类型修正提示和 `review_saved=false`，整批未保存；补齐当前 `dirty_seq` 为 `expected_seq`，将 `limitations` 传为字符串数组，再重试原项。无须重新扫描或新建检查。工具发现中直接展开这一个提交操作的嵌套参数，其他操作继续使用原有紧凑定义。

Windows 源码环境可用下列只读入口验证日志链路（不启动项目扫描）：

```powershell
$env:PYTHONPATH = 'src'
$env:SECURITY_RUNTIME_GLOBAL = '1'
.venv/Scripts/python.exe scripts/performance/measure.py --scenario mcp --cache unknown --build phase1-working-tree -- .venv/Scripts/python.exe scripts/performance/mcp_probe.py --samples 2 -- .venv/Scripts/python.exe -m security_runtime.cli mcp
# 将下一行路径替换为上一条命令打印的 Timing directory。
.venv/Scripts/python.exe scripts/performance/report.py C:/Users/你的用户名/AppData/Local/Temp/asr-performance-实际目录
```

桌面验收仍需让 Codex / WorkBuddy 的实际 Runtime 进程使用本次构建及相同计时环境；源码测试通过不代表已安装版本自动更新。一次采集对应一次验收任务；从首个产品调用到最终回复的总时间，取宿主记录中两者时间戳之差，再与上述服务器和复核区间对照。不能把它们相加，否则会重复计时。

---

状态：计时实现和测试入口已提供；正式安装/扫描/桌面耗时验收待执行。后续性能优化待验收数据再制定。

## 范围与版本

以当前已安装 0.3.12 的源码提交 `fbbf758c173d6c48984a810c394b55d838162ad9` 为基线，在独立分支 `codex/performance-phase1` 开发。原集成目录存在合并冲突，不改动该目录。本分支未发布、未替换已安装 Runtime。验收必须记录包含本次改动的实际构建摘要，不能仍标记为原版构建。

本次增加安装、规则准备、组件准备、后台检查、扫描器子进程与 MCP 请求的计时。不开启预热、不改变扫描范围/策略、不合并 MCP 工具、不调整并发数和授权流程。

## 三条测量链路

| 链路 | 观测项 | 计时口径 |
| --- | --- | --- |
| 安装 | 引导、Python 下载/校验/解压/探测、产品下载、压缩包校验、离线环境/依赖、配置、包校验/清单、激活、能力探测、组件与漏洞数据准备 | 外层总时间与内部各操作分别记录；安装完成与后台全部就绪分开验收 |
| 检查 | 提交至首次处理尝试、后台批次、规则内容身份/解析/计划、引擎探测、扫描子进程、已有扫描阶段计时 | 首次/重复、排队/执行分开；保留实际覆盖与结果版本 |
| MCP | 建连初始化、工具发现、服务器处理、客户端往返、序列化结果大小 | 服务器不声称能测模型思考与桌面传输时间；直接 stdio 与桌面分别验收 |

原有扫描结果中的 `scanner_diagnostics.timing_ms` 和各引擎诊断继续作为文件发现、输入准备、并行编排、归一化、持久化的事实来源。新日志补充生命周期和进程边界，不用包装器时间替代已有细项。

Shell/独立安装器阶段边界由测试入口收到固定标记时计时，是包含输出传输延迟的观测值；子步骤详细计时以 Runtime 单调时钟为准。现阶段下载仅测总时间，DNS/TLS/首字节、下载字节/重试次数仍需关联现有下载诊断，不伪造拆分。组件探测的隔离子进程可能清理追踪环境，其内部缺失保留为未知，外层 `install.capability_probe` 仍计时。

每个 Python span 保存随机运行/进程身份、父 span、固定阶段名称、单调起止与耗时、正常返回/抛出异常。正常返回不等于业务成功。排队关联使用本次运行加盐摘要，不保存实际检查引用。仅同一运行、同一机器启动内关联排队时间；跨重启/缺失提交记录显示未知。

## 使用入口

以下命令均在本工作副本根目录执行，`python` 需来自已有开发环境（Python 3.12+ 且安装项目依赖）。源码运行先设置 `PYTHONPATH=src`。不需要修改用户全局配置。

### 先检查测量链路

```sh
PYTHONPATH=src python scripts/performance/measure.py --scenario smoke --cache unknown --build phase1-source -- python scripts/performance/rules_probe.py
```

该命令只读取内置规则，连续三次解析，报告规则数量、缓存命中、首次和后续耗时，不扫描项目。

### MCP 直接连接

```sh
PYTHONPATH=src SECURITY_RUNTIME_GLOBAL=1 python scripts/performance/measure.py --scenario mcp --cache unknown --build phase1-source -- python scripts/performance/mcp_probe.py --samples 20 -- python -m security_runtime.cli mcp
```

只调用运行信息，无项目接入/扫描/修复。每次新建服务器进程；进程内第一条与后续请求分别看。客户端测量文件 `mcp-client.json` 包含每次往返、错误标志和序列化字节数，不保存返回内容。未完成分页时明确标记；不能把第一页工具数量当作总数。

桌面端要在专用验收配置中启动相同测试构建并传入追踪目录/运行 ID，分别测连接与连续调用；直接 stdio 测量不能代替桌面结果，也不能借此归因模型延迟。

### 安装与扫描

先按仓库现有构建流程生成包含 `performance_trace.py` 的测试包；安装脚本和测试包须来自同一工作副本。不要直接使用线上旧包冒充带内部计时的测试包。macOS 本基线含专属 Python 的 trial 安装入口；原生 tar 包入口另提供 `scripts/performance/install_native.sh`，复制当前集成目录安装流程，仅加入阶段标记；原脚本 SHA256 为 `b6bd79d3fee39064a6930615683065116337dce2e122345a1cfe15ba1844d640`。两种安装链路分别验收，不混用数据。

在专用测试账户/虚拟机中运行安装；命令本身会安装所选包。测量包装器不隔离 HOME、不清缓存、不选择目标、不替用户安装。

```sh
python scripts/performance/measure.py --scenario install-fresh --cache empty --build ACTUAL_TEST_BUILD -- sh distribution/macos/install.sh codex /absolute/test-payload-directory
```

重复安装改为 `--scenario install-cached --cache warm`。升级/离线分别使用 `install-upgrade` / `install-offline` 并选择实际匹配的命令和环境；标签本身不模拟离线或清除缓存。

扫描使用测试构建已有的 CLI/MCP 入口和同一固定小型样例。将明确的扫描命令放在包装器 `--` 后；首轮 `scan-first`、后续 `scan-repeat`，记录文件数、规则数、语言、引擎版本、配置摘要、漏洞库版本/新鲜度和覆盖状态。命令每次新进程与同一常驻会话重复调用须分组；不能以 OS 文件缓存热替代进程缓存热。

后台场景须等原检查引用的保存终态，或安装准备的保存就绪状态后再汇总。外层命令退出并不代表后台完成。组件缺失/过期、扫描 PARTIAL、请求错误均保留，不算成功性能样本。

### 生成报告

包装器在系统临时目录创建专属 `asr-performance-*` 文件夹并打印实际路径：

```sh
python scripts/performance/report.py /absolute/asr-performance-directory
```

输出 `run.json`（场景和外层时间）、`events-*.jsonl`（逐进程事件）、`report.json`（分段聚合/缺失/未闭合/队列）、可选 `mcp-client.json`。后台完成后可以重新汇总同一目录。文件属于本地测试资料，需保留时复制整个目录；正式基线按轮次独立保存。

## 测试矩阵与样本

| 场景 | 初始条件 | 首轮验收样本 |
| --- | --- | --- |
| 首次安装 | 独立干净测试环境，记录网络/平台/架构 | 3 次独立环境 |
| 重复安装 | 同构建和有效缓存 | 5 次 |
| 升级 | 明确旧构建到测试构建，保留升级回执 | 3 次 |
| 离线 | 可重复的网络阻断，区分完整/缺失缓存 | 各 3 次 |
| 首次检查 | 新 Runtime/工作进程，同一固定样例 | 5 次 |
| 后续检查 | 同一会话/进程，先无修改重复，再相同规模修改 | 各 10 次 |
| MCP | 新建连接及同连接连续只读调用 | 5 次建连，每次 20 次调用 |

安装前台完成 T_install、所有组件就绪 T_ready、检查提交到结果可读 T_check、MCP 往返 T_rpc 分开记录。计时开启/关闭按交替顺序做对照，控制机器负载、样例、缓存、网络、实际构建一致；不能并发跑正式性能样本。首次/重复不能混算。

## 第一阶段验收门槛

1. 实际测试构建和配置已记录，能重跑；记录的缓存状态为真实初始条件而非标签推测。
2. 安装同时有脚本阶段和内部安装事件；扫描有 `scan.total`；MCP 有客户端与服务器两侧数据。缺失内部事件的旧包报告不通过完整性检查。
3. 无无法解释的未闭合/孤立事件、日志截断、解析错误；超时/失败样本单独展示。报告的 `measurement_valid` 只表示已观测日志满足基本完整性，不证明全链路覆盖或功能通过。
4. 并行/嵌套阶段不能相加作为总时间；报告阶段为 inclusive 时间。保留原始时间线，按总等待时间定位关键路径。首轮少样本报告中位数/范围，稳定 P95 至少同类 20 个独立样本；报告内单次运行的重复操作 P95 不能当作产品 P95。
5. 开关计时前后业务结果、错误、安装回执、扫描范围与状态一致；没有新增下载、扫描、修复或外发日志行为。
6. 计时开销暂定不超过同条件总耗时 5%；不足样本或环境噪声大则标记未验证，不宣称已达标。
7. 将总耗时中无法观测的时间明确保留为未知。安装下载安装前的引导、子进程启动、跨进程空档、后台完成等不能填 0。

本阶段不设“安装减少 30%”等优化收益门槛。验收交付是可解释、可复现的基线与各场景前三个耗时来源，之后才制定缓存、预热、接口精简和并发优化方案。

## 实现边界与恢复

默认无计时文件。开启需存在的绝对私有目录（权限 0700）和 32 位十六进制运行 ID；包装器自动提供。日志不记录参数、命令、项目路径、源码、异常正文或工具返回内容。每个进程单文件上限 8 MB，汇总最多 256 个进程文件；达到预算视为测量缺口。目录不可写时不影响原业务，但报告不得因此声称测量完整。

包装器超时终止直接子进程，不擅自杀已脱离的后台产品工作进程；须检查原状态。移除计时环境变量或使用 `--disabled` 即关闭新计时。保留现有产品监控设置并在对照样本中一致使用。

## 本地原生测试构建

本次原生构建输出到 `dist/performance-phase1/security-check`，仅供本机架构测试，不发布、不覆盖已安装版本。构建身份以目录内 `version.json` 为准，`source_dirty=true` 明确表示未提交的性能测量改动。

打包后的本地 tar 包与 SHA256 放在 `dist/performance-phase1/payload`。在专用测试账户中，把上述安装示例的脚本替换为 `scripts/performance/install_native.sh`，本地包目录替换为该 payload 目录，并把 build 替换为 `version.json` 的 build_id。本地包安装不包含网络下载时间；线上完整下载安装必须另测，不能把复制本地包标为下载提速。

本轮实现验证发现四项原有回归失败，均在未修改基线复现（增量包验证、全局工厂 admitted 参数、安装准备旧回执、宿主分析配置影响的断言）。不属于本次计时变更修复范围，不能声称全套回归通过。新增计时测试十项通过；另一次计时/安装进度/MCP 上下文回归组合 28 项通过（当时计时测试为八项）。
