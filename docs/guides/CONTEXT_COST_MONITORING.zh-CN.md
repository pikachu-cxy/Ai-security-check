# 上下文开销与 token 监测

当前适用 **0.3.9 正式版**。Codex 当前聊天可直接请求“启动本聊天的消耗监控”，结束后一键导出 HTML / JSON 报告 ZIP；用法见[监控页面](LIVE_MONITORING.zh-CN.md)及[文档站指南](../../website/guide/context-cost.md)。下文为通用工具统计、手动导入和工程对比方法，不要求普通用户执行手动步骤。

从旧版升级时下载当前包和配套 SHA256，重启宿主并核对 `build_id`；源码拉取不会自动更新独立安装。

## 监测什么

Runtime 在最终 MCP 响应处记录一次统计，包含工具调用次数、各工具返回大小、耗时、已交付源码行数、
重复证据交付、复用标记和构建元数据。全局路由内部的子调用不重复计量。
不保存源码、提示词、参数、结果正文、异常文本、项目路径或原始会话标识，不上传统计。
数据库与现有 Runtime 状态目录并列，文件名为 `context-cost.sqlite3`，签名密钥单独保存；
保留最近 14 天、最多 10,000 条调用事件。过期记录清理意味着长期实验应及时导出摘要。

| 统计 | 含义与边界 |
| --- | --- |
| `text_bytes` | MCP 文本内容 UTF-8 字节 |
| `structured_bytes` | 结构化返回的紧凑 JSON 字节 |
| `wire_bytes` | 完整工具结果的紧凑 JSON 字节，不含 JSON-RPC 信封 |
| `elapsed_ms` | 工具响应前耗时，不含监测写库，不是整段会话耗时 |
| `failed_calls` | MCP 错误或异常次数；正常返回的扫描失败/部分覆盖不算传输错误 |
| `actual_model_tokens` | 显式导入的宿主实际用量；未导入为 null/UNKNOWN |

文本和结构化字段不能相加后宣称是模型输入。宿主可能只选其中一份，还会截断、缓存、压缩历史。
本地字节统计不覆盖宿主自己的文件读取、推理、原生 CLI Hook、用户提示词及完整历史；
Codex CLI 的实际 usage 则覆盖相应宿主运行，不能把全部变化归因于 Runtime。

## 查看一次使用

监测默认启用。使用更新后的 Runtime 并重新连接宿主后，正常工具调用就会记录。

### 可切换的消耗调试模式（当前源码新增）

本节的新命令已进入源码，并在本机以 `4e926b5ba565…` 的 0.3.8 本地调试构建安装验证，尚未公开发行。已有其他 0.3.8 包不因版本号相同而自动具备这些命令；需安装包含该功能的构建后使用。源码开发环境可在仓库根目录用 `PYTHONPATH=src .venv/bin/python -m security_runtime.cli` 代替下列 `security-check`。

本机受管安装入口未加入 PATH 时，可先设置 `RUNTIME_DEBUG="$HOME/.local/share/AI-Security-Runtime-macos-trial/security-check"`，再以 `"$RUNTIME_DEBUG"` 代替下列 `security-check`。首次升级后需重启 Codex，让既有 MCP 进程切到新构建；之后保存模式即时生效。

```console
security-check context-usage monitor
security-check context-usage monitor --mode debug --run pilot-one
security-check context-usage monitor --mode basic
security-check context-usage monitor --mode off
```

- `basic` 为兼容既有行为的默认值：记录调用统计，保留原有数据，不增加调用时间线。
- `debug` 记录调用统计、随机调用编号和起止时间，支持观察工具流程与并发；阶段按工具类别划分，不代表扫描器内部计时。
- `off` 停止自动记录新的调用，保留已有数据供查询和导出；显式导入用量仍属于用户主动写入。

模式和可选运行标签保存在同一统计库，使用该库的进程在后续调用读取，无需重启。关闭过程中已开始的调用可能已有观测；关闭不是历史清理。`--db` 只控制指定的统计库，不会修改 MCP 进程正在使用的库。默认库在当前用户范围共享，开关影响同一库的其他宿主连接；运行标签用于实验分组，不是会话或项目隔离证明。

环境变量优先：`SECURITY_RUNTIME_CONTEXT_MONITOR=0` 强制关闭；否则 `SECURITY_RUNTIME_CONTEXT_MODE=off|basic|debug` 覆盖保存的模式，使用环境指定的运行标签或 `default`。`SECURITY_RUNTIME_CONTEXT_RUN` 覆盖保存的运行标签。非法模式或不可读取的设置停止观测并返回未知，不影响原工具结果。环境变量需要在 MCP 进程启动环境中设置，修改它们仍需重连；保存开关不需要。

### 真实统计的本地可视化（当前源码新增）

```console
security-check context-usage report --run pilot-one --output pilot-one.html
security-check context-usage report --run pilot-one --output pilot-one.json
```

输出目录须存在，文件须为新的 `.html` 或 `.json`；拒绝覆盖已有文件和链接路径。默认最多导出最近 2,000 条明细，可用 `--limit 1..10000` 调整；总览和排名仍基于所选运行的全部有效保留记录，省略数量会明确显示。省略 `--run` 时涵盖该统计库全部保留运行，不能当作当前聊天的独立用量。

HTML 是离线交互快照，无外部脚本、网络请求或源码正文。打开文件即可查看：

- 运行整体的真实 token、响应字节、累计工具耗时、调用和错误数；没有导入 usage 时 token 显示未知。
- 工具耗时/返回量/次数排名、单次最大值及 P50/P95；分位数为保留样本的最近秩计算，样本量单独显示。
- 按工具、类别、状态和名称筛选调用明细及时间线，查看详细模式中的并发调用。筛选不改变顶部完整样本总览及排名，也不会将运行级 token 分配给单个工具。
- 观测窗口、工具区间并集、数据缺失、无效记录、导出省略及构建身份；已有基础记录没有起止时间，不能补建历史时间线。

页面提供采集模式切换命令的复制入口和 JSON 下载；它不能直接控制后台进程。切换后需重新导出新文件才能刷新快照。导出只读取已有统计，不触发扫描、模型调用、安装或修复。

`elapsed_ms` 使用单调时钟；起止时间用墙钟。区间并集不重复累计并发，但不是完整任务实际用时；系统时钟变化会限制时间线解释。模型处理、宿主调度、网络和锁/队列等待尚无独立记录时明确为未知。调试记录中的 `observation_prewrite_ms` 只计测量准备至写入前的开销，排除设置读取、事务提交与完整监控开销，不可作为监控总成本。

实时页面现已作为可选独立模块提供，每 2 秒刷新，支持采集模式控件、单份聊天真实用量读取、扫描入口分类和手动观察窗口。完整产品任务身份、内部阶段/等待拆分及宿主 token 的调用级关联仍待补齐。启动、计量边界与整体移除方式见[实时页面指南](LIVE_MONITORING.zh-CN.md)。实时页面从源码独立运行，不要求替换当前受管 Runtime。

聊天总 token 包含开发、讨论和核查等宿主消耗，不能视为产品扫描消耗；显式扫描入口响应耗时也不等于扫描器内部时间。此次只增加观测和展示，不改变检查、复核、缓存或调度策略，不宣称节省 token 或时间。

```console
security-check context-usage status --json
```

通过 MCP 进程环境变量 `SECURITY_RUNTIME_CONTEXT_RUN` 区分实验，例如 `before`、`after`；
标签允许 1–64 个 ASCII 字母、数字、点、下划线和连字符，首字符须为字母或数字。
未设置时使用 `default`。修改启动环境后需重新连接 MCP；普通终端临时设置不会改变已运行进程的环境。
设 `SECURITY_RUNTIME_CONTEXT_MONITOR=0` 可关闭监测，不改变扫描、复核或修复行为。

```console
security-check context-usage status --run after --json
security-check context-usage compare --baseline before --candidate after --json
```

`top_tools` 给出返回量最大的工具。`limited_measurements` 或 `invalid_records` 非零时应先检查统计完整性，
不能将缺失观测算成节省。事件数量有上限，长会话结束后应及时保存摘要。

## 接入 Codex CLI 的实际 token

Codex CLI 非交互模式的 `--json` 输出包含 `turn.completed.usage`。
在用户原本就要执行的任务中保存 JSONL，或明确选择已有的本地 rollout 日志，再导入：

```console
security-check context-usage import-codex --path before.jsonl --run before --json
security-check context-usage import-codex --path after.jsonl --run after --json
security-check context-usage compare --baseline before --candidate after --json
```

导入只读取明确指定的文件，不搜索会话目录，不保存日志正文，不发起模型请求。
JSONL 本身可能包含项目内容，应由使用者自行保管；监测数据库只保存用量及不透明来源标记。
读取限制为 32 MiB/文件、1 MiB/行、100,000 行，超过限制明确报错，不静默截短后出结论。

相同日志再次导入不会重加旧用量；同一增长文件的后续导入更新已有统计。
rollout 使用最后累计快照，不能把每个累计值相加。
不同文件中同一线程的 exec 片段无法证明是否重叠时拒绝合并；无线程身份或记录损坏时标记不完整。
导入的真实用量仍可能展示部分已观测计数，但不完整数据不生成节省百分比。

`cached_input_tokens` 是输入中的缓存部分，`reasoning_output_tokens` 是输出中的推理部分，
均不能再加一次到总量。计费还取决于模型、缓存和价格；当前功能不推算费用。

对比时使用同一模型、CLI 版本、项目/规则、任务提示和相同起始历史，分别使用新线程，
不要把冷启动与热缓存、恢复旧长会话与新会话混为一组。
`actual_token_reduction_percent` 只有两边真实用量完整时才有值；字节变化单独显示。
可先比较固定首次扫描、未改源码的重复扫描、中断后恢复三种场景。

字段来源：[Codex 非交互模式](https://learn.chatgpt.com/docs/non-interactive-mode)、
[工具输出预算](https://learn.chatgpt.com/docs/config-file/config-reference)。

## 通用优化与宿主隔离

摘要默认值、分页、简短提交回执、完整证据交接预算和重复源码共享均在公共服务/MCP 层实现，
不按 Codex、Cursor 或操作系统分叉。旧完整输出仍可显式请求：扫描 `summary=false`，
查询 `view="full"`，提交 `compact=false`；恢复时旧复核正文须显式开启。
复核状态、原始证据哈希、允许引用范围、BYOK 原始包和修复授权不因压缩而改变。
AGENT_NATIVE 每批领域 JSON 预算为 64 KiB，含指导、schema 和检查点；这不是整个 MCP wire 或模型 token 上限。
容量不足会延后完整成员；单个完整包也装不下时明确停止自动重试，不能当作已复核。

公共统计依赖通用 token 计数契约；Codex 日志解析只在显式导入命令执行。
Cursor 及其他 MCP 宿主可以使用字节统计，无真实 usage 适配器时保持 token 未知。
这些变更没有修改编辑器配置、审批开关或宿主的上下文管理。
Windows/macOS 使用相同代码。早期监测定向测试在 Windows；本轮新增实时页面及相关 72 项回归在 macOS 完成，Windows 实时页面仍待实机验收。

## 可重复的本地基准

```console
python scripts/context_cost_benchmark.py --output artifacts/context-cost/optimization-report.json
```

脚本从固定旧提交读取投影实现，用同一份合成数据比较当前实现，校验覆盖状态及完整证据一致。
只生成 JSON 和 HTML，不调用扫描器、模型或网络。报告明确将实际 token 节省保留为未知，
不能用合成数据的字节缩减代替试用者的真实用量结论。
