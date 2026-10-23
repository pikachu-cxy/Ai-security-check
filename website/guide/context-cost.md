# 上下文开销与 token 监测

0.3.9 提供一键启动当前聊天监控及结束后导出报告。安装新版 Runtime 和 Skill 后，完全退出并重启 Codex，确认连接的版本与构建。

## 日常使用：一键开始，一键导出

1. 在当前项目的 Codex 聊天中说：**“启动本聊天的消耗监控。”**
2. 助手打开本机页面并自动开始观察，不需要你输入命令、采集标签或查找日志。
3. 正常完成开发或检查；使用结束后点 **结束并导出报告**。
4. 保存下载的 ZIP，可直接把它提供给维护者分析。ZIP 含离线 HTML 报告、JSON 统计和计量说明。

页面仅监听本机回环地址，使用随机访问路径；监控本身不请求模型、不启动扫描或修复。身份缺失、多份候选日志或不支持的宿主会明确不可用，不选择“最近的聊天”凑数。当前自动 token 关联仅实现 Codex 本机日志；其他宿主可用通用工具字节统计。

### 报告能说明什么

| 项目 | 说明 |
| --- | --- |
| 本窗口聊天 token | 起止最近已报告累计用量的差值，包含期间的开发、讨论和核查；未结算部分可能缺失 |
| 观察窗口总时长 | 开始至结束的单调时钟时长，包含中间等待 |
| 已关联工具耗时 | 通过当前会话校验的 Runtime 调用耗时；并发区间另给并集，不将累计值当用户等待时间 |
| 纯开发 / 纯安全 token | 目前无法可靠拆分，保持未知；不能用聊天总量减去工具字节得到 |

缓存输入包含在输入 token 中，推理输出包含在输出 token 中，不能再次相加。新聊天尚无用量基线、日志轮转或记录不完整时，报告会说明缺失范围。结束快照固定，重复导出不会继续累计。

### 监控与产品隔离

监控是可选本机模块。关闭、运行失败或从源码交付中整体移除监控模块，不改变产品扫描、任务账本与权限结果。它不写产品业务数据库或宿主配置，不上传统计。

自动关联只检查匹配身份所需的有界本机日志元数据，并读取计数；不保存聊天正文、源码、日志路径或原始会话身份。监控为当前聊天建立有期限的详细记录租约，结束后释放，不改写共享采集模式。受管安装包仍需保持内容完整，不应直接删除包内文件。

下列命令供维护者进行历史导入、对比或诊断，日常使用上面的按钮流程即可。更多边界见[实时监控工程指南](https://github.com/pikachu-cxy/Ai-security-check/blob/feature/runtime-mvp/docs/guides/LIVE_MONITORING.zh-CN.md)。

## 监测什么

Runtime 在最终 MCP 响应处记录一次统计，包含工具调用次数、各工具返回大小、耗时、已交付源码行数、
重复证据交付、复用标记和构建元数据。全局路由内部的子调用不重复计量。
不保存源码、提示词、参数、结果正文、异常文本、项目路径或原始会话标识，不上传统计。
严格只读的安全摘要查询不留调用记录，避免为了监控而创建本地状态；其工具耗时和响应字节不计入工具统计，聊天 token 计数仍包含相应宿主活动。
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

## 维护者：统计与对比

当前源码默认关闭采集，用户主动选择基础统计或详细调试后才记录后续活动。打开页面或查看历史不会自动开启；明确保存过的开启设置继续有效。公开安装包是否包含该行为，应核对实际构建。

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

## 维护者：手动导入 Codex CLI 用量

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

公共统计依赖通用 token 计数契约；Codex 日志适配只在用户启动本聊天监控或显式导入时执行。
Cursor 及其他 MCP 宿主可以使用字节统计，无真实 usage 适配器时保持 token 未知。
这些变更没有修改编辑器配置、审批开关或宿主的上下文管理。
Windows/macOS 使用相同代码；实际平台与编辑器的验证范围以[支持状态](../reference/support.md)为准，不将历史 Windows 定向测试等同于当前 Mac 桌面验收。

## 可重复的本地基准

```console
python scripts/benchmarks/context_cost_benchmark.py --output artifacts/context-cost/optimization-report.json
```

脚本从固定旧提交读取投影实现，用同一份合成数据比较当前实现，校验覆盖状态及完整证据一致。
只生成 JSON 和 HTML，不调用扫描器、模型或网络。报告明确将实际 token 节省保留为未知，
不能用合成数据的字节缩减代替用户的真实用量结论。
