# 上下文开销与 token 监测

本轮功能已在源码实现，尚未随新安装包发布。已有 0.3.8 独立安装不会因为源码变化而自动获得此功能。

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
Windows/macOS 使用相同代码；本轮定向测试运行在 Windows，macOS 实机尚未验收。

## 可重复的本地基准

```console
python scripts/context_cost_benchmark.py --output artifacts/context-cost/optimization-report.json
```

脚本从固定旧提交读取投影实现，用同一份合成数据比较当前实现，校验覆盖状态及完整证据一致。
只生成 JSON 和 HTML，不调用扫描器、模型或网络。报告明确将实际 token 节省保留为未知，
不能用合成数据的字节缩减代替试用者的真实用量结论。
