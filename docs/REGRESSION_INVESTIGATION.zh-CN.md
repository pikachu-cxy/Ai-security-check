# 六项回归失败调查与文件通知收尾修复

本次仅修改源码和测试，不安装、替换当前 Runtime 或修改用户的 CLI 配置。

## 失败归因

| 用例 | 结论 | 证据与处理 |
|---|---|---|
| `test_real_delta_same_revert_and_readonly[afterFileEdit]` | 旧测试初始化过时 | 用例使用非默认的旧比较模式，要求完整内容差异判断，却没有创建 `hook-v1` 比较状态。新的原生 SessionStart 使用 product epoch，不能与旧快照互换。采用项目已有的 `legacy_comparison` 测试助手初始化，保留原来的无变化、修改、回退、重复事件、只读和隐私断言。 |
| `test_real_delta_same_revert_and_readonly[afterShellExecution]` | 同上 | 同样显式建立旧比较状态，不改变生产事件处理逻辑。 |
| `test_workspace_isolation_and_multifile_bom` | 同上 | 两个工作区分别初始化旧比较状态，保留两个文件、BOM 和跨会话隔离断言。 |
| 原 `test_cursor_automatic_default_records_paths_and_keeps_chat_quiet` | 输出及 Stop 预期过时 | 已验证的 postToolUse 会刷新内部会话路由，以支持启动上下文遗漏或 MCP 重连；非空内部上下文不等于向用户输出警告。改为验证路由签名和确切上下文、路径入库、没有扫描。取消状态仍须静默；正常 Stop 的配置行为由专门用例覆盖。 |
| `test_pre_ready_before_script_post_and_finish_collect_exact_paths[False]` | 本次失败由受限运行环境阻断原生通知造成 | 有依赖时监听能启动，但受限环境探针连续约 2.6 秒只返回 timeout；同一探针在普通本机权限下约 33 毫秒收到新文件事件。未修复源码在普通本机权限下通过该用例。 |
| `test_pre_ready_before_script_post_and_finish_collect_exact_paths[True]` | 同上，全局入口 | 未修复源码在普通本机权限下也通过，不能将这两项失败直接解释成产品必然漏记。 |

依赖缺失是最初另一个环境问题。测试解释器必须能加载项目要求的 `watchfiles==1.3.0`；仅补依赖不能解决操作系统通知被运行环境阻断的问题。

## 另外确认并修复的产品问题

`development_file_watch._Window.run` 原来在开始收尾后，第一次 100 毫秒轮询返回 timeout 就退出。
timeout 只说明这次轮询没有收到事件，不是操作系统已排空所有写入通知的确认。
因此，Shell 已完成写入而通知稍晚到达时，清单可能漏掉文件。

增加可控的延迟通知用例：收尾开始后先返回 timeout，下一批才返回文件路径。
旧代码稳定得到空清单；修复后的清单包含该文件。这个验证不依赖平台通知速度，也不依赖放宽测试权限。

修复使用原有的两秒总排空预算，空轮询期间继续接收，截止后结束；不随新事件或重复收尾重置期限。
到期仍有通知时保留已记录路径及排空超时诊断，不无限等待。正常收尾最多增加约两秒排空等待。
不新增全项目盘点、Git 差异回溯、扫描或文件内容采集。

## 验证范围

- 确定性测试：迟到通知不会因首次空轮询丢失；持续通知不会无限延长收尾。
- 原生通知：真实子进程新建、修改、删除、重命名、原子替换、子目录文件、外部写入，以及收尾后停止记录。
- Hook 集成：项目和全局 Pre/Post/finish 链路；新建文件改用真实子进程脚本写入。
- Cursor：保留旧模式的原断言，同时单独验证默认模式只记录路径、不建立快照、不即时扫描。
- 配置与 Stop：沿用此前新增的专项测试及开发检查、等待、Cursor 生命周期回归。

本地运行相关用例可使用具备项目依赖和 pytest 的解释器：

```sh
PYTHONPATH=src python -m pytest \
  tests/test_development_file_watch.py \
  tests/test_development_file_watch_hooks.py \
  tests/test_cursor_host_adapter.py \
  tests/test_lightweight_hooks.py \
  tests/test_user_config_stop.py \
  tests/test_development_delivery_mcp.py \
  -q --tb=short -p no:cacheprovider
```

原生通知用例需在允许系统文件通知的环境运行；不通过跳过或改成轮询全项目来掩盖失败。

## 保留的边界

排空预算无法保证补回操作系统从未投递的通知，也不能覆盖收尾后仍在后台写入的进程。
真实 CLI 端到端验收仍需单独执行。
Cursor 短生命周期命令 Hook 没有因此获得跨进程常驻监听；未知 Shell 写入仍保留未知范围并需要明确路径补录。
新增默认 Cursor 测试专门约束这一点，不能把空清单解释成没有修改或已完整扫描。
# 2026-11-01 桌面 Stop 验收补充排查

只读核对验收项目的签名检查记录与聊天执行历史；没有改写测试记录、补交测试扫描或替换安装版本。

| 文件 | 本批次 Agent 复核 / 逻辑审计 | 本批次 Stop | 保存结果 |
| --- | --- | --- | --- |
| `stop_probe.js` | 开 / 开 | 开 | 真实 Hook 续接；序号 1/1，静态结果就绪，已提交复核 |
| `static_only_probe.js` | 关 / 关 | 关 | 未请求收尾、未扫描、无 Stop 续接记录 |
| `stop_disabled_probe.js` | 关 / 关 | 关 | 未请求收尾、未扫描、无 Stop 续接记录 |

因此第二次没有验收到“只关 Agent、保留 Stop”的组合。后来磁盘上的 Stop 开关为 true，
不会改写上述未收尾记录的 false 快照。修改用户配置无需重启；应新建检查核对有效快照。
第三次不续接符合其关闭快照，但单凭无续接聊天记录不能独立证明宿主已实际发出 Stop 事件。

第二次未收尾的文件监听窗口继续运行，也观测到了第三次写入的 `stop_disabled_probe.js`。
两次检查归属不同，第三次另有独立记录；这里是同一工作区时间窗重叠，不是聊天被合并。
原记录保留，不为验收自动清理或补交。

成功续接那次仍存在报告偏差：助手读取了完整方法并提交复核，但未再次读取风险及处置，
也未使用四个独立风险标签。本次源码修复在 Stop 原生输出与风险接口共用报告要求，
提交响应明确要求从 offset=0 重读，分页响应提供下一页动作；读取不确认报告已交付。
测试覆盖 Codex/ Cursor 的实际输出字段、提交后处置变化、完整分页、只读不写账本、
零风险报告边界、静态模式仍触发 Stop，以及关闭快照不被后来开启配置覆盖。
这些自动化测试验证产品输出契约，不承诺宿主模型必然遵守自然语言格式；仍须后续桌面验收。

