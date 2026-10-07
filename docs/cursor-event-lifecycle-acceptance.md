# P0-9.4 Cursor Event Lifecycle + Baseline Ordering

本轮只修 normalized lifecycle / snapshot publication / 独立 command Hook 进程排序。起点与最终 Git HEAD 均为 `ee1bfd9c12493683cc313cb3628753a51ae124ac`，分支 `feature/runtime-mvp`；未 commit/push，不替换活动 Runtime，不修改真实 `.cursor` / `.codex`，不执行新 Desktop E2E。前序未提交成果保留。

用户最新真实 Desktop 证据确认 P0-9.3 claims、generation、workspace anchor、relative roots、project env、file containment 已通过；这些实现本轮冻结。新生命周期的真实 Desktop 仍 `PENDING_USER_RETEST`。

## 根因与证据边界

旧 Cursor ingress 在 normalized SessionStart 调度前调用 `WorkspaceBaselineSeeds.capture_session`。其 `_capture` 在 workspace OS lock 内运行 `_scan_scope(... baseline=True)`，扫描后复查字节且要求完整 coverage，最后才保存 session baseline。因此 SessionStart 扫描耗时会堵住真正的修改事件。`_scan_scope` 的旧统一 diagnostic literal 是 `POST_TOOL_USE_MUTATION`，即使调用用途是 baseline 也使用这个标签。

`Baseline source changed` 与 `Baseline coverage insufficient` 都可能在扫描后导致 ValueError；Cursor 已 validated 分支将其压成 `HANDLER_EXCEPTION`，无原异常持久化。源码证明这个失败路径存在，最新时间线与 source change 竞争吻合，但历史记录不足以唯一确定当时究竟是哪个 exception predicate；精确异常根因记 `UNDETERMINED_FROM_RETAINED_DIAGNOSTICS`，不得猜测为已证实。

旧 FILE_CHANGED 获取 lock 不等待，被 SessionStart 扫描挡住即返回 BUSY，没有持久 pending intent。没有后续活动/Stop 时修改可能永久漏处理。旧 normalized Stop 映射到 AGENT_STOP，同一旧扫描路径在缺 baseline 时执行 Scanner 并建立修改后的 baseline；它无法恢复丢失的 pre-edit attribution。

## 新调度和比较点

Cursor 显式使用 `HookCoordinator.handle_lifecycle`；neutral dispatch 依据 normalized kind 路由，并继续复用同一个 Core 的 snapshot、state store、OS workspace lock、scanner、family multiset、coverage gating。Codex 与 legacy callers 的原 convergence/Stop continuation 路径保留，不做全 Host 生命周期迁移。

| kind | route | 行为 |
|---|---|---|
| SESSION_START | SESSION_BASELINE | claims/binding 后，在 OS lock 内捕获两次 bounded HMAC filesystem snapshot，验证稳定及 activity ordering，然后原子 fsync/replace 发布 comparison baseline；无 Scanner/AI/build/Deep/remediation |
| WORKSPACE_ACTIVITY | WORKSPACE_RECONCILIATION | READ_ONLY 直接跳过；其他操作读取已有 snapshot，对当前真实 filesystem digest reconciliation。有效 byte delta 使用既有增量 Scanner，一次管理层 scan；成功且 source 稳定才推进 snapshot |
| SESSION_STOP | SESSION_FINALIZATION | finalization/read pending intent，不扫描、不创建 baseline；没有 baseline 则 `SESSION_STOP_WITHOUT_BASELINE` |

重复 SessionStart 保留已发布比较点，不用修改后字节覆盖它。基于 byte inventories 的 activity scope 为 changed files + 已有 family proof 所需 paths，不加入未变化的 pre-existing dirty files。Scanner engine、规则、finding/policy/remediation/receipt/Ticket/Envelope、generation/anchor/containment 均未修改。

comparison baseline 的 coverage 为 UNKNOWN、execution 为 NOT_EXECUTED、scan id 为 null；不是“已扫描且无风险”的证明。第一次 Scanner 才建立 family security observation，仍沿原 `FIRST_SCAN_UNATTRIBUTED_RISK_PRESENT` 安全语义：既有风险可能在编辑前存在，不冒认 NEW、不授权 AUTO_FIX。后续 Family/Episode 和覆盖证明继续复用原实现。现有完整 scanner baseline/state 保留既有 proof。

## 跨进程排序及无法证明的情况

仍用现有 OS-owned workspace single-flight lock，process death 自动释放，不删除 lock inode。Cursor lifecycle 有界等待最多 10 秒；真实 delta 不依赖 Stop 排空，activity 在锁内重新 reconciliation，不因旧 cooldown 直接丢弃不同字节的编辑。完全相同的 snapshot 在 lock 内 dedupe，重复/重叠 event 不重复启动同一次 scan。

workspace-local `pending-activity.db` 复用 SQLite transaction：最多 64 个 pending session，只有 host/session hash 与 Runtime 生成的 opaque arrival nonce，无 event payload、源码或身份原值。arrival 可以在另一进程持有 workspace lock 时登记；完成只清除匹配 nonce，不能清除后来的 arrival。该 intent 不是 Finding、proof 或 authorization。超时返回 `WORKSPACE_SINGLE_FLIGHT_TIMEOUT`、`pending_mutation=true`、`mutation_event_dropped=false`，独立进程/重启可见；下一 workspace activity 重试真实 digest，Stop 不偷偷扫描。没有新增后台 worker，故超时 pending 不承诺无人触发的自动完成；明确提供 retry，而非 BUSY 后永久遗忘。

baseline 捕获期间已存在/新到达 activity intent，或两次 capture 不稳定：不发布一个“修改后 pre-edit baseline”，返回 `BASELINE_ATTRIBUTION_UNAVAILABLE`。baseline 捕获失败返回 `BASELINE_CAPTURE_FAILED`。后续缺比较点 activity 走原安全 first-scan/lazy attribution unavailable，绝不伪造 delta/NEW。没有可靠 Host pre-edit barrier/原编辑时间的迟到事件，Runtime 不能追溯证明过去字节；baseline 是本次 SessionStart 实际观测到的稳定比较点，不能被解释为全局强制 Host 编辑顺序保证。

Scanner 返回 FAILED/PARTIAL，或 scan-time moving contents 时保留先前 snapshot 与 pending intent，不把失败缓存为完成证明；同字节 retry 仍真实扫描。边界/引用校验不放宽。

## Diagnostics

既有 bounded cross-process recent SQLite 保留。增加闭集 `event_dispatch_route`、`baseline_state_before/after`、`baseline_publish_status`、`activity_waited_for_baseline`、`activity_wait_ms`、`busy_reason`、`mutation_event_dropped`、`pending_mutation`、`scanner_invocation_count`，以及 BASELINE_CAPTURE_STARTED / BASELINE_PUBLISHED / SESSION_FINALIZED stage。

`scanner_invocation_count` 是本次 Core 管理层 quick-scan 调用次数；不是各 provider OS process/probe 数的合计。`scanner_run` 继续用既有实际 process ledger。等待用本进程真实 monotonic wall time；只有 arrival 时 baseline 缺失、等待后出现的可观测 publication 才标 waited=true；锁拥有者不能确定时为 null，不推断 Scanner CPU。diagnostics 不存 raw path、原 conversation/generation、command、edits、tool input/output、transcript、源码、Secret、token。

## 验收记录

新增 `tests/test_cursor_event_lifecycle.py` 与 pipe-controlled independent process fixture。覆盖 snapshot-only baseline、duplicate start 保留、ordinary 2300→2400、same bytes、revert、CRLF/BOM、multi-file scope、read-only、Stop 有/无 baseline、failed capture、first-scan attribution、failed scan retry、独立进程 capture/publication overlap、timeout pending/retry、conditional completion 和 closed diagnostics。旧 Cursor Stop assertion 按明确 finalization 状态更新。

首轮 targeted：208 passed / 1 failed / 156.28s；唯一失败为旧 Stop assertion 仍要求 REUSED_LAST_RESULT，已更新为本轮要求的 SESSION_FINALIZED。最终 focused：343 passed in 331.23s (0:05:31)；full：1687 passed, 9 skipped, 6 subtests passed in 2141.83s (0:35:41)。9 skipped 单列于 regression artifact（3 显式 performance benchmark + 6 默认 offline 未启用的 real_e2e scanner cases），不算通过。新增15 lifecycle cases全部通过；不把首轮失败记 PASS。

候选 wheel/sdist 离线构建、integrity、88 module byte 对照和 compliance 已 PASS；首轮 package 发现新 process fixture 未进入 sdist，已加 MANIFEST 精确 include 并重新验证。installed native command + actual managed offline Scanner local trial PASS / 37.76s，临时 venv `--no-index --no-deps --system-site-packages`，借用已安装依赖，非全依赖隔离；独立 CLI 查询 recent PASS。SessionStart scanner=false、route SESSION_BASELINE、publication PUBLISHED；ordinary delta=1、scanner=true、managed invocation=1；Stop scanner=false、SESSION_FINALIZED。此测量 under concurrent local tests，不是 Desktop benchmark。

现有本地实际 MCP + managed offline Scanner Codex recurrence 两轮 PASS / 37.39s，opaque refs 原样、原 Envelope/receipt、安全复扫到 CLOSED 保持；Host 编辑为模拟，不是新的真实 Desktop。详见 local/codex trial artifacts。新 Desktop、Cursor live continuation、三人试用、独立人工 Ground Truth 均未伪造通过。

## 下一次 Desktop 最小复测

在使用经用户自行更新候选 Runtime 的 Cursor 中，打开 Project F 的新 conversation。先只读查询 recent，确认该 sessionStart 已 `BASELINE_ESTABLISHED / SESSION_BASELINE / PUBLISHED / scanner_run=false`。随后只做一次普通 timeout 2300→2400 修改，不主动扫描、build 或测试。用独立 PowerShell 查询：

```powershell
security-check hooks recent --path "C:\Users\Administrator\Desktop\ai-security\runtime-cursor-e2e-f" --limit 8 --json
```

应见同 session hash 的 afterFileEdit：claims VALID、WORKSPACE_RECONCILIATION、snapshot available、content delta=true、mutation=true、changed_file_count=1、scanner_run=true、scanner_invocation_count=1，无 BUSY 丢失。随后自然 stop 应 SESSION_FINALIZATION / scanner=false；未开始新的 Desktop E2E，也未在本轮安装真实用户配置。
