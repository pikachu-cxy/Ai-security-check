# Core P0-7.2 — Codex Tool Coverage + Lazy Workspace Bootstrap

本轮只扩展 Global Codex Hook 的工具覆盖和首次 workspace 恢复路径。未修改 remediation、Ticket/envelope、Scanner、Functional Verification、Sandbox/CET 或真实 `%USERPROFILE%\\.codex`；不 commit、不 push。

## 结果

- 原因：Global `hooks.json` 只匹配 `apply_patch|Edit|Write`。Codex 通过 Bash/unified exec 修改文件时，PostToolUse 不会交给 Runtime；手工 SessionStart 才能解析并扫描项目。
- 当前 matcher：`^(Bash|apply_patch|Edit|Write)$`。
- MCP Hook input 保留 event、workspace_path、session_id、tool_name，并增加可选 `tool_input`；不接收 transcript 或完整 tool_response。命令只在内存中用于分类，不写入 state/receipt。
- Bash 分类：`READ_ONLY`、`POSSIBLE_WORKSPACE_MUTATION`、`UNKNOWN`。只读 git status/diff、cat/Get-Content、ls/dir、rg/grep 直接返回 `NOT_SCANNED`；mutation 和 UNKNOWN 仍交给 HookCoordinator，最终以真实 snapshot/content digest 确认变化。
- 非敏感诊断：`tool_classification`、`workspace_mutation_observed`、`changed_file_count`、`scanner_trigger_reason`、`scanner_skipped_reason`。
- Global 路由在 SessionStart 未完成时，首次 PostToolUse mutation 会重试受限 bootstrap；仍在初始化或不可用时 fail-soft，不伪造安全结果。SessionStart 仍是正常 baseline 路径。
- Workspace claim、canonical/path containment、symlink、跨 workspace session 绑定、opaque refs 和现有 baseline/Family/Episode 语义不变。

## 验证

- Codex Hook focused：29 passed。
- P0-7.1 / Global schema 关键路由用例：通过；完整 focused runner 曾发现的唯一失败是旧测试仍假设四字段 schema，已更新为包含可选 `tool_input`。
- Full offline：1414 passed / 9 skipped / 6 subtests passed；最初全量仅有 4 个旧 ABI 断言失败（matcher、tool_input 和 Bash 拒绝断言），更新为本阶段官方覆盖契约后，4 个回归用例单独通过。9 个 skipped 仍是 3 个需显式 managed Scanner 前提和 6 个缺少真实 scanner binaries 的旧 E2E。
- Package/compliance：最终 wheel/sdist 构建、wheel compliance、licenses 和 notices 均 PASS。
- Actual Desktop Core E2E：未运行。加载本轮 Runtime 后，在 Project C 先验证 SessionStart 正常，再分别执行 `git status`、`Get-Content`、Bash 写入和 apply_patch；核对只读不扫描、mutation 扫描、`tool_classification`、真实 changed-file count，以及 SessionStart 缺失时首次 mutation 的 lazy bootstrap。

## 安全边界

首次观察到已有风险而没有 pre-edit baseline 时仍返回 `FIRST_SCAN_UNATTRIBUTED_RISK_PRESENT`，不授权 AUTO_FIX。工具分类不会替代 snapshot、digest、bounded scope 或真实 scanner proof。
