# P0-9 Cursor Host Adapter v1

Status: implementation and local native command/Scanner trial completed; final full offline regression passed. Cursor Desktop remains PENDING_ACTUAL_CURSOR_DESKTOP. Automatic continuation remains PENDING_CURSOR_CONTINUATION_CAPABILITY. Do not substitute the local fixture for Desktop evidence.

[Mapping and official source investigation](cursor-host-adapter-design.md) was stated before implementation. Current selected official events: sessionStart, afterFileEdit, afterShellExecution, stop. The event model and shared scanner/policy/snapshot/family semantics are unchanged. Cursor installs its own command transport; it does not masquerade as a Codex MCP Hook. Standard native MCP configuration was investigated and is left untouched.

CursorHostEventAdapter validates event-specific claims and resolves the single claimed workspace through the existing canonical resolver. Conversation binds persist across short-lived command processes; missing/malformed identity, wrong workspace, nested repo attribution, remote claims and links fail closed. generation_id is validated, not invented. There is no guaranteed invocation ID for these four events, and no claim of exact Host replay protection. Bounded signed session/root metadata and a local sequence support binding consistency; repeated events converge through real filesystem snapshots, cooldown and single-flight. Neither command hints nor afterFileEdit itself prove mutation.

The finite common capability model declares session/file/shell/global/stop support; invocation and setup seed are false. A finite Cursor transport dataclass separately records documented Stop followup and MCP support, missing post-edit Agent context/live continuation, and unsupported remote execution. Capability is not authorization or execution timing.

SessionStart reuses WorkspaceBaselineSeeds.capture_session with an explicit host argument (default remains codex). It captures a bounded baseline with real quick Scanner coverage and source byte recheck under the original workspace lock. Duplicate SessionStart preserves the existing pre-edit point. Ordinary activity dispatch is unchanged. Missing startup uses existing first-scan attribution-unavailable semantics, never fake NO_CHANGE or AUTO_FIX.

Cursor command subprocesses cannot export connection-local Ticket authority to an independently connected MCP process. The selected post events have no documented Agent context output. Existing report_only RemediationService policy is used as a conservative transport ceiling, without writing or replacing the user's mode setting; automation is not granted. Stop returns no automatic follow-up. Finding/Remediation Offered is the honest boundary for this release, not an automatic fix/receipt/CLOSED claim. Full closure continues to work through the unchanged Codex transport.

Global setup uses the installed absolute Python/venv or frozen CLI command, never a repository PYTHONPATH workaround. Windows quoting rejects unrepresentable interpolation paths. Temporary installed native command tests include spaces in the executable and workspace path. Config merge removes only exact definitions proven by an HMAC ownership manifest. Custom command/prompt Hooks, unrelated Hook events, unknown top-level settings and mcp.json values remain intact. Repeated healthy setup/repair does not rewrite config bytes. Missing owned definitions can be repaired; modified lookalikes or ambiguous duplicates require review and fail closed.

Recent Hooks persist in the existing hook-diagnostics.db (32/workspace, 1024 total); Cursor event/schema vocabulary and normalized fields survive process/restart. Header starts before claims validation. Sensitive raw command, output, edits, source, transcript, token or session/generation identity never enter this journal. Independent CLI reads the same journal without starting Scanner or changing security state.

Initial focused: 211 passed / 200.38s. Final focused: 215 passed / 208.65s. Final full offline: 1582 passed / 9 skipped / 6 subtests passed; 1861.18s runner duration. Skip reasons are separately recorded in [regression](cursor-host-adapter-regression.json). [Local installed trial](cursor-host-adapter-local-trial.json): PASS / 40.06s, actual offline Scanner and Windows command stdio, temporary wheel installation with borrowed system dependencies, ordinary delta, same bytes, TLS finding, simulated Host manual fix + real rescan, Stop convergence, cross-process CLI and installation lifecycle. [Codex local MCP trial](cursor-host-adapter-codex-trial.json): PASS / 36.70s, actual managed offline scanner, two recurrence Episodes, simulated Host, original opaque refs/ticket/envelope/receipt path. The inherited fixture source label is historical; subprocesses load this repository's current src. [Package](cursor-host-adapter-package.json): wheel/sdist integrity plus licenses/notices compliance PASS; 87 module bytes checked.

The first native trial stopped on an acceptance-script SQL column-name mistake after the TLS detection; the corrected rerun passed. No product Scanner workaround was made. Skip details and full result belong in the final regression artifact, not inferred here.

## Candidate commands and future Desktop trial

Run with the user's chosen installed candidate; this iteration did not install into active Runtime or real .cursor/.codex.

```powershell
security-check setup cursor --scope global --json
security-check integration status cursor --scope global --json
security-check integration repair cursor --scope global --json
security-check integration remove cursor --scope global --json
security-check hooks recent --path '<test-workspace>' --limit 8 --json
```

The generated user hooks.json has version 1 and four event arrays. Each command is the installed absolute executable + CLI prefix + cursor-hook, type command, timeout 120; Stop adds loop_limit 1. No Codex matcher/template expansion or raw commands from Hook input are installed. Cursor's Hooks UI/output channel must confirm actual discovery and delivery.

After choosing the candidate, open a fresh local trusted Java Git fixture in Cursor and a fresh conversation, wait for sessionStart baseline to complete, then ask Cursor to change timeout 2000→2100 only, without invoking security-check. Independently query recent: host cursor, claims VALID, normalized DIRECT_FILE_MUTATION, content_delta_detected true, changed_file_count 1, scanner_run true. Write identical bytes or run git status: no scanner. A later isolated TLS edit should produce the first-party finding with real scanner evidence. Automatic Agent Fix is not a P0-9 Desktop PASS criterion until continuation is actually established; do not bypass by allowing Runtime to edit source.

Current limitations: single local root, no exact invocation identity, no cloud/remote/Tab/generic pre/post tool coverage, no post-edit Agent context, no live automatic Ticket continuation, command-process cache lifetime resets, no Desktop trial this iteration. Other Hosts, Deep, Scanner/Rule/Ticket changes, commercial gates and source writers remain out of scope. Three users and independent Ground Truth retain their prior Pending/unexecuted status.

SessionStart diagnostic note: baseline capture emits Scanner stages before the normalized activity dispatch. Its final scanner_run=false denotes that the subsequent unchanged activity dispatch did not scan; inspect the stage journal for the real baseline scan. No fabricated post-edit performance or automatic closure is inferred from that row.
