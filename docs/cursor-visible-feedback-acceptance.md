# P0-10.1 Cursor Visible Security Feedback acceptance

Status: LOCAL VERIFIED. Final focused/full offline regression passed. Actual Cursor UI visible-feedback trial PENDING. The preceding detection/attribution/Finding/Policy/advisory chain is DESKTOP VERIFIED by the user's report; that does not verify this delivery patch.

## Official contract and installation

Checked https://cursor.com/docs/hooks on 2026-10-07. `postToolUse` runs after a successful tool call. Common identity fields include conversation_id, generation_id, hook_event_name and workspace_roots; event fields include tool_name, tool_input, tool_output (JSON-encoded string), tool_use_id, cwd, duration and model. The documented optional output is `additional_context`, injected into the conversation after the tool result. The Global command runs from the Cursor configuration directory: process cwd is never a workspace authority.

The existing four owned commands remain. One owned `postToolUse` command is added with `matcher: "^Write$"`, `type: "command"`, timeout 120 seconds, and the existing installed-runtime cursor-hook launcher. Signed legacy four-event ownership manifests migrate to five events during setup/repair. User postToolUse commands, unknown configuration fields and MCP configuration remain intact. Repeated setup/repair do not rewrite correct content; remove deletes owned records only. An unowned Runtime lookalike still fails closed.

## Responsibilities and correlation

afterFileEdit keeps the existing normalized Core scan/attribution/policy/advisory route and `{}` output. It creates a presentation-only IN_FLIGHT marker after the existing workspace/session admission, before Core dispatch; completion publishes only existing SCANNED + scanner_run + OFFERED + NEW-family results. Neither the marker nor feedback changes security state. Errors in feedback publication cannot suppress or change Core processing.

postToolUse is a separate delivery route. It validates common claims, Write and an opaque tool_use_id, resolves the same canonical CURSOR_PROJECT_DIR/corroboration and verifies an existing signed session/generation binding without creating or advancing it. It does not normalize to WORKSPACE_ACTIVITY, instantiate a coordinator, dispatch Core, scan, create grants, tickets, confirmations or envelopes, or authorize edits. tool_use_id is only a local correlation hint; supports_invocation_id remains false. Missing/mismatched bindings produce `{}`. No transcript/tool result/command interpretation restores missing claims.

Correlation includes canonical workspace hash, session hash, generation hash, latest mutation-window opaque ID, existing family identity, existing NEW scan identity and advisory offer version. Advisory-only P0-9.6 intentionally creates no security Episode. Here `episode` is a presentation recurrence key derived from existing NEW scan/family identity, not a new Finding/security Episode or authority. PERSISTING never creates a new offer; a later scanner NEW recurrence can notify again. Delivery is an atomic at-most-once output attempt, not an acknowledgment that the Desktop UI displayed it.

Before delivery, current workspace scan/family membership and a bounded HMAC of the affected file bytes must still agree. Changed/missing files, resolved/stale families, another latest edit/session/generation and expired windows suppress delivery. Binding hashes and file hashes grant no remediation authority.

## Persistence, race and limits

Outbox: `<Runtime state>/cursor-feedback/<canonical-workspace-hash>/feedback.json`, signed with the existing HookStateStore key/atomic-write infrastructure. It is readable across independent processes and restarts; it does not use process-local memory. Per workspace, retain at most 64 windows and 64 offers. Active presentation TTL is 180 seconds; expiration is checked on access/new windows, with no background worker. States are PENDING / CONTEXT_INJECTED / EXPIRED. Old records are evicted within the fixed bound.

afterFileEdit and postToolUse can overlap in separate command processes. Delivery checks a persisted latest IN_FLIGHT window and waits at most 30 seconds using a local monotonic deadline and 100 ms bounded polling. No OS lock spans the sleep or Scanner execution. No pending/no Finding returns `{}` immediately; timeout returns `{}`, FEEDBACK_WAIT_TIMEOUT, retains the pending window and never cancels the scan or consumes an offer. A later matching postToolUse can retry. A postToolUse arriving before any in-flight marker exists returns promptly; it cannot infer a future scan from command text.

## Controlled context and privacy

Fixed template `cursor-security-feedback-v1`; show at most 3 deterministic severity/file/family-ordered items and an additional_count. Each DTO contains a closed normalized title, severity enum, sanitized relative file identity, category enum and existing selected policy action. Other NEW members use REVIEW_REQUIRED rather than inventing policy decisions. Context explicitly says informational / no edit authorization / no automatic fix / explicit user intent required.

Never render or save arbitrary Finding title/description/evidence/raw_data, source lines/comments, tool_input/output, shell command, transcript, absolute project path, raw conversation/generation/tool-use IDs, secret values, credential or prompt. The outbox persists safe DTOs/hashes, not the full formatted context. Source is read transiently only for a bounded digest. The recent diagnostics retain only closed fields: pending/count/channel/status/waited/wait_ms/deduped/generation_match/workspace_match/session_match/template_version. Channel CURSOR_POST_TOOL_USE_ADDITIONAL_CONTEXT; delivery status NONE/PENDING/CONTEXT_INJECTED/WAIT_TIMEOUT/STALE/DEDUPED. Existing read-only hooks recent CLI is reused; no new CLI or MCP tool.

## Stop and frozen security behavior

Stop remains SESSION_FINALIZATION_ONLY, `{}`, no Scanner, no followup_message, no eventual repair. Scanner/rules/snapshot/first-scan attribution/Finding/Policy/remediation/opaque refs/receipt/Ticket/Exact Edit Envelope/Deep Verification/Codex MCP implementations remain byte-identical to the incoming snapshot. No build, model, network, permission/entitlement feature or scanner worker is added.

## Local evidence

Initial 22 targeted tests passed; final candidate has 23 new tests including Core-factory-error wait cleanup. 23 passed in 107.28s (0:01:47). Coverage: risk/safe/no-pending/admission/delivery-only capability/binding/dedupe/stale file/resolution/TTL/recurrence/timeout retry/reload/isolation/sensitive data/aggregation/retention/tamper/installer/legacy migration. Final focused: 222 passed in 336.63s (0:05:36). Final full: 1753 passed, 9 skipped, 6 subtests passed in 2326.90s (0:38:46). Skipped cases are listed separately in cursor-visible-feedback-regression.json; none are counted as passes.

`scripts/cursor_feedback_acceptance.py` uses real managed offline scanners and two independent native CLI command processes. Stdout is parsed as actual Cursor JSON, never substituted by an in-process return. Real TLS race passed: writer IN_FLIGHT observed before completion, postToolUse returned an additional_context object, 539 context bytes; waited 19321.468 ms, total delivery command 19857.498 ms. afterFileEdit retained `{}`; current + pre-edit attribution scans = 2. postToolUse added 0 scanner calls. No-pending 489.587 ms and safe-edit delivery 559.046 ms returned `{}`. Dedupe, resolution/recurrence and Stop also passed. These are local command wall times under concurrent regression load, not Desktop UI latency or a Scanner optimization claim. Native fixture initially had an incorrect first-scan assertion after a prior safe scan; fixed the fixture order. One intermediate race assertion failed without diagnostic detail; it is not counted as passed. Final source and installed-candidate runs are independently recorded.

Real Codex stdio MCP regression passed with two episodes: POLICY_AUTO → INLINE_PREPARED → exact envelope MATCHED → real original-rule scanner proof → SCANNER_VERIFIED_RESOLVED / CLOSED; original opaque values passed unchanged. Duration 74.75 seconds under concurrent load. No Desktop UI trial was performed.

wheel/sdist/package integrity/compliance passed; 91 Python source files compared byte for byte with wheel contents. Clean candidate venv install passed offline, using existing system-site dependencies (no dependency downloads); installed native commands also passed. This is an isolated candidate installation, not replacement of the active Runtime.

Evidence: cursor-visible-feedback-native-trial.json; cursor-visible-feedback-installed-native-trial.json; cursor-visible-feedback-codex-trial.json; cursor-visible-feedback-package.json; cursor-visible-feedback-clean-install.json; cursor-visible-feedback-regression.json; cursor-visible-feedback-workspace-audit.json.

## Next minimal Desktop trial (manual, Pending)

After separately installing/reviewing the candidate, inspect Global setup/status: original four commands plus owned postToolUse matcher ^Write$. Open a fresh Cursor chat in a disposable Git project with a committed safe TLS baseline. Ask the Agent to introduce only a TLS hostname-verification bypass and not run a security command. Expect the existing NEW/AUTO_FIX-policy/ADVISORY_ONLY/OFFERED path, then a visible final reply warning of the Runtime security issue and asking whether to review a fix; no automatic source repair.

Read `security-check hooks recent --path <fixture> --limit 16 --json`: afterFileEdit should show FIRST_SCAN_NEW_RISK_ATTRIBUTED, AUTO_FIX, ADVISORY_ONLY, OFFERED; postToolUse should show CURSOR_POST_TOOL_USE_ADDITIONAL_CONTEXT / CONTEXT_INJECTED / scanner_run=false. A repeated Write must not repeat the same presentation episode; a safe edit should be silent. Actual visible final-chat response remains PENDING_ACTUAL_CURSOR_UI until the user checks it.

The final error-path correction completes the presentation window even if Core construction fails, while retaining ERROR / HANDLER_EXCEPTION. It does not leave a delivery process waiting for a scanner that never started.

Modified product files: security_feedback.py (new), cursor_event_adapter.py, cursor_hook.py, cursor_integration.py, recent_hooks.py. Tests/fixture: test_security_feedback.py (23 cases), scripts/cursor_feedback_acceptance.py; MANIFEST.in. Five current handoff documents and sanitized acceptance/evidence files updated; generated egg-info SOURCES changed through packaging only.

No commit, push, active Runtime replacement, real .cursor/.codex modification, actual Desktop UI automation, or next stage. Prior uncommitted work and document history are retained.

Final offline skipped reasons:

- SKIPPED [1] tests\performance\test_managed_cache_lifetime.py:14: Explicit managed real Scanner benchmark environment required
- SKIPPED [1] tests\performance\test_managed_cache_lifetime.py:38: Explicit managed real Scanner benchmark environment required
- SKIPPED [1] tests\performance\test_managed_hot_path.py:10: Explicit managed real Scanner benchmark environment required
- SKIPPED [1] tests\test_e2e_real.py:58: real scanner binaries required
- SKIPPED [1] tests\test_e2e_real.py:80: real scanner binaries required
- SKIPPED [1] tests\test_e2e_real.py:120: real scanner binaries required
- SKIPPED [1] tests\test_e2e_real.py:154: real scanner binaries required
- SKIPPED [1] tests\test_e2e_real.py:68: real scanner binaries required
- SKIPPED [1] tests\test_e2e_real.py:38: real scanner binaries required
