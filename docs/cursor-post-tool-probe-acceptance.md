# P0-10.1a Cursor postToolUse Desktop Capability Probe

Acceptance: LOCAL READY FOR DESKTOP PROBE. Actual Cursor Desktop 3.22.12 dispatch and its actual file-write tool name are UNKNOWN / PENDING. Local command fixtures are not Desktop evidence.

The user reports that the existing real afterFileEdit -> Scanner -> first-scan NEW attribution -> Finding -> AUTO_FIX policy -> ADVISORY_ONLY -> OFFERED chain works and that feedback is PENDING. That chain is retained. This candidate only observes whether postToolUse arrives.

## Temporary candidate

Checked https://cursor.com/docs/hooks on 2026-10-07: a successful tool call can produce postToolUse; matcher "*" matches everything. Documented tool types include Write, Read, Shell, Grep, Delete, Task and MCP:<tool_name>.

matcher="*" is a temporary Desktop capability probe.

Global setup/repair generates an owned postToolUse command using the existing launcher with --post-tool-use-probe, matcher "*", type command and timeout 120. The other four owned definitions are unchanged. Signed P0-10.1 ownership records migrate; user-owned hooks/unknown fields/MCP remain intact. Repeated setup/repair is idempotent; remove only removes owned entries. No real host configuration was modified.

Without this explicit command flag, the existing P0-10.1 delivery route remains available and unchanged. This temporary candidate installs the flag only on its owned postToolUse record. Do not treat it as a production matcher decision.

## Ingress and diagnostics

Bounded stdin JSON parsing -> probe-specific postToolUse schema -> existing canonical workspace resolver -> existing signed session/generation binding verification -> safe recent diagnostics -> stdout {}. It does not advance/create a binding, normalize Core activity, construct Coordinator, call Scanner/Policy/remediation, open/wait/consume outbox or render additional_context. Wrong event on the probe-only command is rejected before Core dispatch. Claims/workspace failures remain observable and fail closed.

conversation_id, generation_id and workspace claims remain required and validated. Probe accepts bounded opaque tool_name independently of the production Write filter. tool_use_id is optional observation metadata; malformed values, if supplied, are rejected. It grants no authority; supports_invocation_id remains false and invocation_identity_status remains UNAVAILABLE_CONTENT_RECONCILIATION_ONLY.

Recent fields: event=postToolUse; event_schema=cursor-postToolUse-v1; post_tool_use_probe; post_tool_use_observed; post_tool_use_tool_class; post_tool_use_tool_name_normalized; post_tool_use_tool_name_known; post_tool_use_tool_name_hash; post_tool_use_matcher_mode=MATCH_ALL_PROBE; tool_use_id_present; scanner_run=false; scanner_invocation_count=0. Existing claims and workspace diagnostics remain.

Only controlled Write/Read/Shell/Grep/Delete/Task/MCP/UNKNOWN names are exported. Unknown names are hashed; MCP suffixes are not persisted. Never store raw arbitrary tool_name, tool_input, tool_output, command, transcript, source, secret, conversation/generation/tool-use IDs. Existing bounded persistent recent infrastructure enables an independent CLI process to read observations. Observation is not a security proof or UI acknowledgment.

## Checks

Targeted: 17 passed in 28.51 seconds. Focused: 178 passed in 363.16 seconds, including Codex MCP Hook and Core hot-path regressions. Final full offline regression: 1770 passed, 9 skipped, 6 subtests passed in 2469.72s (0:41:09). Skipped prerequisites remain separately listed in `cursor-post-tool-probe-regression.json`; no actual Desktop verdict is inferred. Native source fixture passed for WRITE/SHELL/UNKNOWN: actual independent cursor-hook command stdout {}, independent hooks recent query, zero Scanner invocations, outbox bytes unchanged. Unit test uses an existing OFFERED/PENDING feedback to assert byte preservation; native fixture also verifies an existing IN_FLIGHT outbox remains unchanged and is not waited on. Core/outbox/remediation access is forbidden by test sentinels. No scans.db is created by native probe calls.

Early local iterations failed due to fixture wiring/record shape, a duplicated diagnostic keyword, and resolver validation not receiving the explicit probe mode. These were corrected without changing production admission. The native fixture additionally needed canonicalization before manually seeding its temporary Windows binding; Runtime validation was retained.

Wheel/sdist, package integrity and compliance: PASS; 92 Python source files checked against the wheel. Offline isolated-venv installation: PASS using existing system dependencies (no dependency downloads). Installed-package native command fixture: PASS in 2.54 seconds; it clears PYTHONPATH and asserts imports come from the installed package, not the source checkout. Scanner/attribution/Finding/Policy/remediation/outbox/formatter/Codex implementations are frozen and audited against the incoming worktree snapshot. Stop semantics remain unchanged: SESSION_FINALIZATION_ONLY, scanner_run=false, {}, no followup_message.

## Files changed in this stage

Runtime: `src/security_runtime/cli.py`, `cursor_event_adapter.py`, `cursor_hook.py`, `cursor_integration.py`, `recent_hooks.py`, and new `cursor_probe.py`. Tests: new `tests/test_cursor_post_tool_probe.py`; existing `tests/test_security_feedback.py` changes only its installer matcher/command assertions. Packaging: `MANIFEST.in` and generated egg-info `SOURCES.txt`. Native acceptance: new `scripts/cursor_probe_acceptance.py`. Evidence: this acceptance document and the `docs/cursor-post-tool-probe-*.json` reports. Disposable local orchestration helpers remain under ignored `.security-runtime`.

Incoming-worktree audit: 549 files preserved; 541 byte-identical, 8 permitted integration/diagnostic/test/packaging files changed, no deletion. Cursor binding methods and Core factory AST unchanged. HEAD remains `ee1bfd9c12493683cc313cb3628753a51ae124ac`.

## One future Desktop operation

After separately installing the candidate and running security-check integration repair cursor --scope global, confirm the owned postToolUse matcher is "*" and command contains --post-tool-use-probe. In a fresh Cursor Chat in the existing safe test project, request one harmless file modification (for example only changing a timeout from 2400 to 2500), without requesting a security scan. Do not introduce another TLS risk.

Then run security-check hooks recent --path "<test-project>" --limit 16 --json. A postToolUse record with observed=true and WRITE proves dispatch for this operation. A different normalized type informs the next matcher decision. Only afterFileEdit with no postToolUse is an absent observation for the tested Desktop version/path; first confirm candidate installation/loading and successful native command diagnostics before attributing it to Host capability. Missing records alone are not proof that no process was dispatched, because failures before Runtime ingress are not observable here. Stop designing guaranteed feedback on this surface if the verified host path does not deliver it.

No commit/push/active Runtime replacement/real .cursor or .codex change/actual Desktop probe/Rule Program/new phase.
