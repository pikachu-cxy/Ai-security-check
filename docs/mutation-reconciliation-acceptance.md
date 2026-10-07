# Core P0-7.3.3 — Mutation reconciliation

## Actual Project C evidence (read only, UTC)

The persisted session baseline was written at 2026-10-06 10:27:13, after SessionStart at 10:27:06. It remains PRE_EXISTING_BASELINE / SCANNED. Target file mtime is 09:21:52. Current target contains 2400, not 2300. The stored digest matches the current filesystem and the in-memory 2400 variant; it does **not** match the 2300 variant. No source is changed to conduct this comparison. State bytes remain unchanged.

The 10:30:00 PostToolUse record is VALID / SAME_ROOT and NO_CHANGE. It compared a baseline already containing 2400 with current 2400. Available evidence does not prove a real 2300→2400 filesystem byte change after that baseline. Do not label this historical record a demonstrated digest miss. The observed file timestamp predates the successful SessionStart. File mtime alone is not the proof: independent digest equality and differing test variants corroborate the comparison.

Old changed_file_count=1 meant a Git dirty/untracked inventory entry (the Java file remains untracked). It was not a delta from the last processed snapshot. Mutation was independently determined by aggregate HMAC digest comparison. The transport also unconditionally reported mutation=true even for NO_CHANGE; recent diagnostics correctly preferred the coordinator's measured false. This contradictory presentation is corrected.

Evidence: [safe read-only observations](mutation-reconciliation-readonly-evidence.json). No raw session/turn/tool IDs, reference, source, command or secret are saved there.

## Lifecycle and changes

SessionStart captures a bounded baseline under the existing workspace lock, verifies bytes again after the existing baseline scanner, then publishes the comparison point. For a previously established matching workspace/host/session, duplicate SessionStart and reconnect preserve its saved comparison point instead of replacing it with current post-edit bytes.

PostToolUse loads that point **before** current capture. It compares actual filesystem HMAC digests, retaining the original aggregate Git HEAD/index/content comparison and family logic. New optional file_digests cover the bounded Git tracked plus dirty/untracked inventory (maximum 1000 files / 20 MB, each file at most 1 MB), permitting an exact count of raw byte/inventory deltas. This complementary comparison catches byte-only changes Git autocrlf may hide, without changing Git configuration or interpreting every clean tracked file as dirty. Raw BOM/CRLF bytes are hashed without normalization. Unchanged tracked files are not added to scanner input; actual complementary byte deltas are added to the existing dirty/retained scope. Scanner implementation and proof policy are unchanged.

Same bytes or changes restored before observation return NO_CHANGE with changed_file_count=0, even if snapshot_file_count remains 1. Classification/host tool_input is never evidence of mutation. READ_ONLY keeps its existing no-scanner route.

Missing SessionStart / missing valid saved pre-edit snapshot: Global lazy bootstrap remains bounded and advisory. A comparison point created after the tool ran cannot prove NO_CHANGE or authorize edit attribution. If bootstrap is ready within the request, return INCONCLUSIVE / WORKSPACE_BASELINE_ATTRIBUTION_UNAVAILABLE; if still pending, keep WORKSPACE_INITIALIZING. Diagnostics say LAZY_BOOTSTRAP / NO_TRUSTED_PRE_EDIT_SNAPSHOT, with nullable delta/match. Future edits can use the newly established comparison point. No fabricated pre-edit bytes or security proof.

The existing after-scan check now checks both the aggregate and complementary raw byte inventory before publishing, rejecting moving source including Git-hidden CRLF changes. Snapshot publication, family multiset, coverage gating, single-flight/cooldown and Scanner execution remain in their existing implementation. No Host Claims, matcher, workspace resolver/binding, Finding, remediation, Ticket, exact edit envelope, rules or Deep Verification changes.

## Safe diagnostics / compatibility

MCP and cross-process recent CLI expose snapshot_available, snapshot_source, snapshot_generation (opaque hash of the aggregate comparison digest and complementary file inventory), pre_snapshot_match, content_delta_detected, reconciliation_reason, snapshot_file_count and actual changed_file_count. Values are closed enums, bool/null, counts or hash; no source, full path, command, raw identity, receipt or token is included. Existing retention and read-only CLI are unchanged.

Old hook-v1 snapshots remain readable. If they lack file_digests, equality proves zero delta only within the old bounded Git dirty capture; differing aggregate digest triggers the existing scanner path but per-file content count stays unknown/null until next stable capture. No historical clean-file bytes are invented. New map keys are bounded safe relative paths, must contain the dirty inventory, and values must be 64 hexadecimal characters. These hashes are comparison metadata, not new scanner proof or authorization. Complementary inventory reading adds bounded filesystem work, not scanner invocations or source persistence.

Changed implementation: hook_runtime.py, baseline_seed.py, codex_mcp_hook.py, global_mcp.py (pre-bootstrap snapshot check only), recent_hooks.py; new test_mutation_reconciliation.py; MANIFEST test include. Incoming unrelated dirty work is preserved.

## Acceptance

All 25 new cases are included in the final 281-passed focused run. Includes real filesystem writes, each of Bash/apply_patch/Edit/Write through local Global MCP, same-content/reverted-content skips, multi-file delta counts, BOM/CRLF and Windows aliases, autocrlf, reload/reconnect preservation, first lazy-bootstrap attribution, legacy state compatibility, malformed digest rejection, moving-source publication rejection and diagnostic privacy. Scanner invocation uses the existing deterministic execution fixture; these are not new real Desktop scanner performance claims.

最终 focused：281 passed in 293.87s (0:04:53)；full offline：1523 passed, 9 skipped, 6 subtests passed in 1838.52s (0:30:38)，零失败，skipped 单列不计 PASS。wheel/sdist integrity/compliance PASS / 4.58s。 Final logs and skipped reasons are recorded in mutation-reconciliation-regression.json. Initial test helper incorrectly read a nonexistent nested structured key; corrected the tests to use the actual flattened adapter response. An initial autocrlf fixture had committed CRLF bytes rather than a normalized LF blob; corrected only the fixture. A broader regression caught an overly broad intermediate approach: disabling autocrlf for Git diff made clean tracked CRLF files appear dirty. That approach was removed and replaced by complementary bounded byte comparison, preserving the old dirty scope. The preliminary full run was explicitly stopped (exit 130) when this correction invalidated its frozen source; it is not a PASS. Failed preliminary runs are retained and are not PASS evidence.

No commit, push, activity replacement, actual Project C edit/scan, or real user .codex write. Actual fresh Desktop trial remains pending user execution; P0-8 is not started.

## One Desktop trial after candidate is loaded

In a fresh Project C chat after the candidate Runtime is loaded, wait for the normal SessionStart baseline to finish, then ask the host to change the **currently present** timeout from 2400 to 2500 (verify the old value and exactly one replacement). Do not replace 2300 again, and do not request an independent scan. Read:

```powershell
security-check hooks recent --path "C:\Users\Administrator\Desktop\ai-security\runtime-global-e2e-c" --limit 5 --json
```

The mutation event should show VALID claims, snapshot_available=true, pre_snapshot_match=false, content_delta_detected=true, changed_file_count=1, workspace_mutation_observed=true, scanner stage and actual scanner_run=true. Baseline readiness/delivery remains a prerequisite; absence of a trusted point must be explicitly unattributed, not NO_CHANGE.
