# Core P0-7.3.1 — Recent Hook Diagnostic

Scope: observability only. `feature/runtime-mvp`, starting HEAD `ee1bfd9c12493683cc313cb3628753a51ae124ac`. Previous dirty work preserved. No commit/push, real user CODEX_HOME access/rewrite, active Runtime replacement, new scanner/rules, remediation/Ticket/envelope/baseline/bootstrap/Deep/CET changes.

## Previous lifecycle and the Desktop blind spot

| Fields | Before this patch |
| --- | --- |
| host_claim_status, missing_claims, invalid_claims, event_schema, workspace_claim_match, session_claim_match, turn_claim_present, tool_use_claim_present | Built in the MCP transport/Global router and returned synchronously. The live guard retains identifier hashes, not a queryable history of diagnostics. Early Global rejection does not enter a workspace coordinator. No per-event DB/receipt/log record. |
| tool_name | Host input and transient classification/guard input; normally omitted from the summary projection. |
| tool_classification, workspace_mutation_observed, scanner_trigger_reason, scanner_skipped_reason | Added by the transport after coordinator work, or by its early return. Synchronous result only; not in HookSnapshot.last_result. |
| changed_file_count | Bounded coordinator snapshot count, returned synchronously. Hook state has changed_files for convergence, not this per-event diagnostic/history. |
| scanner_run | Live execution ledger and synchronous result. Scan DB/receipts contain their existing scanner/proof facts, and Hook state has scanner_runs/execution_state, but none is a complete PostToolUse arrival/claims/classification record. |

`hooks status` queries integration configuration; `summary` queries scan/Finding history. Neither is a recent Hook ingress reader. Successful scans may leave state, but rejected or skipped calls can leave none of that state. The compact ticket text channel also omits much of the full synchronous structured result. No transcript or Host stdout reconstruction is used.

## Persistence, isolation and safety

Dedicated `hook-diagnostics.db`, table `recent_hook_diagnostics`, under `SQLiteStore.default_path().parent`. Windows default: `%LOCALAPPDATA%\AI Security Runtime\hook-diagnostics.db`; `SECURITY_RUNTIME_STATE_DIR` selects the existing Runtime state namespace. The MCP and CLI processes must use the same OS user/state namespace.

This reuses local SQLite and the existing read-only SQLite infrastructure. It does not instantiate/migrate a scan store from the reader. It contains no proof, Finding, policy, authorization, Ticket or baseline. No production code reads diagnostic values to decide security behavior.

Retention: 32 calls per canonical workspace hash; 1024 calls across the database including the explicitly unbound partition. Old rows are overwritten/evicted, with SQLite secure deletion and reusable pages. Late completion of an evicted in-flight call cannot resurrect it. Each call retains at most 32 phase markers. No TTL or cross-restart clock continuity is claimed.

At transport ingress, before SDK/Global claim validation, commit HOOK_RECEIVED. Then attempt diagnostic-only canonical root attribution; failure remains unbound. That lookup does not admit a workspace, initialize baseline, start a scanner or grant authority. A malformed request with a valid cwd remains queryable under its canonical root. Missing/unsafe cwd requires explicit `--unbound`, never guessed from the last workspace or a session/ref.

Global→project nested calls share one ContextVar observation; the SDK request wrapper observes project calls before the existing SDK validator, which remains in place. Existing schema/claims/guard/ownership/config checks are not replaced or relaxed.

Persist only timestamp, process-local monotonic scope and elapsed markers, random opaque diagnostic id, workspace/session hashes, expected event/schema, fixed claim field names, boolean/null matches and presence, allowlisted tool/classification, mutation boolean/null, bounded file count, fixed scanner/handler status/reason codes, scanner_run and completion flag. Unknown codes become OTHER/UNKNOWN rather than arbitrary strings. The reader also filters/validates the stored projection, and rejects corruption without echoing content.

Never persist raw tool_input, command, transcript, tool_response, source/snippets, Secret, token, receipt/opaque task/ref/grant values, raw session/turn/tool-use ids or target file paths. Claim field *names*, including `tool_input` in invalid_claims, are diagnostic metadata; their values are never stored.

## Stages and interpretation

Supported: HOOK_RECEIVED, CLAIMS_VALID, CLAIMS_REJECTED, READ_ONLY_SKIPPED, RECONCILIATION_STARTED, RECONCILIATION_COMPLETED, MUTATION_NOT_OBSERVED, SCANNER_TRIGGERED, SCANNER_COMPLETED, HANDLER_ERROR, HANDLER_COMPLETED.

SCANNER_TRIGGERED is a real coordinator scan-orchestration entry, not proof an engine was launched. scanner_run comes from the existing live scanner execution ledger. SCANNER_COMPLETED means that scanner call returned, not that coverage is FULL or the project is safe. An exception preserves observed invocation and does not synthesize completion. Errors swallowed by the existing transport are recorded without changing its returned safety status. The final handler status/reason remains the existing protocol result.

The observed mutation comparison uses the same existing resolved/seeded previous snapshot. It can be null when no comparison exists. It is diagnostic only; it does not change the legacy transport mutation flag, Core risk attribution or Family/Episode proof. changed_file_count is the existing bounded snapshot count, not an exact patch reconstruction.

Rows are committed at ingress and each observed boundary, so another process can read an unfinished call. Abrupt termination can leave completed=false and the last observed stage; do not invent a terminal outcome. Records survive MCP restart; monotonic_scope changes on a fresh process, and elapsed markers must not be subtracted across scopes.

The journal is advisory. One failed/busy write disables further writes for that call, avoiding repeated SQLite lock waits; SQLite timeout is 50 ms. Core executes once with its original checks. Structured MCP output adds recent_hook_diagnostic_id and RECORDED / WRITE_UNAVAILABLE / RETENTION_EXPIRED. Missing records cannot prove non-delivery if storage was unavailable, retention evicted the record, a different state namespace was queried, or the new candidate was not loaded. No backfill for old Desktop edits exists. This records Runtime MCP ingress, not authenticated Host provenance.

## Read-only CLI

```powershell
security-check hooks recent --json
security-check hooks recent --path C:\path\to\ProjectC --limit 32 --json
security-check hooks recent --path C:\path\to\ProjectC --limit 10
security-check hooks recent --unbound --limit 32 --json
```

Default cwd is resolved to its canonical workspace. Limit 1–32; default 16. --unbound explicitly selects unattributed calls and cannot be combined with --path. No records returns NO_RECORDS; an unreadable/corrupt/unsafe store or invalid query returns fixed UNAVAILABLE, exit 2. The CLI uses mode=ro and query_only, never creates directories/schema/keys, launches a scanner, acquires authorization, updates baseline, creates Episode/Finding or fixes source. Human output shows timestamp/event/last stage/claims/scanner/id; JSON carries the closed record.

## Validation and Desktop gate

25 diagnostic cases cover valid/rejected claims, initialized/initializing classification, event-specific lifecycle contracts, readonly and mutation, no-change snapshot, suppressed/escaping/scanner exceptions, sensitive content absence in DB/output, workspace isolation and subdirectory attribution, explicit unbound, bounded global/per-workspace retention and late eviction, in-flight entry/schema visibility, write/observer failure, corrupt DB, read-only query byte preservation, real stdio MCP process→independent CLI and fresh process restart. Final boundary suite 25 passed / 52.06s; final frozen focused 190 passed / 293.43s (runner 294.67s). Final frozen full offline: 1470 passed / 9 skipped / 6 subtests passed in 2722.77s (runner 2723.91s), zero failures. Three skipped cases require an explicit managed real Scanner benchmark environment; six require real scanner binaries. Skips are not PASS. [Exact counts and skip reasons](recent-hook-regression.json). Earlier full runs stopped to complete ingress schema/classification/lifecycle observations are not PASS.

Final candidate wheel/sdist integrity/compliance PASS in 8.67s; all 80 Runtime Python files byte-matched. [Package evidence](recent-hook-package.json). Temporary no-index/no-deps venv install uses existing third-party dependencies and verifies candidate module origin in that venv (not an empty third-party environment). Installed Global stdio MCP wrote rejected/readonly observations, then independent installed CLI read them after server exit with DB bytes unchanged. Fresh setup/repeated setup/repair/status/doctor/uninstall and original config bytes/state preservation PASS; Codex CLI 0.160.0 parsed the temporary configuration. 51.31s. [Install and cross-process evidence](recent-hook-installed-trial.json). No active package replacement or real user config access.

[Workspace audit](recent-hook-workspace-audit.json) preserved all 424 incoming files; 19 protected product modules remain byte-identical. Removing observer statements/imports from hook_runtime, codex_mcp_hook and mcp_server yields the identical incoming AST; GlobalWorkspaces root/admission/bootstrap class AST is unchanged. Frozen code does not drift. This supplements behavioral tests; no authority is assigned to the diagnostic rows.

Actual Desktop E2E remains user scheduled. The incoming user reports a restarted Desktop with actual edits after installing P0-7.3; those edits have no retrospective recent records. Once the user chooses to load this candidate and reconnect MCP:

1. Query recent before editing to establish the latest diagnostic id/time.
2. Fresh Project C chat: read/git status; query with an independent PowerShell. Expect PostToolUse, HOOK_RECEIVED→CLAIMS_VALID→READ_ONLY_SKIPPED, scanner_run=false.
3. Change timeout through normal Bash/apply_patch without requesting a scan; query again. Expect a new row and the actual reconciliation/scanner or explicit skipped/error boundary.
4. If rejected, read missing_claims/invalid_claims/match flags. If the workspace query is empty, inspect --unbound explicitly. If both are empty, check candidate loading, same user/state namespace and MCP connectivity/write availability; do not infer success or weaken claims.

The Hook definition/matcher/input, user Hook state and trust definition are unchanged by this patch. No repair or trust reset is prescribed merely for the new diagnostic feature. No Desktop PASS is inferred from the simulated Host/real SDK tests. Other stages remain Planned.
