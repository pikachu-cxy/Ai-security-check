# Core P0-7.3 — Codex Global Hook Host Claim Propagation

Scope: event claims, input generation, safe diagnostics and invocation binding only. Starting HEAD `ee1bfd9c12493683cc313cb3628753a51ae124ac`, branch `feature/runtime-mvp`. Existing dirty work preserved. No commit, push, real user CODEX_HOME access, active Runtime replacement, scanner/remediation/Ticket/Deep implementation changes.

## Evidence and limits of root-cause attribution

The reported Desktop result proves rejection before mutation classification/scanning, but does not identify a rejected field. The incoming Global router collapses unknown tool / non-object arguments / any JSON-schema error into `INVALID_HOST_CLAIMS`; its exception boundary collapses other unlisted reasons into `WORKSPACE_OR_REFERENCE_REJECTED`. The incoming project adapter validates only event/workspace/session/tool strings. Neither validator previously required turn_id or tool_use_id. Thus their absence alone cannot be asserted as the cause of the previously reported rejection.

Confirmed contract gap: the definition and MCP schema omitted turn/tool invocation fields, so no invocation-level binding existed. Reproducible rejection classes include wrong/missing basic claims, unsupported tool_name, stringified tool_input and unexpected fields. They now report exact fixed field names. No original Desktop payload was captured, no transcript was read, and the exact offending field in that historical invocation remains **UNDETERMINED_PENDING_ACTUAL_DESKTOP_DIAGNOSTICS**. Do not substitute a hypothesis for observed evidence.

## Official contract

Checked on 2026-10-06 against [OpenAI Codex Hooks](https://learn.chatgpt.com/docs/hooks), Common input fields / PostToolUse / Stop / MCP tool hooks. PostToolUse provides turn_id/tool_use_id and the common permission_mode. Whole-value `${field}` preserves native JSON type. apply_patch is the canonical name even when matching Edit/Write. Bash commands use tool_input.command. No transcript/tool_response/model output is forwarded or used to reconstruct claims. Main-branch schema may differ from release behavior; the release guide is the reference here.

## Claims and security binding

All values are untrusted host assertions. Identifiers prove consistency with this connection, **not authenticated provenance**. Runtime does not accept permission_mode as an edit/remediation grant. Existing signed policy, snapshots, opaque refs and receipts remain the authority.

| Claim | PostToolUse | Source / purpose |
| --- | --- | --- |
| event | required, exact PostToolUse | hook_event_name; select event contract |
| workspace_path | required absolute bounded string | cwd; existing root resolution, no-links, containment, config admission |
| session_id | required bounded string | session_id; session cannot switch root, including read-only Bash |
| turn_id | required bounded string | turn_id; records invocation's claimed turn, rejects same tool-use id in another turn |
| tool_use_id | required bounded string | tool_use_id; reject repeat invocation, including changed session/turn/tool/root |
| tool_name | required bounded allowlisted string | tool_name; Bash/apply_patch/Edit/Write classification |
| permission_mode | optional, validated official enum when present | permission_mode; descriptive only, never grants authority |
| tool_input | optional native object/null, malformed type rejected | tool_input; transient classification only; not persisted or echoed |

SessionStart requires event/workspace/session; permission_mode is optional and has no turn/tool fields. Stop requires event/workspace/session/native boolean stop_hook_active; turn_id and permission_mode are optional; no tool_name/tool_use_id. Stop retains its existing signed continuation guard; a turn claim creates no new authority.

Rejected/unbound Stop remains quiet in the Hook text channel (`{}`); structured claims diagnostics still reject and no continuation is granted. A draft wrapper briefly emitted warning text there; the Stop compatibility test exposed it and the final event-specific output restores existing behavior.

Both Global and project MCP PostToolUse now require turn/tool invocation claims. Older hand-authored PostToolUse inputs without them fail closed and must be regenerated. The command adapter and direct embedded coordinator API are retained; the MCP claim guard is supplied by the connected server, not inferred from absent metadata.

Replay bookkeeping is connection-local, hashes only, bounded at 4096 invocation ids and 64 sessions; no eviction that would re-admit old calls. Exhaustion rejects. Independent invocations in one turn are allowed. Restart clears live bookkeeping; this is not a claim of durable replay protection across restarts. Existing persisted signed scan/remediation authority is unchanged. Invocation ids are consumed atomically before classification/bootstrap, even when valid calls encounter INITIALIZING; the same invocation must not be manually retried to acquire authority. This creates no scanner proof. Another actual Host tool invocation supplies its own new id. Replayed mutation claims cannot start a new-session bootstrap scan.

## Pipeline and diagnostics

`PostToolUse → schema/claims → root/config/session/invocation binding → classification → bootstrap if needed → existing HookCoordinator`.

READ_ONLY still avoids scanner invocation. POSSIBLE_WORKSPACE_MUTATION / UNKNOWN still use existing snapshots and scanner path. Read-only calls now undergo workspace/session validation before returning. No rule, scanner, receipt, Family/Episode or remediation behavior is reimplemented.

Diagnostics: host_claim_status, missing_claims, invalid_claims, event_schema, workspace_claim_match, session_claim_match, turn_claim_present, tool_use_claim_present, fixed reason_code/scanner_skipped_reason. Unknown input keys are represented only as `unexpected_fields`; keys/values, command text, source, secrets, raw ids/tokens are not echoed. Unknown match state is null rather than invented. Global rejection systemMessage contains only fixed field names and fixed reason codes.

Generated complete configuration: [hooks.json](codex-host-claims-generated-hooks.json). Definition changes require one new review; repeated setup/repair preserves its exact definition and does not rewrite an already healthy configuration. Temporary-home tests cover migration of signed legacy managed Hook, user Hook/MCP/state/unknown settings preservation and owned-only uninstall.

## Validation

Final frozen focused suite: **419 passed in 849.26s** (runner 850.02s). No skips or failures. Final frozen full offline regression: **1445 passed, 9 skipped, 6 subtests passed in 2463.32s** (runner 2464.32s); zero failures. Skips are three explicitly enabled managed performance cases and six older real-scanner cases whose binary prerequisites were not configured in that runner. Skips are not PASS. The separate installed-candidate real stdio MCP/scanner trial passed in 125.06s.

Final regression, install, real local MCP/scanner and workspace-preservation evidence is recorded in `codex-host-claims-regression.json`, `codex-host-claims-installed-trial.json`, `codex-host-claims-mcp-trial.json`, `codex-host-claims-package.json` and `codex-host-claims-workspace-audit.json`. Desktop host invocation itself remains Pending; a simulated Host over real stdio MCP is not Desktop proof.

## Project C minimal Desktop check

1. After explicitly choosing to load this candidate Runtime, run `security-check repair` (or `security-check setup --scope global`). These are the Global commands; the legacy `integration repair codex` manages project scope. Do not manually remove user config. This development task did not install the candidate or execute these commands against your home.
2. Review the updated user Hook once, reconnect the MCP connection and open a fresh Project C chat. The managed PostToolUse input should have all eight fields shown in the generated document.
3. Run a read-only git status/read: expect claims VALID, workspace/session match true, READ_ONLY, scanner_run false.
4. In the disposable test file, change a timeout through Bash or apply_patch: expect claims VALID, snapshot reconciliation and scanner for observed source changes.
5. Add the isolated TLS trust-all test risk: expect Finding/policy and the existing inline remediation flow. Remove only the authorized risk; require actual scanner resolved proof and return to Host. Do not request Functional Verification.
6. If rejected, report only the safe diagnostics listed above. Do not supply transcript, raw tool input, command content or identifiers. This will establish the exact field for the reported Desktop failure without bypassing validation.

Functional/build/test/sandbox remain outside default Core Hook. Ground Truth and independent human trials retain their prior pending status. No P0-8 work started.
