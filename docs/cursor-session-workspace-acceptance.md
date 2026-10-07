# P0-9.2 Cursor SessionStart / workspace resolution

Official [Cursor Hooks contract](https://cursor.com/docs/hooks) checked 2026-10-07 (Asia/Shanghai): conversation_id is stable across turns; generation_id changes for each user message; sessionStart fires when a composer conversation is created and session_id equals conversation_id. User-provided actual Desktop evidence confirms generation_id is empty at sessionStart, then valid at afterFileEdit. Hook delivery is already VERIFIED; no launcher investigation or new Desktop E2E in this iteration.

## Confirmed SessionStart defect and event-specific correction

The previous common validator required nonempty generation_id for every selected event. It rejected the real sessionStart before workspace binding/baseline. sessionStart now requires valid conversation_id/session_id equality and one workspace root; generation may be absent or exactly empty and is marked NOT_YET_AVAILABLE. Whitespace-only, wrong type, oversized (including oversized whitespace), C0 control and surrogate values still reject. afterFileEdit, afterShellExecution and stop still require a valid nonempty bounded opaque generation string. No fake generation or invocation ID is produced.

CursorBindings preserves the signed conversation/root namespace and budgets, adding a bounded signed generations map of hashes keyed by session hash. First activity OBSERVED; same generation UNCHANGED; next user message UPDATED. Missing generation at a repeated sessionStart RETAINED when a previous observation exists; no previous generation is substituted into the raw event. This is a turn-scoped observation, not an invocation identity, replay authentication, authorization or proof. Cross-workspace reuse of a conversation still rejects before writing the generation. Legacy three-key bindings are accepted/migrated by the new reader; older readers fail closed on the extended state, so do not share candidate state with an older installed Runtime. The active Runtime/state is untouched by this acceptance.

## Workspace evidence and precise resolver boundary

The retained actual Desktop rows prove failure while cursor_workspace_resolution_stage=WORKSPACE_ROOTS, before any canonical identity was available. With the old shared resolver, WORKSPACE_CANONICALIZATION_MISMATCH projected INVALID_WORKSPACE_CLAIM or WORKSPACE_DIRECTORY_REQUIRED. This places the failure in raw path admission/directory handling, not generation or CURSOR_PROJECT_DIR comparison. The old rows do not contain the path shape; exact raw predicate remains UNDETERMINED_FROM_RETAINED_DIAGNOSTICS. Do not claim URI, case or Git ownership caused that historical rejection.

Project F was probed read-only using its user-supplied ordinary Windows absolute path, forward slashes, uppercase, trailing separator and src subdirectory. All five have WINDOWS_NATIVE shape, exist, Git probe OK and the same canonical root identity. No project source was read/edited, no Hook dispatched, no scan run and no safe.directory/config writes. This evidence is about the supplied known path, not a reconstruction of Cursor's historical raw root or environment. See [read-only evidence](cursor-session-workspace-readonly-evidence.json).

New Cursor ingress preflight diagnoses PATH_SHAPE → FILESYSTEM → BOUNDARY → GIT_PROBE → CANONICAL_RESOLVER → COMPLETE before calling the unchanged shared resolver. The original Git helper supplies command-local safe.directory; Cursor now first checks Git without that ownership override. Dubious ownership, timeout, missing Git, malformed output or other probe failure cannot silently fall back into non-Git discovery. No global/system Git trust is changed. Genuine NOT_REPOSITORY retains existing bounded non-Git source layout support; an unrecognized directory rejects ROOT_NOT_REPOSITORY. Git's returned root must agree with the shared canonical resolver.

One workspace_roots[0] remains primary. Optional API project_dir / actual CURSOR_PROJECT_DIR is independently canonicalized and must corroborate the same root. There is no process cwd fallback or raw string equality. Windows native/slash/case/trailing/subdirectory variants retain canonical equivalence. File URI is explicitly unsupported with URI_STYLE_PATH, never percent-decoded or guessed. Protected roots, UNC, parent traversal, link/junction, source conflict, nested repositories, outside file and cross-workspace conversation reuse stay fail closed. File containment and filesystem digest reconciliation still use existing Core.

## Safe persistent diagnostics

Existing recent SQLite journal/retention remain unchanged (32/workspace, 1024 total). Added per workspace_root / cursor_project_dir: is_absolute, exists, path_style (WINDOWS_NATIVE/POSIX/FILE_URI/UNKNOWN), drive_present, canonicalized, git_probe_status, git_repo_detected, resolution_step, resolution_reason. Generation state and binding observation enums are also retained. Closed reason codes distinguish RAW_PATH_NOT_ABSOLUTE, PATH_NOT_FOUND, PATH_NOT_DIRECTORY, WINDOWS_PATH_NORMALIZATION, URI_STYLE_PATH, GIT_ROOT_LOOKUP_FAILED, GIT_DUBIOUS_OWNERSHIP, ROOT_NOT_REPOSITORY, LINK_OR_JUNCTION_REJECTED and REGISTERED_WORKSPACE_MISMATCH. Existing source/nested mismatch codes remain compatible with a CURSOR_PROJECT_DIR_MISMATCH / NESTED_REPO_CONFLICT detail.

No raw paths, IDs, generation, command, tool_input, output, transcript, source, Git stderr or Secret is recorded. Only booleans/enums/bounded lengths/hashes persist. The query is diagnostic-only, not a security proof or authority. Failures before a canonical root remain in the unbound diagnostic partition.

## Verification and scope

New tests: 37 cases. Initial targeted run: 2 failed / 122 passed due solely to a new test accessing HookStateStore.base; changed its assertion to CursorBindings.base. Final targeted PASS: 124 passed / 72.45s. Focused PASS: 265 passed / 276.26s. Full offline PASS: 1647 passed / 9 skipped / 6 subtests passed / 2079.44s runner duration. The nine skips are individually recorded: three require an explicit performance environment and six require real Scanner binaries. Installed native command + actual managed offline Scanner PASS / 46.99s, including empty generation sessionStart from temporary user Hook cwd and cross-process diagnostics. Codex MCP recurrence regression PASS / 40.18s. [Final results and skips](cursor-session-workspace-regression.json). These are local simulated Hosts, not Desktop trials. Candidate wheel/sdist integrity and licenses/notices compliance PASS / 5.09s, 88 module source bytes checked.

Core, Scanner, Finding/Policy, Family/Episode, remediation, Ticket/Envelope, Codex adapter, shared canonical resolver/Git helper, rules, Deep and installer are byte-unchanged against the incoming snapshot. No commit/push or active Runtime replacement, no real .cursor/.codex writes, no Desktop trial. Earlier uncommitted work and document history remain preserved. Continuation capability is still PENDING_CURSOR_CONTINUATION_CAPABILITY.

## One next Desktop test (user-run)

After the user chooses to load the candidate, open a fresh Cursor chat in Project F, wait for sessionStart, then request one ordinary timeout-only edit without manually scanning. Use the same selected installation and state namespace to query:

```powershell
security-check hooks recent --path "C:\Users\Administrator\Desktop\ai-security\runtime-cursor-e2e-f" --limit 8 --json
```

Expected sessionStart: VALID, generation NOT_YET_AVAILABLE, CORROBORATED, session/workspace match. Expected afterFileEdit: generation AVAILABLE/OBSERVED, containment true, DIRECT_FILE_MUTATION, trusted baseline, real digest delta and scanner_run=true. If no workspace row exists, query `security-check hooks recent --unbound --limit 8 --json`; it reports the actual safe path shape/step/reason without exposing raw claims. No real Desktop claim compatibility PASS until this user retest.
