# P0-9.1 Cursor Desktop schema and workspace compatibility

Official contract rechecked 2026-10-06: [Cursor Hooks](https://cursor.com/docs/hooks). User command Hooks run from the user config directory; `CURSOR_PROJECT_DIR` is documented as present. Common identities are strings, not UUIDs or hex. Hook delivery for the four selected events is user-reported Desktop VERIFIED; this iteration does not retest launcher delivery or run a new Desktop trial.

## Evidence and root-cause boundary

The previous native Cursor validator had no UUID/hex regex. Its identity check required a non-whitespace string, maximum 500 characters, no C0 control/surrogate, and no `${` substring. The latter was a Codex-template assumption inappropriate for opaque native stdin strings. It is removed; the bounds now measure the original string rather than its stripped length. Empty, non-string, oversized, control and invalid Unicode values still fail closed. A null workspace_roots also previously passed the first shape guard accidentally; it now rejects at claims validation.

Historical Desktop recent rows prove invalid generation/sessionStart and workspace rejections, but do not contain generation type/length or the two workspace source identities. They cannot establish which individual generation predicate failed. Do not claim that a UUID constraint caused the real failure. Project F root, src and Java subdirectory were inspected read-only with the current canonical resolver and resolve to the same identity. No source was read or edited in that project. Exact historical Desktop generation/source cause remains UNDETERMINED_FROM_RETAINED_DIAGNOSTICS; raw payloads/transcripts are neither collected nor reconstructed.

The previous workspace source was event workspace_roots[0], corroborated with CURSOR_PROJECT_DIR when provided. It did not call Path.cwd(). The generic CANONICALIZATION_MISMATCH conflated malformed root/directory, event/env source disagreement, and nested file workspace disagreement. New diagnostics separate these cases without accepting a mismatched root or guessing a workspace from cwd.

## Source and binding contract

One event workspace_roots string is primary. It passes bounded type/shape checks, then the unchanged canonical workspace resolver, Git-root discovery, protected-root and link policy. CURSOR_PROJECT_DIR, when supplied, must resolve to the same canonical root; a disagreement returns CURSOR_WORKSPACE_SOURCE_MISMATCH. No process cwd fallback exists. Zero/multiple event roots remain unsupported, even when environment provides a root; no arbitrary selection or silent override is allowed.

afterFileEdit requires an absolute existing non-link file canonically contained in the admitted root. Outside files reject. Its parent resolves through the same resolver; a distinct nested repository returns CURSOR_FILE_WORKSPACE_MISMATCH. The event/env comparison and file/root comparison are separate. Existing persistent conversation/root binding, cooldown, single-flight and actual filesystem reconciliation are unchanged. Generation is validated as an opaque Host claim; it is not fabricated into an invocation identity or new authorization token.

An independently resolved event root can partition a rejected diagnostic row before env/file validation; this is diagnostic attribution only, never registration, snapshot, scanner or authority. A rejected request still cannot establish a session binding or enter Core.

## Safe diagnostics

Added: generation_id_present/type_valid/shape_valid, clipped generation_id_length (maximum 501), generation_id_validation_reason (MISSING/INVALID_TYPE/EMPTY/OVERSIZED/CONTROL_CHARACTER/INVALID_UNICODE/VALID); workspace_root_count and workspace_roots_validation_reason; cursor_project_dir_present; cursor_workspace_source (WORKSPACE_ROOTS/CORROBORATED); workspace_sources_match; canonical workspace hashes; cursor_workspace_resolution_stage (WORKSPACE_ROOTS/CURSOR_PROJECT_DIR/FILE_CONTAINMENT/FILE_WORKSPACE/COMPLETE); file_path_containment and specific workspace_rejection_reason. Recent filters use closed enums/booleans/counts/hashes. No raw identity, path, command, edits, source, transcript or secret persists.

## Acceptance

New automated cases: 28. Initial targeted: 112 passed / 74.97s. Broader focused: 243 passed / 234.63s. Full offline: 1610 passed / 9 skipped / 6 subtests passed; 1942.39s runner duration. [Regression and individual skip reasons](cursor-schema-compatibility-regression.json). Candidate wheel/sdist source integrity, licenses/notices compliance PASS; final package report is separate. Native installed command/Scanner fixture PASS / 45.37s with process cwd set to temporary .cursor and opaque generation containing ${}; Codex MCP TLS recurrence PASS / 40.04s. Both used temporary state/config roots and simulated Hosts, not Desktop. Real Cursor Desktop PENDING_NEXT_USER_RETEST; continuation unchanged PENDING_CURSOR_CONTINUATION_CAPABILITY.

Core, Scanner, Finding/Policy, remediation/Ticket/Envelope/rules, Codex adapter, shared workspace resolver and Deep are unchanged. No commit/push, actual Cursor/Codex config writes or active Runtime replacement. Prior uncommitted work is preserved. Full results and skip reasons are recorded in the regression artifact.

## Minimal next Desktop retest

After the user chooses to reload the candidate, open a new Cursor chat in Project F, wait for sessionStart to complete, then ask for one timeout-only edit without manually scanning. Query with the same chosen installation/state directory:

```powershell
security-check hooks recent --path "C:\Users\Administrator\Desktop\ai-security\runtime-cursor-e2e-f" --limit 8 --json
```

Expected: Cursor, sessionStart VALID, CORROBORATED, workspace/session match true, then WORKSPACE_ACTIVITY/DIRECT_FILE_MUTATION, real digest delta and scanner_run true. If the generation is empty/invalid or even the event root cannot resolve, the row is unbound; inspect `security-check hooks recent --unbound --limit 8 --json` for the safe reason, not a raw payload. Missing/invalid claims are not waived for Desktop. This iteration cannot honestly mark the historical failure fixed on Desktop without that retest.
