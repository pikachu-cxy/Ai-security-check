# P0-9.3 — Cursor Real Workspace Anchor Compatibility

Scope: Cursor-only workspace admission/diagnostics. Starting HEAD `ee1bfd9c12493683cc313cb3628753a51ae124ac`, branch `feature/runtime-mvp`, prior dirty workspace preserved. No commit/push, active Runtime replacement, real `.cursor`/`.codex` changes or fresh Desktop trial.

## Root cause and corrected contract

User's actual Desktop evidence confirms roots shape VALID but POSIX/native-nonabsolute on Windows, failing PATH_SHAPE/RAW_PATH_NOT_ABSOLUTE. The previous adapter tried `workspace_roots[0]` as the authoritative filesystem ingress before optionally resolving `CURSOR_PROJECT_DIR`. This was the incorrect assumption; strict resolver rejection itself was correct. `[]` was also rejected at common claims validation. No launcher/delivery/generation investigation is repeated.

Rechecked [official Cursor Hooks documentation](https://cursor.com/docs/hooks) on 2026-10-07: environment `CURSOR_PROJECT_DIR` always supplies workspace root; afterFileEdit has absolute file_path. It is a Host claim, not attestation: Runtime independently applies the existing absolute-path, link/junction, protected-root, read-only ownership preflight and shared canonical resolver. The latter and shared Git helper are unchanged; no global/local safe.directory change.

1. Require/resolve CURSOR_PROJECT_DIR as strict anchor before routing or persistent session binding. No process cwd fallback; direct adapter callers must supply the argument just as the command entry point supplies the environment.
2. workspace_roots is required list with <=1 bounded nonempty string, no control/surrogate characters. Missing/wrong type/malformed still INVALID_HOST_CLAIMS; >1 remains CURSOR_MULTI_ROOT_UNSUPPORTED. [] is EMPTY_HOST_LIST with legal anchor; it never selects a filesystem root.
3. Single native-absolute root is independently resolved and canonical identity must MATCH anchor, including compatible slash/case/trailing/subdir -> Git root. Disagreement CURSOR_WORKSPACE_SOURCE_MISMATCH before CursorBindings write. Diagnostic partition follows validated anchor.
4. Single native-relative root (including POSIX slash path which is nonabsolute on Windows) is UNVERIFIED_RELATIVE / WORKSPACE_ROOT_RELATIVE_UNVERIFIED. Never normalized via cwd/anchor concatenation, interpreted as filesystem location or used to grant authority. Invalid URI is not decoded. It does not assert roots-source match.
5. afterFileEdit still needs a real existing absolute file, no `..`, no link/junction and containment under anchor. Its parent canonical workspace must agree, rejecting nested repositories. Session binding remains persistent/bounded/signed; cross-workspace conversation reuse rejects before Core.
6. SessionStart absent/exact-empty generation retains NOT_YET_AVAILABLE; malformed generation remains rejected, activity/stop still require valid generation. Generation validation and CursorBindings implementation are unchanged.
7. Baseline/reconciliation/scanner decisions remain solely existing Core digest state. Relative or empty metadata alone never starts scanner; actual file digest change does. Same bytes and read-only remain skipped. No remediation/Ticket/rules/policy/Deep change.

## Diagnostics and privacy

New closed enums/bools: cursor_workspace_anchor=CURSOR_PROJECT_DIR; cursor_project_dir_valid; workspace_roots_state=EMPTY_HOST_LIST/SINGLE_ABSOLUTE/SINGLE_RELATIVE/MULTI_ROOT; workspace_root_relative; workspace_root_corroboration=MATCHED/UNVERIFIED_RELATIVE/EMPTY_HOST_LIST/MISMATCH; file_path_absolute; workspace_binding_reason. Existing cursor_project_dir_is_absolute/canonicalized, path-shape, Git probe enums, workspace hashes, containment and session diagnostics remain available. Recent uses existing persistent bounded SQLite (32/workspace, total1024), readable from independent CLI/restart. No raw root/env/path/session/generation/file path/command/source/input/output/transcript/Secret saved. All new projections closed and non-authoritative.

## Validation

Targeted: 124 passed / 80.24s, including 25 new cases. Previous 99 Cursor cases remain successful after fixture callers explicitly supply the newly required anchor; former empty-root rejection replaced by malformed control-string rejection and new positive empty-root tests. Strict bad-path tests now exercise required anchor, not optional relative metadata. Generation assertions unchanged.

Focused: 254 passed in 261.39s (0:04:21).
Full offline regression: 1672 passed, 9 skipped, 6 subtests passed in 2110.34s (0:35:10).

Skipped (not PASS):

- SKIPPED [1] tests\performance\test_managed_cache_lifetime.py:14: Explicit managed real Scanner benchmark environment required
- SKIPPED [1] tests\performance\test_managed_cache_lifetime.py:38: Explicit managed real Scanner benchmark environment required
- SKIPPED [1] tests\performance\test_managed_hot_path.py:10: Explicit managed real Scanner benchmark environment required
- SKIPPED [1] tests\test_e2e_real.py:58: real scanner binaries required
- SKIPPED [1] tests\test_e2e_real.py:80: real scanner binaries required
- SKIPPED [1] tests\test_e2e_real.py:120: real scanner binaries required
- SKIPPED [1] tests\test_e2e_real.py:154: real scanner binaries required
- SKIPPED [1] tests\test_e2e_real.py:68: real scanner binaries required
- SKIPPED [1] tests\test_e2e_real.py:38: real scanner binaries required
Package: PASS, wheel/sdist byte integrity across 88 Python modules, check_wheel and license/notices compliance; see cursor-workspace-anchor-package.json. No dependency downloads.
Installed native Cursor command + actual managed offline scanner trial: PASS / 49.35s; empty roots SessionStart from config cwd, relative roots activities/stop, ordinary digest delta scanner, same-byte/read-only skip, TLS finding/manual bounded fix/rescan, cross-process CLI, setup/repeat/repair/remove/re-setup verified. Temporary venv borrows installed system dependencies (`--no-index --no-deps --system-site-packages`), not fully dependency-isolated. This is simulated Host, not Desktop evidence.
Codex local MCP actual Scanner regression: PASS / 45.02s; actual offline TLS recurrence/Episode/opaque ref path, no Cursor change to Codex adapter/Core.
Workspace preservation/generation AST audit: PASS; 481 incoming files, no deletions, changed only explicitly allowed Cursor/test/doc/package inventory files. Frozen192 files unchanged. Generation validators and CursorBindings AST unchanged; previous docs history byte-preserved.

Evidence files use the `cursor-workspace-anchor-` prefix; tests/manifests/logs also under ignored `.security-runtime`. Tests are not real Cursor delivery claims. Fresh actual Desktop PENDING_USER_RETEST, live Cursor remediation continuation retains prior Pending.

## One next Desktop check (operator, not run in this patch)

After the candidate is intentionally made available to Cursor by the operator in a later authorized step, open a fresh Project F chat (`C:\Users\Administrator\Desktop\ai-security\runtime-cursor-e2e-f`). Let SessionStart finish, then ask Cursor to change one ordinary existing Java timeout constant once, with no manual scanner/build. Query using the candidate's read-only CLI in the same state namespace:

```powershell
security-check hooks recent --path "C:\Users\Administrator\Desktop\ai-security\runtime-cursor-e2e-f" --limit 8 --json
```

Expect sessionStart VALID / NOT_YET_AVAILABLE / baseline established with CURSOR_PROJECT_DIR anchor and EMPTY_HOST_LIST or UNVERIFIED_RELATIVE if Host sends those forms. afterFileEdit: workspace/session match true, absolute file containment true, real delta changed_file_count=1, SCANNER_TRIGGERED/COMPLETED and scanner_run=true. Root corroboration stays UNVERIFIED_RELATIVE or EMPTY_HOST_LIST if relevant; it must not be fabricated MATCHED. If invalid anchor/source/file/session, expect precise rejection and no scanner. An older active Runtime/CLI cannot validate this candidate patch. This work deliberately does not replace it.
