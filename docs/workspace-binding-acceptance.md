# Core P0-7.3.2 — Global workspace binding

Only the Global workspace admission bug and safe rejection diagnostics. No scanner, Finding, remediation, Ticket, envelope, rule, Deep/CET changes. No commit/push, real user config writes, package installation or active process replacement. Incoming dirty work is preserved.

## Exact reproduced failure

The old Global catch at global_mcp.py set workspace_claim_match=false for any failure before that flag was assigned. It did not necessarily compare two workspace identities. A generic WORKSPACE_OR_REFERENCE_REJECTED with a canonical workspace_hash and session_claim_match=null could conceal a configuration/admission exception.

Read-only inspection of the actual configured Python launcher, using -I and its declared Runtime env, reproduced IntegrationDiagnostic(INSTALLED_RUNTIME_REQUIRED) in configuration_status. The active package resolves to this checkout and installed_runtime classifies it DEV. GlobalWorkspaces constructs an integration with allow_dev=false. Its read-only configuration check called _desired, which reapplied the new-install DEV restriction before workspace/session admission. Hook delivery, schema completeness and path spelling were not the rejection cause.

Project C: C:\Users\Administrator\Desktop\ai-security\runtime-global-e2e-c. Read-only checks confirmed cwd resolves to its Git root; backslash, forward slash, case and trailing separator give the same root. Existing recent rows are attributed to that root hash, but incorrectly report workspace mismatch. No related project configuration layers were found. No Project C file was edited or scanned by the diagnostic probe. Config bytes were unchanged. [Native read-only evidence](workspace-binding-readonly-evidence.json).

## Fix and boundaries

configuration_status first validates the existing HMAC ownership manifest and bounded configuration, then permits _desired to compute the expected current launcher/Hook fingerprints for a COMMITTED existing enrollment. Verification is not installation. Exact current server/Hook fingerprints must still match; unowned, tampered, incomplete or stale enrollment cannot become CONFIGURED. Setup/repair still require explicit allow_dev for a DEV launcher, and cannot self-enroll through this read-only path.

The ownership manifest attests the launcher and Hook configuration, not source integrity or historical package kind. This patch does not claim otherwise. It does not relax workspace containment, links, refs, session binding, tool-use replay or edit authorization.

Strict resolve_workspace is unchanged. It rejects relative/traversal/UNC/device/link/unsafe/state roots; resolves the cwd and nearest Git root, including nested repositories; uses native Path containment/equality and OS normcase for hashes. Windows aliases normalize to the same existing filesystem identity. Junctions and symlinks are rejected rather than aliased. No PowerShell Resolve-Path or transcript reconstruction is used.

Sequence: strict cwd→canonical root/containment→configured enrollment/layer checks→admit root→bind session→invocation guard→classification→existing lazy bootstrap/reconciliation/scanner. A missing registration or SessionStart is not an identity mismatch. Lazy PostToolUse initializes the bounded baseline as before; INITIALIZING/DEGRADED does not fabricate a scan or proof.

## Diagnostic identities

New bounded persistent fields: workspace_claim_hash (canonical cwd), resolved_workspace_hash (nearest root), registered_workspace_hash (existing child root), session_workspace_hash (existing session root), workspace_registered, session_binding_present, workspace_relation, workspace_binding_stage, workspace_rejection_reason. All identities are hashes, not paths/refs. Stages distinguish resolution/configuration/admission/session/invocation/bootstrap/forwarding. Fixed reason enums include INSTALLED_RUNTIME_REQUIRED, CONFIG_INVALID, OWNERSHIP_INVALID, MCP_CONFIGURATION_CONFLICT, link/outside-root/canonical/session mismatch and phase-specific fallback failures. Unknown exception text is never persisted.

workspace_claim_match becomes true once strict root/containment succeeds; later config errors no longer assert a nonexistent path mismatch. session_claim_match stays null until its check occurs. Rejections still fail closed and scanner_run remains false. Recent diagnostics retain the existing 32-per-workspace/1024-global/read-only/privacy contract and cannot grant authority.

## Validation

28 new cases cover default child admission without prior session; fresh DEV denial; signed existing enrollment read-only verification; setup/repair explicit opt-in; unowned/tampered/incomplete/stale/different launcher rejection; Windows root/slash/backslash/case/trailing/subdirectory; nearest nested repository; SessionStart; lazy PostToolUse to bounded scan; stage-specific configuration errors; wrong root; cross-workspace/session/tool-use; junction/unsafe root and safe projection.

Initial run: 75 passed / 1 failed, because a new test incorrectly expected DEGRADED for a tampered block; the implementation correctly raised MCP_CONFIGURATION_CONFLICT. The test now asserts that stricter existing failure. An initial focused invocation referenced a nonexistent test filename and ran no tests; it is not a PASS. Final focused 180 passed in 263.29s (runner 264.33s), zero failures. Final frozen full offline 1498 passed / 9 skipped / 6 subtests passed in 2034.91s (runner 2035.65s), zero failures. Three skipped cases require an explicit managed real Scanner benchmark environment; six require real scanner binaries. Skips are not PASS. [Exact regression and skip reasons](workspace-binding-regression.json). Candidate wheel/sdist integrity/compliance PASS / 7.78s, all 80 Runtime Python files byte-matched; [package evidence](workspace-binding-package.json). No installation was performed. [Workspace audit](workspace-binding-workspace-audit.json) confirms all 431 incoming files retained, other incoming product/test/script files byte-identical, strict resolver and existing GlobalWorkspaces methods AST-identical, and all 177 frozen code files unchanged.

Actual Desktop scan gate remains user scheduled. No historical opaque refs were used, parsed or regenerated; no real Hook events were manufactured by the read-only probe.

## One minimal Desktop trial

Reconnect/restart MCP so it loads the updated module. In Project C, request one normal timeout change through Bash/apply_patch, without requesting a security scan. Query security-check hooks recent --path "C:\Users\Administrator\Desktop\ai-security\runtime-global-e2e-c" --limit 3 --json in independent PowerShell. Expect canonical hash agreement, claims valid/session bound, then actual classification/reconciliation/scanner or the real bootstrap/skipped boundary. INITIALIZING requires completion/retry through the existing protocol and is not a pass. No setup/repair or Hook trust change is needed just for this patch.
