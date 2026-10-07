# P0-9.6 — Cursor Advisory Remediation Contract

## Scope and status

Runtime advisory contract implemented. Managed offline Scanner / independent Cursor command fixtures and Codex local MCP recurrence PASS. Final focused/full regression: Final focused: **397 passed in 1074.60s (0:17:54)**. Full offline: **1730 passed, 9 skipped, 6 subtests passed in 2361.35s (0:39:21)**.. Actual Desktop NOT_RUN; no active Runtime replacement, real .cursor/.codex edits, commit or push.

## Root cause and boundary

RemediationService._on_hook read config.path while checking whether its writable state/configuration could invalidate the workspace source preservation guard. _policy_binding also used config.path mtime for confirmation preference revision binding. This is a **policy configuration storage path**, not workspace, transport executable, communication or remediation artifact path.

The service's config slot was implicitly a disk-backed RemediationConfig with read() and path. Cursor injected a read-only AdvisoryTransportConfig into that slot because it also had read(), but it was not a policy storage implementation. AttributeError became generic REMEDIATION_INCONCLUSIVE. Its forced report_only preference also mixed Host execution capability with a policy judgment.

Policy and execution now have separate slots: config is real RemediationConfig; transport is immutable RemediationTransportConfig / AdvisoryTransportConfig. Policy storage exposes managed_paths() and revision() explicitly. Existing confirmation mtime binding and state-outside-workspace guard remain. No fake path, hasattr(path) fallback or host-specific Core branch.

Cursor reads the actual user-level remediation preference via RemediationConfig(), preserving opt-out/report_only/ask_before_fix. Its existing supports_live_remediation_continuation=false maps to supports_agent_continuation=false. Transport has no read()/path; supports_write=false for every Runtime transport because the Runtime never edits. Default live transport retains existing Codex compatibility.

## Workspace and offer

Normalized dispatch passes the already verified host context to remediation. Advisory requires a valid VerifiedHostContext whose canonical workspace, host and private session match the existing call. Missing/mismatch fails closed before remediation state initialization; it never falls back to config storage or cwd. Existing scan/task resolution separately binds the current workspace/scan/Finding. Legacy live direct callers retain their existing Runtime workspace argument contract.

After the original policy decision, an advisory-capable transport projects the existing TaskFixService resolver and fixed task_fix.PLANS into bounded informational context. It includes the original opaque task_ref, Finding/rule/family/severity/confidence, hashed affected file identity/location, fixed Scanner/corroboration evidence markers, existing guidance/constraints, one-file scope and real original rule/file verification requirement. It does not copy arbitrary Scanner prose, evidence excerpts, source, raw Host IDs or Secrets. Context is capped at16KB and freshness is rechecked; unavailable/stale context remains inconclusive.

For policy AUTO_FIX, policy_decision stays AUTO_FIX and policy_authorization_kind=POLICY_AUTO. Execution action is ADVISE; status=REMEDIATION_OFFERED, remediation_status=OFFERED, capability=ADVISORY_ONLY. Context explicitly says edit_authorized=false/context_is_not_credential=true. No grant, confirmation token, Ticket, prepared marker, continuation handoff or new Episode is created by the offer; no automatic attempt budget is consumed. Manual/confirmation decisions are preserved as policy_decision and likewise offered without manufacturing authorization.

Existing live grant paths are capability-gated: an advisory instance cannot resume a historical Agent grant, issue one or drive its automatic verification/closure. The Episode identity, receipt/reference validators, _new_episode, _close and original scanner proof implementation are unchanged. Generic advisory Host fixture uses the same behavior, with no Cursor hardcode in Core.

## Delivery and diagnostics

Cursor continuation remains PENDING_CURSOR_CONTINUATION_CAPABILITY. Cursor's native post-edit return remains {}: its existing schema does not document delivery of post-edit agent context. This patch does not invent a field, use Stop followup or claim the Desktop displayed a fix offer. OFFERED is the Runtime structured result; read-only recent exposes its safe status/capability metadata across processes. Existing summary/task fix APIs remain the manual access path for Finding/task details.

Added closed diagnostic fields: policy_decision, remediation_execution_capability, remediation_transport_mode, remediation_status, agent_continuation_available, remediation_workspace_source. Existing bounded recent SQLite stores only enums/bool, not context, refs, raw path, source or Secret. These diagnostics are not security proof or authorization.

## Changed files

- src/security_runtime/remediation_transport.py: capability contract and informational projection of existing task fix plans.
- src/security_runtime/remediation.py: separate transport slot, verified context binding, advisory branch and capability guards; additive diagnostics.
- src/security_runtime/remediation_policy.py: explicit managed_paths/revision storage interface; decide() unchanged.
- src/security_runtime/cursor_hook.py: replace misplaced transport-as-policy-config with real user preferences and capability wiring only.
- src/security_runtime/host_event_runtime.py: forward existing verified context.
- src/security_runtime/recent_hooks.py: closed diagnostic projection.
- tests/test_advisory_remediation.py:18 cases; MANIFEST.in includes them in sdist.
- Existing five state/architecture/decision/stage/acceptance documents and this stage's JSON evidence.

Cursor Event Adapter/schema/anchor/generation/lifecycle, HookCoordinator/snapshot, first_scan_attribution, Scanner/rules/Finding, Ticket/Envelope/Deep bytes remain unchanged. Original policy decision and Episode/reference/receipt/proof AST checks remain unchanged. Prior uncommitted work and documentation history preserved; see audit JSON.

## Acceptance

Final focused: **397 passed in 1074.60s (0:17:54)**. Full offline: **1730 passed, 9 skipped, 6 subtests passed in 2361.35s (0:39:21)**.

Skipped cases are listed separately below; they are not PASS:

- SKIPPED [1] tests\performance\test_managed_cache_lifetime.py:14: Explicit managed real Scanner benchmark environment required
- SKIPPED [1] tests\performance\test_managed_cache_lifetime.py:38: Explicit managed real Scanner benchmark environment required
- SKIPPED [1] tests\performance\test_managed_hot_path.py:10: Explicit managed real Scanner benchmark environment required
- SKIPPED [1] tests\test_e2e_real.py:58: real scanner binaries required
- SKIPPED [1] tests\test_e2e_real.py:80: real scanner binaries required
- SKIPPED [1] tests\test_e2e_real.py:120: real scanner binaries required
- SKIPPED [1] tests\test_e2e_real.py:154: real scanner binaries required
- SKIPPED [1] tests\test_e2e_real.py:68: real scanner binaries required
- SKIPPED [1] tests\test_e2e_real.py:38: real scanner binaries required

18 new advisory contract cases; original 25 first-scan attribution cases included unchanged. The earlier 256-case targeted run is an intermediate check, not the final acceptance result.

Actual managed offline Semgrep 1.178.0 / Gitleaks 8.30.0 Cursor command fixtures: PASS, 83.02s. NEW TLS uses one Java target / 21 rules and retains the original current + pre-edit proof before OFFERED. Existing TLS, additional occurrence and safe edit attribution remain unchanged; SessionStart/Stop run no Scanner. Independent CLI reads safe advisory diagnostics. These trials ran alongside regression and are not performance benchmarks.

Actual local stdio MCP + managed Scanner Codex regression: PASS, 44.25s, two recurrence Episodes, INLINE_PREPARED / MATCHED Envelope / SCANNER_VERIFIED_RESOLVED / CLOSED; original opaque references passed exactly and old Episode refs rejected. Native edit is simulated; Desktop NOT_RUN.

Wheel/sdist, integrity and compliance PASS; 90 runtime module bytes compared with source, new transport module and test included. Candidate-only temporary venv install PASS, 7.75s: --no-index --no-deps with existing system-site-packages dependencies, outside repository, PYTHONPATH unset. This is not a fully dependency-isolated environment and does not replace the active Runtime.

Incoming workspace audit PASS: no deletion, frozen 190 Python files unchanged, original policy/Episode/reference/receipt/proof AST unchanged, old document history preserved. No network/model/target build/Deep Verification/actual Desktop/user configuration edits/commit/push.

Evidence: [regression](cursor-advisory-remediation-regression.json), [Cursor managed Scanner](cursor-advisory-remediation-real-trial.json), [Codex local MCP](cursor-advisory-remediation-codex-trial.json), [package/compliance](cursor-advisory-remediation-package.json), [candidate install](cursor-advisory-remediation-clean-install.json), [workspace audit](cursor-advisory-remediation-workspace-audit.json).

## Next user Desktop verification

This stage does not install or run Desktop. After the user deliberately selects the candidate version, use Project F with a tracked safe TLS source whose pre-edit bytes can be recovered exactly from existing Git index/HEAD. Start a fresh Cursor conversation: SessionStart baseline PUBLISHED and scanner=false. Ask only for an isolated hostname verifier bypass fixture edit; do not explicitly run security-check, builds or tests.

Read-only PowerShell:

```powershell
security-check hooks recent --path "C:\Users\Administrator\Desktop\ai-security\runtime-cursor-e2e-f" --limit 8 --json
```

Expect claims/binding valid, filesystem delta true, FIRST_SCAN_NEW_RISK_ATTRIBUTED, pre scan1/current+pre dispatch2, policy_decision=AUTO_FIX (default smart_auto), remediation_execution_capability=ADVISORY_ONLY, remediation_status=OFFERED, agent_continuation_available=false, remediation_workspace_source=VERIFIED_HOST_CONTEXT. With report_only/ask_before_fix, expect their actual policy decisions instead. No automatic source fix/Scanner-resolved/CLOSED claim. Native post-edit context delivery and Cursor live Agent continuation are not newly verified capabilities. Dirty/unrecoverable pre-edit bytes retain the P0-9.5 inconclusive boundary.

Stop after recording the Runtime offer. Actual fresh Desktop result, Cursor live continuation, three real trial developers and independent Ground Truth remain Pending; other stages stay Planned.
