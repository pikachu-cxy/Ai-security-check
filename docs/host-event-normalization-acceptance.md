# Core P0-8 — Host Event Normalization v1

## Scope and baseline

The user reports P0-7 Global Codex Desktop E2E VERIFIED, including real TLS detection, POLICY_AUTO, INLINE_PREPARED, prepare_task_fix=0, exact REMOVE_LINE, original-rule scanner proof, CLOSED and RETURN_TO_HOST. This is supplied actual-host acceptance, not a new Desktop run performed in P0-8. Historical local acceptance records remain unchanged.

P0-8 is an incremental architecture extraction from feature/runtime-mvp / ee1bfd9c12493683cc313cb3628753a51ae124ac. The incoming 443-file workspace was preserved before edits. No commit, push, real user CODEX_HOME access, active Runtime installation/replacement, actual Desktop E2E, new Host adapter, new rule/scanner, Deep verification, model or network operation is added.

## Internal boundary

`Codex raw event → CodexEventAdapter → NormalizedHostEvent → handle_normalized_event → existing HookCoordinator / RemediationService / HostContinuationGuard`.

`HostEventAdapter` is a small Python Protocol: host identity, declared capabilities, host-specific claim validation, and normalization after binding validation. It is not a remotely exposed MCP tool or a capability/entitlement framework. `CodexEventAdapter.bind_project` retains the old project containment, link, translator and invocation checks. Global ingress retains the existing strict canonical resolver, registration, configuration ownership, session binding and replay guard, invoking the adapter to validate/normalize. The existing CodexClaimGuard remains the one implementation of Codex claims/replay consistency. No turn/tool-use fields become mandatory for other hosts.

The normalized v1 model contains:

| Field | Contract |
|---|---|
| schema_version | host-event-v1 |
| kind | SESSION_START / WORKSPACE_ACTIVITY / SESSION_STOP |
| context | VerifiedHostContext, ephemeral internal binding |
| operation | READ_ONLY / DIRECT_FILE_MUTATION / POSSIBLE_WORKSPACE_MUTATION / UNKNOWN |
| mutation_hint | bool/null; never evidence or permission |
| sequence_identity | generated opaque observation identity; no raw host identifier |
| observed_monotonic / clock_scope | actual local monotonic observation, scoped to this process; not historical authority |
| stop_guard_active | normalized bool for Stop only; optional for activity/session start |

`VerifiedHostContext` holds host, canonical workspace, workspace identity/hash, session binding/hash, optional invocation hash and immutable capabilities. The private session value remains ephemeral and repr-hidden because the existing signed snapshot/remediation namespace uses the original session identity. Never serialize the whole context with dataclasses.asdict, persist it, or return it over MCP. Only its explicit safe diagnostic projection is returned. Construction is trusted embedding code; arbitrary MCP input cannot assert a verified context. Validation means BINDING_CONSISTENT, **not cryptographic Host authentication, attestation or repair authority**.

## Capabilities

`HostCapabilities` is a frozen bool contract: supports_session_start, supports_workspace_open, supports_native_file_edit, supports_shell_post_event, supports_tool_input, supports_invocation_id, supports_stop, supports_global_install and supports_setup_seed. Codex declares all except workspace_open. setup_seed describes the existing Codex integration-owned comparison seed; it does not create a new execution trigger. Capability is not execution timing. Other normalized adapters are not implemented; the registry returns no adapter/default false capabilities for them. Existing Cursor command/config support is left untouched and is not relabeled VERIFIED normalized support.

## Parsing and control flow

Codex SessionStart/Stop/PostToolUse names, Bash/apply_patch/Edit/Write mapping, official-shaped claim fields, turn/tool-use replay requirements and command-shape classification reside in the adapter/transport layer. The moved Bash classifier is AST-identical to the previous implementation; this stage does not expand its grammar. Codex legacy command callers retain their previous identity contract, while connected MCP requires the existing strict event-specific schema. Normalization refuses a missing/rejected binding diagnostic.

Core dispatch switches only on EventKind and OperationClass. READ_ONLY bypasses capture/scanners/remediation. Every other activity, including a DIRECT_FILE_MUTATION hint, calls the same filesystem coordinator. No changed-file count, shell text or host success assertion becomes mutation proof. Generic normalized session/activity/stop fixtures exercise the same Core without Codex tool names or Codex turn/tool-use fields.

Lifecycle is unchanged: baseline/session point → load previous snapshot first → current raw-byte filesystem digest → reconcile → real delta → bounded scanner → stable byte recheck → snapshot publication. Existing same-content/revert skips, CRLF/BOM/autocrlf comparison, workspace aliases, nested/subdirectory resolver, safe lazy-bootstrap attribution and snapshot preservation remain covered. The generic Stop continuation dispatch supplies the context's actual host namespace to the existing guard; the default standalone Codex wrapper remains compatible.

No Scanner, Finding, Family/Episode, policy, remediation budget/grant, opaque-ref, receipt, ticket, exact edit envelope, rules or Deep verification implementation is copied or relaxed. Core still returns to the Host after security resolution. No build/test/functional verifier is called automatically.

## Compatibility and remaining host names

Public MCP names, argument schemas, required claims and output text schema are unchanged. Global hooks.json/config generators, matcher, ownership hashes, hooks.state handling and user-preservation logic are unchanged. No re-review or setup migration is introduced by a Hook definition change.

Codex output formatting/advisory and inline ticket feedback remain in codex_mcp_hook / CodexHookAdapter. Project connection readiness remains a Codex installation observer in integration_readiness. GlobalWorkspaces is the existing Codex transport/configuration router: it retains Codex namespace/default installation binding and its existing bounded bootstrap implementation. Those are not generic Scanner/Finding decisions. The core-supported host enum retains namespace names, and the legacy POST_TOOL_USE_MUTATION diagnostic constant and user-facing PostToolUse guidance remain for ABI compatibility. Raw standalone Stop/command entry points are compatibility wrappers. Do not mechanically remove those strings or change signed identities.

## Recent diagnostics

The existing cross-process SQLite journal, ingress HOOK_RECEIVED, rejected-claim records, retention (32 per workspace / 1024 global), read-only CLI and fail-soft writing are retained. Additive safe fields are host, host_event_contract, normalized_event_kind, normalized_operation_class, workspace_binding_status, host_capabilities (closed bool keys) and normalized_scanner_trigger_reason=WORKSPACE_CONTENT_DELTA/null. Existing Codex event_schema, claim fields, tool_classification, scanner_trigger_reason and reconciliation fields retain their ABI. Direct file tools still report legacy POSSIBLE_WORKSPACE_MUTATION alongside normalized DIRECT_FILE_MUTATION.

No raw command/tool_input, tool response, transcript, source, Secret, raw session/turn/tool-use ID or bearer reference is saved in the diagnostic projection. A supports_tool_input boolean is a capability declaration, not tool input content. The adapter parameter to the observer is extensible; its current default is the existing Codex transport. Rejected input remains unnormalized, with original fail-closed diagnostics rather than fabricated verified metadata.

## Acceptance

Focused：182 passed in 170.80s (0:02:50)；full offline：1548 passed, 9 skipped, 6 subtests passed in 1804.88s (0:30:04)，零失败，skipped 单列不计 PASS。wheel/sdist integrity/compliance PASS。本地 stdio MCP + 真实离线 Scanner 的 TLS recurrence 两轮 PASS（模拟 Host，非 Desktop）。 Logs retain the initial restricted-run WinError 5 temporary-directory failures, test-fixture setup mistakes, and overly broad privacy substring assertions. Those preliminary runs are not PASS evidence. Corrections use disposable isolated state/temporary CODEX_HOME and the original scanner/claims requirements; no requirements were relaxed to pass tests.

The existing local stdio MCP + actual managed offline scanner TLS fixture passed two recurrence episodes, each AUTO_FIX → INLINE_PREPARED → native simulated minimal edit → MATCHED → SCANNER_VERIFIED_RESOLVED / CLOSED / RETURN_TO_HOST. prepare_task_fix=0, original values forwarded exactly, old Episode refs rejected. This is a simulated Host using real MCP/scanners, **not actual Desktop or model acceptance**. See host-event-normalization-mcp-trial.json.

wheel/sdist source integrity (84 Python modules), package checks and licenses/notices compliance passed offline. No package is installed into or replaces the active Runtime. See host-event-normalization-package.json. Frozen source/workspace preservation audit: host-event-normalization-workspace-audit.json.

## Next-host design boundary

The security Core can consume a normalized event with no Codex raw fields; no CursorHookCoordinator or second scanner/remediation implementation is needed. A future Cursor adapter must implement its actual schema, workspace/session/invocation consistency, capabilities, output/continuation format and installation/transport integration. The current Codex Global installer/router is not claimed to be a host-generic installer. Wiring another Global transport needs its own adapter-facing construction; compatibility with a real Cursor schema and Stop/inline-remediation capabilities remains unverified. Record that integration gap rather than guessing an official schema or changing Core risk rules. Cursor/Claude/Gemini/Copilot normalized adapters remain Planned.

No new Desktop test is requested or performed in this stage. Stop after the local delivery gates complete.
