# Codex Integration

## Current status

**Codex Global Runtime Integration = DESKTOP VERIFIED** on the observed path.

```text
AI edit
→ Global Hook
→ mutation reconciliation
→ Scanner
→ Finding / Policy
→ INLINE_PREPARED remediation
→ Exact Edit Envelope
→ real Scanner proof
→ CLOSED
```

The Runtime remains the security authority. It validates workspace/session
binding, scanner evidence, policy, bounded edits, receipts, and the post-edit
proof. The host model is not used to manufacture security truth.

## Interfaces

Local upgrade development adds `upgrade diagnose/plan/apply/recover` with active
layer inspection, explicit unknown-server approval, signed pre-write recovery
intent and all-file CAS recovery. Invalid ownership/unknown Hook aliases remain
blocked. Signing keys and scan state survive migration; ephemeral permissions are
never restored. `delivery` provides stable frozen launchers, immutable build slots,
integrity verification and signed activation/rollback. Existing connections must
restart. Read-only diagnosis never runs a command from an unknown MCP entry.
`trial` profiles isolate CLI testing, not actual Desktop identity or Hook trust.

The R2.2 companion AI Security Review Skill guides the existing MCP task workflow;
its reference is generated from HOST_INSTRUCTIONS. Explicit review does not
require a Hook. Skill lifecycle is independent of signed Global MCP/Hook ownership
and never edits Host trust or unrelated configuration. See the
[Windows personal acceptance checklist](WINDOWS_EXPERIENCE.md). New-build Desktop
Skill selection and automatic Hook feedback remain separate acceptance checks.

Codex Global Hook is the verified Desktop integration. Generic MCP remains an
available explicit interface for inspection, triage, remediation preparation,
and deep verification flows; it is not the only or primary Codex integration.
CLI is useful for setup, status, and local operation. Configuration being
writable is not equivalent to a Desktop verification claim.

## Boundaries

[The Hook definition example](continuation-hooks-example.json) is the current
public event ABI fixture (template claims only, no user data). Its exact equality
is frozen by existing regression tests; R2.2 does not change these definitions.

Global MCP ownership uses a signed sidecar manifest and the exact semantic
fingerprint of `mcp_servers.ai_security_runtime`, including its nested env.
Global BEGIN/END comments are obsolete and never required for ownership.
Missing or moved comments and unrelated configuration reordering are allowed.
Unattested same-name servers and semantic changes fail closed. A signed current
entry that differs from the desired Runtime is stale and may be repaired.
Legacy signed Global installations migrate through repair; project legacy
integration retains its existing marker validation.

Global repair patches complete statements belonging only to that MCP subtree,
then reparses and verifies unrelated semantics. It does not serialize the shared
TOML document. Sibling MCPs, marketplaces, projects, plugins and host hook trust
state remain user/Host-owned. Ambiguous parent inline-table layouts are readable
but repair rejects them rather than rewriting unrelated bytes. Hooks retain
their separate exact handler fingerprint ownership.

The local Codex CLI add command cannot persist every required Runtime field;
its `-c` values are execution overrides. This is why Runtime uses a bounded patch.
Official contracts: [MCP](https://developers.openai.com/codex/mcp),
[configuration](https://developers.openai.com/codex/config-reference), and
[hooks](https://developers.openai.com/codex/hooks). Hook trust is Host-managed;
Runtime neither reads internal trust policy nor synthesizes trust approval.

Core does not default to build/test, broad functional verification, or model
invocation. Missing scanner or proof evidence is reported as unknown or
inconclusive. See [Architecture](ARCHITECTURE.md), [Project context](PROJECT_CONTEXT.md),
and [Smart auto-remediation](SMART_AUTO_REMEDIATION.md).
