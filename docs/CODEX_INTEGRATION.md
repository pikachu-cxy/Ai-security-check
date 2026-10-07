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

Codex Global Hook is the verified Desktop integration. Generic MCP remains an
available explicit interface for inspection, triage, remediation preparation,
and deep verification flows; it is not the only or primary Codex integration.
CLI is useful for setup, status, and local operation. Configuration being
writable is not equivalent to a Desktop verification claim.

## Boundaries

Core does not default to build/test, broad functional verification, or model
invocation. Missing scanner or proof evidence is reported as unknown or
inconclusive. See [Architecture](ARCHITECTURE.md), [Project context](PROJECT_CONTEXT.md),
and [Smart auto-remediation](SMART_AUTO_REMEDIATION.md).
