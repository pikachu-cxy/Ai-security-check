# Architectural Decisions

Only current decisions are recorded here. Historical alternatives and
milestone logs remain available through Git history.

## ADR-001 — Scanner-backed security truth

- Decision: Runtime security truth is derived from scanner evidence, normalized
  findings, policy, and proof; it is not delegated to an Agent.
- Reason: A host or model may be unavailable, ambiguous, or untrusted.
- Status: Accepted.

## ADR-002 — Core is deterministic and bounded

- Decision: Core hooks reconcile workspace changes, scan, apply policy, and
  require proof. Core does not default to build/test or deep verification.
- Reason: The always-on path must remain predictable and local-first.
- Status: Accepted.

## ADR-003 — Capability-first Rule Program

- Decision: Product capabilities own underlying scanner variants and map to
  Finding Family/Episode semantics; YAML rule count is an implementation detail.
- Reason: Capability maturity and coverage must remain stable as variants evolve.
- Status: Accepted.

## ADR-004 — Explicit scanner ownership

- Decision: Semgrep covers code patterns, Gitleaks covers secrets, and Trivy/OSV
  cover dependency domains with explicit fallback boundaries.
- Reason: Engine-specific evidence and limitations must not be conflated.
- Status: Accepted.

## ADR-005 — Narrow remediation authorization

- Decision: Only narrow deterministic fixes may be AUTO_FIX eligible. Policy,
  bounded scope, exact edit envelopes, and a real scanner re-scan remain
  mandatory. `INLINE_PREPARED` is a prepared transport, not proof by itself.
- Reason: Fix convenience cannot weaken security authorization or evidence.
- Status: Accepted.

## ADR-006 — Host capability separation

- Decision: Hooks provide deterministic detection/enforcement; MCP can provide
  Agent chat UX when the host exposes that capability.
- Reason: Cursor `postToolUse` is not a reliable observed feedback channel, and
  configuration writeability is not Desktop verification.
- Status: Accepted.

## ADR-007 — Global Codex semantic ownership

- Decision: Global ownership binds only `mcp_servers.ai_security_runtime` and
  its descendants to a signed sidecar manifest, GLOBAL scope, server identity,
  semantic fingerprint and Runtime version/contract. Comments are not ownership
  boundaries in the shared user-level config. Project legacy remains delimited.
- Reason: Real Desktop restart trials lost marker comments while preserving the
  server definition. The specific writer was not established. No assumption of
  permanent comment preservation is part of the public configuration contract.
- Mutation: Parse the entire TOML first, prove signed ownership, locate complete
  structural statements, replace only the exact MCP subtree, reparse and compare
  all unrelated semantics. Preserve sibling bytes; refuse ambiguous inline-parent
  mutation. Retain HMAC, CAS, interrupted-write recovery and exact hook ownership.
- Status: Accepted; post-restart Desktop stability requires separate evidence.
