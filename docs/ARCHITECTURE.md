# Architecture

## Runtime flow

```text
Host Raw Event
  → HostEventAdapter
  → Runtime Core
  → Workspace / Snapshot
  → Scanner
  → Finding / Family / Episode
  → Policy
  → Remediation
  → Scanner proof
```

Host adapters normalize events and preserve strict workspace, session, and
opaque-reference boundaries. The Core owns reconciliation, scanner execution,
finding identity, policy, remediation authorization, and proof. Hosts do not
duplicate scanner or policy logic.

## Ownership and boundaries

- Semgrep owns bounded code-pattern rules.
- Gitleaks owns secret detection and detector identity.
- Trivy and OSV own dependency and package domains.
- Runtime security truth comes from scanner evidence, normalized findings,
  policy, and proof—not Agent prose.
- Core hooks handle deterministic detection and enforcement. Deep functional
  verification, build/test, and AI audit are explicit flows, not default Core
  work.
- Host capability declarations describe transport availability; they do not
  grant authorization or create evidence.

## Host integration

Codex Global Runtime Integration is **DESKTOP VERIFIED** on the observed path,
including mutation reconciliation, `INLINE_PREPARED`, exact edit envelopes,
real scanner proof, and the `CLOSED` result.

Cursor production uses `sessionStart`, `afterFileEdit`,
`afterShellExecution`, and `stop`. Detection Runtime, first-scan attribution,
Finding/Policy, and advisory remediation are **DESKTOP VERIFIED**. Native Chat
Feedback is `HOST_CAPABILITY_UNAVAILABLE_ON_OBSERVED_PATH`; Automatic
Continuation is `PENDING_HOST_CAPABILITY`. The observed path does not rely on
`postToolUse` or `additional_context` as a production feedback channel.

Generic MCP and CLI are supported interfaces. WorkBuddy has project MCP
configuration and stdio/client regression coverage, but this is not proof of a
real WorkBuddy Desktop workflow or a native lifecycle adapter. Qoder and
CodeBuddy currently have neutral manual Hook commands, without a registered
native event adapter or dedicated installer. Their CLI host names are not a
support or Desktop-verification claim.

The existing Codex and limited Cursor observations remain scoped to their
recorded paths; a fresh candidate, another entry point or a new host needs its
own evidence. Native chat feedback, authorization continuation and transport
availability are verified separately. Personal integrations do not advertise
optional functional verification or automatically execute project builds/tests.
See [Host support and next-stage acceptance](HOST_SUPPORT.md) for the current
matrix, official platform references, shared adapter boundary and per-host gates.

## Rule and finding model

The capability-first model is:

`Capability → underlying scanner rules → Finding Family / Episode → Policy →
remediation / proof`

Variants share capability-owned Family identity while retaining underlying rule
identity and source coordinates. Absence requires all applicable variants and a
real scanner proof. Family/Episode recurrence is conservative; ambiguous or
missing proof remains unresolved.

R2.1 adds an independent Finding Quality view and append-only review history.
Portable quality identity correlates observations across checkout locations;
legacy workspace-scoped scanner/remediation identities remain authoritative
for authorization. Human/AI/policy review labels do not alter scanner output,
coverage, enforcement or existing AI triage. Reviews bind to a particular scan
and observation; no model runs or automatic suppressions are part of baseline
collection. See [Finding quality](design/FINDING_QUALITY.md).

R2.1.1 adds locator-based, on-demand local evidence. New SAST scans retain
bounded scan-time file hashes/coordinates, not source copies. Detail requests
rehydrate redacted workspace context through canonical boundary/handle checks,
strict decoding and file/line budgets. EXACT requires historical revision proof;
STALE or unverifiable current_context is separate from original_evidence.
Neither live evidence nor its availability changes coverage, identity or reviews.

See [Rule Program](design/RULE_PROGRAM.md), [coverage matrix](design/RULE_COVERAGE_MATRIX.md),
[Codex integration](design/CODEX_INTEGRATION.md), and
[functional verification](FUNCTIONAL_VERIFICATION.md).
