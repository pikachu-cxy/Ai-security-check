# Project Context

This is the long-term handoff document for the AI Security Runtime. Read it
first when resuming development.

## Current milestone

- Branch: `feature/runtime-mvp`
- Milestone: R0 Rule Program v1 and Java High-Confidence Pack
- Next stage: **R1 Detection Quality Hardening — Real-World Detection Corpus & Evaluation**
- Product: local-first security verification for AI-assisted coding. The agent
  edits; the Runtime supplies scanner-backed findings, policy, and bounded
  remediation.

## Current architecture

`Host raw event → HostEventAdapter → Runtime Core → workspace/snapshot →
Scanner → Finding/Family/Episode → Policy → Remediation → scanner proof`

Codex Global Runtime Integration is **DESKTOP VERIFIED** for the observed
path: AI edit → Global Hook → mutation reconciliation → Scanner → Finding /
Policy → `INLINE_PREPARED` remediation → Exact Edit Envelope → real Scanner
proof → `CLOSED`.

Cursor production events are `sessionStart`, `afterFileEdit`,
`afterShellExecution`, and `stop`. Detection Runtime, First-Scan Attribution,
Finding/Policy, and Advisory Remediation are **DESKTOP VERIFIED**. Native Chat
Feedback is `HOST_CAPABILITY_UNAVAILABLE_ON_OBSERVED_PATH`; Automatic
Continuation is `PENDING_HOST_CAPABILITY`.

Generic MCP and CLI remain supported interfaces. They are not substitutes for
the verified Desktop host paths.

## Rule Program v1

The product is capability-first:

`Capability → underlying scanner rules → Finding Family / Episode → Policy →
remediation / proof`

There are 10 detection capabilities: 2 CORE and 8 VALIDATED. The installed
pack contains 19 capability-owned Semgrep variants, 29 total installed
Semgrep rules, 8 legacy Java EXPERIMENTAL rules default-off, and 2 existing
Python rules. The synthetic corpus reports 46 TP / 28 TN / 0 FP / 0 FN; this is
not production-grade accuracy.

See [Rule Program](RULE_PROGRAM.md) and the [coverage matrix](RULE_COVERAGE_MATRIX.md).

## Verified and local status

R0 capability and package work is locally verified. Codex and Cursor statuses
above reflect the observed Desktop evidence. Runtime security truth is scanner
and policy backed; it does not depend on an Agent's judgment. Core does not
default to build/test or deep functional verification. Missing evidence remains
unknown or inconclusive rather than being promoted to safe.

## Key decisions

- Capability maturity is separate from YAML rule counts.
- Scanner ownership stays with the appropriate engine: Semgrep for code
  patterns, Gitleaks for secrets, Trivy/OSV for dependency domains.
- Finding Family/Episode identity and scanner proof remain the security truth.
- Only narrow deterministic fixes can be eligible for automatic remediation;
  policy, bounded scope, exact envelopes, and real re-scan proof remain required.
- Hooks provide deterministic detection/enforcement; MCP provides Agent chat UX
  where the host supports it.

## Next stage

R1 starts with real OSS/internal detection corpora, independent ground truth,
FP/FN accounting, precision/recall, and evidence-based CORE promotion. Prior
R0 acceptance outputs are historical evidence in Git history, not current
project state.
