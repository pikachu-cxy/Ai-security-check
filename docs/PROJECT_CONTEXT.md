# Project Context

This is the long-term handoff document for the AI Security Runtime. Read it
first when resuming development.

## Current milestone

- Branch: `feature/runtime-mvp`
- Milestone: R1 phases complete; Release Blocker Fix and Global Ownership v2
  passed two independent Desktop restart cycles and Windows standalone checks
- Current stage: **R2.2 local security review experience**; R2.1/1.1 committed
  as an independent finding-quality/evidence baseline. Shared safe triage evidence,
  bounded MCP views and a signed companion Skill lifecycle are implemented.
  New Windows experience requires user Desktop acceptance; earlier Desktop gates
  do not certify this new build's natural-language or Hook visibility.
- Release/CI work is paused by user direction; no tag or Release is implied
- Current local development adds bounded `upgrade diagnose/plan/apply/recover`,
  signed cross-component CAS recovery, stable frozen delivery slots/rollback,
  isolated `trial` profiles, whole-project Skill routing and keyed source
  freshness, plus true Git index projections and strict/report commit gates.
  See the [Chinese implementation handoff](UPGRADE_AND_SCAN_USABILITY.zh-CN.md).
  Final local regression covered 2,070 cases in six disjoint groups: 2,034 passed,
  10 skipped, 26 existing expected failures, zero unexpected failures. Native
  two-build activation/upgrade/rollback, key retention, trial argument isolation,
  unknown-MCP approval and real Git index gates passed. The no-Hook stdio release
  fixture scanned four files with Semgrep/Gitleaks SUCCESS and PARTIAL coverage
  (offline dependency database unavailable), not a repository safety verdict.
  Desktop natural-language selection and Hook visibility remain PENDING.
  No real user configuration, Skill, trust state or business project was migrated.
  Read-only summary does not revalidate engine/DB identity; whole-project requests
  conservatively rescan rather than reuse a fresh-source-only result.
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

## R2.1 finding quality

See [Finding quality baseline](FINDING_QUALITY.md). Raw scanner findings and
existing AI validation remain unchanged. Portable quality IDs, six independent
review statuses and per-rule/capability/source metrics support local review.
Unreviewed findings are not TP; precision needs TP/FP labels and recall remains
unknown without independent ground truth. The initial corpus is the observed
self-dogfood scan, including intentional fixtures, not production accuracy.
No automatic review, suppression, source fix or AI pipeline runs in R2.1.

R2.1.1 exposes bounded redacted local evidence through the existing get_findings
detail option and private baseline export. The managed Semgrep login placeholder
originates in upstream JSON formatting. Older snapshots without file hashes
remain unverifiable; useful current_context is never labelled original EXACT
evidence. New scans capture safe revision hashes and preserve scanner locations.
R2.2 local review reuses the existing host AI triage flow; its new Desktop user
acceptance remains pending. Rules and maturity are unchanged.

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

## R1 detection quality

Phase 1 separates upstream Benchmark labels, scanner observations, source cause
reviews and unlabelled OSS review candidates. Phase 2 adds single-argument
Connection.prepareCall and bounded local ProcessBuilder.command/start modeling.
The frozen 180-case Benchmark sample changes SQLi TP/FP/FN/TN from 0/1/30/29 to
1/1/29/29 and Command from 2/0/28/30 to 3/0/27/30; Path/File stays 1/5/29/25.
No new FP was observed in this sample; six confirmed FP remain known limitations.
All groups are INSUFFICIENT_SAMPLE, not production accuracy evidence. Unlabelled
Jeepay results do not establish recall or safety.

Known limits include cross-function, cross-file, arbitrary wrapper, builder and
collection lifecycle, constant propagation and selected framework abstractions.
Cookie source expansion was not adopted because its bounded experiment added FP.
Maturity remains 2 CORE and 8 VALIDATED; host integration is unchanged.

Versioned evaluation logic, labels and regressions are under `scripts/r1_*.py`
and `tests/corpus/r1/`. Generated reports/scanner outputs stay ignored under
`artifacts/r1/`. Prior R0 acceptance outputs are historical evidence, not current
project state. Release candidate review precedes Release Preflight; no v0.3.1
publication or tag is implied by these local results.
