# Architecture

Risk handling separates four facts: technical assessment, the user's handling
decision, effective reminder state and repair verification. `risk_disposition`
owns the SQLite decision/event/assessment store, stable issue identity and
semantic evidence revisions. It does not scan, invoke a model or authorize a fix.
`finding_feedback` and `task_risk_feedback` adapt their existing finding and
ownership contracts to that store; raw scanner results and original task risks
remain intact. `dependency_disposition` supplies package/advisory identity and
declaration revisions for dependency findings without coupling manifest formats
to the shared decision store. Each workspace keeps private state outside project source.

`risk_decision_guidance` is the canonical interaction contract and choice list;
MCP instructions, generated installed Skill references and summary projections
consume it. `feedback_contract` defines typed evidence input and precise errors.
The host Agent performs bounded investigation, while explicit EXCLUDE, DEFER and
RESTORE user decisions control reminders independently of model agreement.
RESTORE persists until a new user decision. A material code change queues an
internal review; only fresh, concrete risk evidence can reopen a suppressed issue.
Unreadable source cannot revoke a saved choice. Unreadable decision storage is
reported as unavailable rather than converted into zero risks or a new prompt.

Task review v3 separates five responsibilities: immutable sanitized evidence
(`task_preimages`), pure changed-range selection (`task_review_windows`), finite
resource policy (`task_review_budget`), plan/coverage accounting
(`task_review_plan`) and readable delivery (`task_review_transport`). The
`task_review` coordinator owns source verification, locking and persistence;
`task_security` retains task lifecycle, scanning and risk-policy integration.
Neither the planner nor the transport reads files, starts a scanner, authorizes
repairs or treats a locator as evidence.

New task captures keep optional, keyed redacted-line change locators in a private
side table committed with the original sanitized body. References and old body
formats stay compatible. Locators are bound to the original task/path/hash and
retention, used only in transient planning inputs, and never copied to source
packets, plans or control records. Missing legacy locators produce conservative
masked-range requirements rather than post-edit baseline reconstruction.

New v3 plans include every changed unit and derive independent source,
navigation and control allowances from all required ranges. Large-file diffing
uses common boundaries, unique-line anchors and bounded local matching; ambiguous
regions remain required. Batches schedule estimated work without a per-batch
hard cutoff. Source bindings are registered once; source packets contain readable
sanitized lines and new evidence ids, while already-delivered ranges reuse only
actual issued evidence. Finalization still verifies all required windows and
explicit unit submissions, including pages the host never requested.

A 15-minute activity lease advances only on real reading/submission progress.
Explicit preparation can resume an idle v3 plan after verifying its original
owner, immutable snapshot and Hook revision. It preserves the same session,
evidence, cumulative consumption and static result. It does not recreate the
baseline or extend immutable preimage retention (24 hours). Admission beyond the
128MB category guard reports required capacity before delivering source; missing
bodies, capture limits and source truncation remain explicit gaps. These guards
bound memory and delivery, rather than silently omitting work or certifying safety.

Historical result pagination and the bounded terminal persistence receipt are
independent of evidence delivery. Existing v1/v2 task references, original fixed
quotas/deadlines, owners, signatures, risk records and repair gates remain valid;
an already prepared task cannot switch protocol to reset its ledger. Current
window reads verify the requested source and Hook revision; final submission
rechecks the complete source inventory and hashes.

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

The host connector boundary composes installation/configuration, event input,
feedback/continuation output, and capability reporting. Each product/client
entry point retains its own acceptance record while sharing the Runtime Core.
Event adapters already exist; some task registration and global routing remain
Codex-specific. The [Cursor connector development and test plan](CURSOR_INTEGRATION_PLAN.zh-CN.md)
defines the limited extraction needed before adding its full automatic workflow.
This boundary is a development target, not a claim that every connector is complete.

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

Cursor retains the four-event detection-only compatibility mode. The local
automatic beta adds user-level MCP, synchronous preToolUse task preparation,
postToolUse task context and bounded stop fallback. Both hosts share
workspace_services and task_hook_activity; connector-owned configuration and
Cursor transport/task delivery stay outside the scanner and authorization Core.
A Windows isolated installed-process check covers the new transport and task
closeout. Earlier Cursor 3.22.12 Agents probes verified native edit/context and
followup delivery; the new candidate still needs real model risk/repair acceptance.
See [Cursor install and testing](guides/CURSOR_INSTALL_AND_TEST.zh-CN.md).

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
