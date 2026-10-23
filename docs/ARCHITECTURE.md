# Architecture


## Repository layout

Directory migrations group host guidance, task review and task services while retaining the
scan, repair and persistence boundaries. CLI and MCP public entrypoints remain
`security_runtime.cli` and `security_runtime.mcp_server`.

| Location | Responsibility |
| --- | --- |
| `src/security_runtime/guidance/` | Fixed host instructions, versioned topic catalog and shared presentation rules |
| `src/security_runtime/skills/` | Bundled Skill resources; lifecycle and rendering remain in `review_skill.py` |
| `tests/guidance/` | Guidance delivery, Skill lifecycle and risk presentation regressions |
| `src/security_runtime/task_review/` | Review protocol, contract, windows, coverage, budget, plan, revisions and result delivery |
| `tests/task_review/` | Task review regressions and shared review helpers |
| `src/security_runtime/tasks/` | Task lifecycle, ownership, snapshots, immutable evidence, projection, risk handling and verification |
| `tests/tasks/` | Task service regressions and the task-fix stdio fixture |
| `scripts/maintenance/` | Repository content synchronization and metadata checks |
| `scripts/benchmarks/` | Reproducible architecture, context, rule and scanner measurements |

Python imports use the new guidance package directly; there are no duplicate
implementations at the old module paths. Resource lookup remains anchored to the
Runtime package root. Test discovery remains under `tests`; pytest's configured
Python paths preserve shared helper imports during the incremental migration.
Task service helpers use short names under `security_runtime.tasks`, including
`tasks.security`, `tasks.snapshot`, `tasks.preimages` and `tasks.risk_ledger`.
Their existing classes and functions retain the same behavior; source modules,
test monkeypatch targets, measurement tools and package checks use these paths
directly. The immutable legacy-writer fixtures retain their original source.
`security_runtime.task_review` retains the coordinator and its existing module
attributes through the package entrypoint; internal helpers use short submodule
names such as `task_review.plan` and `task_review.transport`. Task record schemas,
protocol identifiers, quotas and MCP tool schemas do not change with this move.

Further groups should follow actual dependencies, with imports, resource paths,
CI, package manifests and callers migrated in the same batch.

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
(`tasks.preimages`), pure changed-range selection (`task_review.windows`), finite
resource policy (`task_review.budget`), plan/coverage accounting
(`task_review.plan`) and readable delivery (`task_review.transport`). The
`task_review` coordinator owns source verification, locking and persistence;
`tasks.security` retains task lifecycle, scanning and risk-policy integration.
Neither the planner nor the transport reads files, starts a scanner, authorizes
repairs or treats a locator as evidence.

Source evidence policy v2 preserves ordinary literals, comments, URLs and long
identifiers. `source_redaction` masks credential values identified by sensitive
field context or known token/private-key formats, URL credentials and scanner
secret ranges. Field names, empty values and environment-variable references
remain readable. This policy applies to source evidence; diagnostic/feedback
redaction retains its existing separate rules. New snapshots and authenticated
preimage references record the policy version. An existing task keeps its
baseline policy for current source and private comparisons, including newly
added files; old immutable evidence is never regenerated or unmasked.

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
independent of evidence delivery. Only v3 executes; v1/v2 task references remain
readable history with their original protocol, owners, signatures, risks and
completion status. Incomplete older tasks cannot resume or migrate. Explicit
subsequent work can start a new v3 task before its first edit without rewriting
old baselines. Independent risk handling and repair authorization remain intact. Current
window reads verify the requested source and Hook revision; final submission
rechecks the complete source inventory and hashes.

## Current execution and result recovery (2026-10-19)

Private scan inputs use a short protected state root, including rules and
provider artifacts. Initialization precedes the ACTIVE claim. Signed attempt
state writes workspace-scan-attempt-v2 while verified v1 cleanup obligations
retain their legacy root; execution receipts remain v1.

ScanPublications stores bounded signed completed facts when publication is
busy. The original task or Hook service rechecks its lease, source, auxiliary
configuration and pending event before committing. The journal cannot grant
execution or repair authority. Queries do not drain it. Cancellation, expiry
and newer generations cannot turn old facts into a new successful execution.

Current result delivery and history share one bounded projection. The current
completion selector requires the original owner, terminal revision and current
source. Default history never repeats a repair choice. Static and host findings
read their existing handling; a read failure preserves details with UNKNOWN
handling. Cold history uses an injected read-only store rather than creating a
writable Runtime. The nine task tools remain unchanged; the additional declared
capability is task-result-delivery-v1.

## Shared architecture (2026-10-19)

Current diagrams, execution flows and acceptance boundaries are in [the continuation record](ARCHITECTURE_UNIFICATION_COMPLETION.zh-CN.md); [the first batch](ARCHITECTURE_UNIFICATION_COMPLETION.zh-CN.md) preserves its historical results. Real Codex/Cursor desktop acceptance is deferred by the user.

Pure lifecycle profiles and task decisions are shared. A durable event claim binds the original task, and the core receives that exact expected reference; it cannot substitute a newer task from the same owner. Delivery receipts distinguish preparation, transport output and host reports; none proves authenticated user consumption.

workspace_services composes product services. WorkspaceApplication owns connection routing and required impact gates without retaining SDK objects. MCPRegistry contains SDK and raw-input adaptation; four tool modules delegate to existing task, audit, disposition and repair services. Short Skill instructions retain mandatory boundaries, with six bundled method topics identified by version and digest.

ScanRequest and CapturedScanInput bind WORKTREE or INDEX bytes, rules and actual execution identities. Task, Hook, setup seed, explicit closeout and production CLI/MCP scans use a shared workspace attempt lane. Claims and conditional publication take short locks; capture, Providers and bounded origin verification run outside them. Source/input identity, independent attempt generation, lease, cancellation and original pending events fence publication. Protected input and Provider artifacts have bounded recovery; the trusted low-level Runtime API without an execution port makes no durable-attempt guarantee.

Each authority commits its own facts and outbox together. Target facts, inbox receipts and version watermarks commit atomically; bounded replay neither scans nor grants authority. Partitioned signed risk storage and real old-writer path fences preserve historical decisions. Package metadata declares actual storage contracts, and the new delivery manager conservatively blocks incompatible rollback while preserving the runtime-state-v1 installation layout. Metadata is not publisher authentication.

Scan history retains its original two-column schema with an additive index and legacy writer tracking. Read-only history does not migrate or replay. A scan's historical attempt record cannot prove publication of the current Task or Hook state, nor revalidate current Provider data.

## Windows native engine execution

`private_directories` owns only the OS primitive that creates an owner/System
protected Windows directory. Scan input keeps its existing error/lifetime
contract through a small adapter; no engine module depends on scan lifecycle.

`engine_environment` owns invocation-local scratch lifetime and child-only
TEMP/TMP/TMPDIR. Windows Semgrep uses the OS-known account LocalAppData/Temp,
independently of inherited temporary-directory variables. An explicit
SECURITY_RUNTIME_ENGINE_TEMP_ROOT must be an existing absolute local directory;
scans reject roots inside their logical workspace. Linked/reparse ancestors,
UNC/device roots and over-budget paths fail closed. An existing, verified 8.3
spelling may shorten a path; the product does not create aliases or junctions.
The UTF-8 scratch-path budget is 60 bytes, reserving space for native socket
names. Each concurrent scan has its own protected random directory. Cleanup
checks the created directory's identity and removes only that directory. A hard
process kill can leave private OS-temp residue; no shared-directory sweeping is
introduced. Host environment, permissions, proxy settings and sandbox remain
under their existing owners.

BaseScanner binds the effective child environment before execution identity
capture and retains it through all batches and post-execution verification.
Other engines and platforms keep their prior environment. Scan-attempt roots
are canonicalized and revalidated after creation, before ACTIVE publication,
so Windows redirection or path spelling cannot split capture from cleanup.

`engine_probe` executes only a small owned Python fixture and fixed local rule
with metrics/version checks disabled, an eight-second process limit and a 64KB
output limit. Windows Semgrep readiness requires its expected result, beyond a
successful --version. Only success enters the existing content/environment/
settings-bound in-process cache. This is component execution availability,
never project scan evidence. Failures keep canonical directory/path-budget,
local-IPC or probe diagnoses; no raw output, source or credentials are persisted.
Existing components are retained. No automatic reinstall, privilege escalation,
sandbox bypass or global environment mutation is part of recovery.

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

### Personal security reply planning

`reply_plan.py` contains immutable security facts and a pure display planner.
`reply_adapters.py` converts existing task, scan, handling and history views;
it does not load stores, scan code, invoke a model, execute tests or issue grants.
`reply_render.py` provides the Chinese fallback used by those views and the CLI.
The host may phrase the reply naturally using the additive
`security-reply-plan-v1` envelope; the original fields remain compatible.

The planner filters suppressed reminders and separates current risks, check
coverage, original-issue verification and handling receipts. It never changes
technical assessment, persisted user choices, freshness proof or repair authority.
Long result pages reference complete facts rather than duplicate their source or
explanations; totals and the three-item display sample are explicitly distinct.
Hook delivery retains its existing turn deduplication and exact capability
transport. Internal control references never come from a rendered message.

Personal replies have no functional-test input and do not recommend functional
tests. Host development outcomes remain outside the security facts model.
Skill references retain workflow/consent requirements and share the presentation
contract, without requiring the host to repeat every secondary operation.
