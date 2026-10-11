# Project Context

This is the long-term handoff document for the AI Security Runtime. Read it
first when resuming development.

For the current public status and future priorities, start with
[development progress](DEVELOPMENT_PROGRESS.md) and [product roadmap](PRODUCT_ROADMAP.md).
The milestone receipts below describe their respective historical source/build
scope; they do not certify the latest installation package or Desktop behavior.

## Current milestone

- Installation efficiency and retention milestone (2026-10-11): personal setup
  reuses a successful capability probe only within the transaction; runtime,
  signed active pointer, environment and package identity changes invalidate it.
  Package verification uses a bounded no-follow inventory, verified byte hashes,
  transaction-local identity reuse, and Windows ChangeTime (not creation time).
  `no_links` keeps fail-closed reparse checks with one lstat per ancestor; native
  reserved-name checks avoid deprecated Path allocation and warning overhead.
  Personal setup cleans verified inactive slots only after the complete receipt;
  live slots/unknown content are deferred/preserved. Completed installs retry
  cleanup at real non-self-test MCP reconnect. Failed setup never triggers GC.
  New Windows packages include a 22,016-byte native launcher verifying the local
  HMAC pointer, exact manifest digest, every declared file and file inventory.
  It supports spaces/Unicode/long paths and uses only Windows system DLLs. Legacy
  bootstraps migrate to `launcher-v2` without replacing a running executable.
  Local `local-delta-v1` ZIPs can be created via `delivery make-update` and applied
  with `install codex --update`; exact-base mismatches, tampered or foreign ZIP
  members fail closed. This is NOT a published remote automatic updater.
  Trivy data uses UpdatedAt/NextUpdate; fresh cache skips downloads, stale data
  refreshes in an isolated staging cache before replacement. Failed/offline
  refresh preserves usable old data and marks dependency coverage PARTIAL with
  Chinese freshness notes. Actual network refresh is not established by mocks.
  Scoped regression: 335 passed, 1 skipped (not a full-suite claim), report
  `artifacts/install-optimized-regression.xml`. Native first/repeat/delta/MCP and
  tamper acceptance passed in `artifacts/install-optimized-native-r2.json`:
  first 8.157s, repeat 3.836s, delta 9.373s; first feedback 0.188s. The 22,124-byte
  delta is a one-document fixture, not a general upgrade size promise.
  Bundle: `dist/install-optimized-final-r2-20261011/security-check`, build
  `e16b0b9288a49019e4c2bd8bd3398d9f23fae0e00fc34d5f672bf90bf5cd05d3`.
  Tests and builds do not replace the live user installation or approve repairs.
  Real legacy running-bootstrap migration also passed:
  `artifacts/install-optimized-migration.json` (8.146s); old slot and bootstrap
  were preserved while running, then removed after exit on the next install.
  ZIP: `dist/experience/ai-security-runtime-v0.3.1-install-optimized-local-20261011-windows-x64.zip`,
  SHA256 `cb8b0e72bd66e5e4447eac39598a21bfd08644ca88fca150b6ffb863d29316ea`.
  Real non-self-test MCP reconnect independently removed the deferred old slot
  without requiring another install; `artifacts/install-optimized-native-reconnect.json`
  passed (first 7.550s, repeat 3.504s, delta 8.565s). ZIP CRC, exact file hashes,
  manifest build identity and checksum sidecar also verified successfully.
  No GitHub push, public Release, cloud Skill fetch or remote installer is implied.

- Installation-feedback milestone (2026-10-11): human-readable, flushed stderr
  feedback begins at the native `install codex` entry before CLI imports and
  launcher validation. Real package/config/copy/capability/Skill/self-check phases
  report their current activity; slow phases emit waiting time without fake
  percentages. The heartbeat does not assert subprocess health or extend the
  existing child timeout. JSON stdout remains a single final receipt. Output
  errors do not alter the installation transaction; failure/cancellation never
  claims success or scanning, and raw exceptions/config/child output are not
  reflected. Direct global `setup` shares the feedback. No authority is added.
  Scoped regression: 56 installation/progress/delivery/upgrade tests plus 78
  global-integration/recovery tests passed (134 disjoint tests, not a full-suite
  claim). Reports: `artifacts/install-progress-regression-final.xml` and
  `artifacts/install-progress-global-regression.xml`. Initial sandbox-only runs
  failed on temporary-directory access; successful isolated runs used the allowed
  execution environment, not a relaxation of product configuration ownership.
  Native acceptance (`artifacts/install-progress-native.json`) passed first and
  repeat installs, user preservation and actual stdio MCP delivery. First feedback
  was observed before exit at 0.175s and 0.180s respectively; JSON stayed clean.
  Bundle: `dist/install-progress-20261011/security-check`; build identity
  `71d0d6bc7f39028ca642e74c6978167fa84f33f49b5dd13a00324c953323286a`.
  ZIP: `dist/ai-security-runtime-v0.3.1-install-progress-windows-x64-20261011.zip`,
  SHA-256 `0470b33da42983ee88e5630a558e0540ecc5335787a17680ec8ed0e123bb1820`;
  archive integrity passed. Real global settings/Skill were not updated. Actual
  Desktop reconnect/trust remains user-controlled; no public release or push.

- Personal installation milestone (2026-10-11): `install codex` on a trusted
  local portable package activates stable program files and coordinates global
  MCP/Hook configuration AND user `ai-security-review` Skill deployment. The
  existing `setup codex` also installs/upgrades the companion Skill. A signed
  cross-component journal supplies preflight, exact-revision checks and recovery;
  user-owned/modified Skill and unknown configuration are preserved, not silently
  adopted. Only the current failed transaction may auto-recover; older interrupted
  transactions need explicit recovery. Installation never grants repair consent.
  Native Windows acceptance passed real fixed-launcher installation, repeat
  idempotence, user-content preservation and stdio MCP guide delivery under an
  isolated synthetic user home (`artifacts/personal-install-native.json`).
  Bundle: `dist/personal-install-20261011-final/security-check`; build identity
  `d40aca1836f3fc89b525a9efff3d14a9712d7af5fe7880905710be91c4cc166c`.
  Local ZIP: `dist/ai-security-runtime-v0.3.1-personal-install-windows-x64-20261011.zip`,
  SHA-256 `8c6f32af101b10985ee3890119fa458717a3b27acba3c2bcf7f1f9dea7d6e74d`.
  New installation/guide unit contracts: 28 passed
  (`artifacts/personal-install-new-contracts-final.xml`); Skill validation passed
  with Python UTF-8 mode. The initial broad run was stopped after obsolete test
  mocks/oversized parameter names and excessive Windows deprecation-warning
  collection; it is not a passed-suite result. Corrected scoped regression passed
  156 cases (`artifacts/personal-install-regression-final.xml`), including the
  28 new contracts; these totals overlap and must not be added together.
  No full-suite all-green claim is made.
  Python wheel `artifacts/personal-install-wheel/ai_security_runtime-0.3.1-py3-none-any.whl`
  passed installed imports/rules/licenses, but coordinated global setup currently
  returns CAPABILITY_MISMATCH in the isolated venv. Direct CLI runtime-info and
  separate stdio MCP initialization/list/runtime-info checks succeeded; the exact
  coordinated-probe discrepancy remains unresolved. It is NOT installation-accepted;
  Windows users should use the native bundle, not this wheel as a proven installer.
  `get_professional_guidance` now exposes a versioned, bounded, input-free global
  read-only content contract. The local Skill prefers this guide for explicit
  deep audits and falls back to its bundled reference. Only BUNDLED is enabled;
  remote endpoint, public-key signing, downloads and verified cache remain
  RESERVED_NOT_CONFIGURED. Remote professional text cannot replace scanner proof
  or human consent. Future design is in `docs/PERSONAL_INSTALL_AND_GUIDANCE.zh-CN.md`.
  Public download/bootstrap installation, cloud guide delivery and actual Desktop
  discovery/trust remain pending. Real global settings/Skill were not updated;
  no GitHub publication, tag, push or deployment occurred in this milestone.

- Local source milestone (2026-10-11): professional audit + rule pack 1.3.0 +
  mandatory human consent. This supersedes historical policy-auto behavior below.
  There are 55 installed SAST rules, 47 default-on, including 15 Python rules;
  25 detection capabilities (2 CORE, 23 VALIDATED), all with unconfirmed automatic
  fix eligibility disabled. Synthetic tests are not production accuracy evidence.
  Canonical `ai-security-review` routes explicit deep audits to its packaged
  `references/deep-audit.md`; normal Hooks retain bounded incremental checks.
  The independently authored workflow draws methodological inspiration from
  3stoneBrother/code-audit, but copies no upstream assets, execution agents or
  claimed scanner/reachability coverage. Runtime owns scanning; host-only static
  reasoning must show concrete edges, controls, unknown links and coverage.
  Maven local declaration/property ownership and bounded Java/Python API references
  support actionable evidence. Neither is full Maven resolution or an advisory-
  specific exploitation proof. Summary distinguishes successful fallback from total
  scan failure, reviewed/pending candidates, rule execution and partial OWASP 2025
  mappings. External Maven/BOM resolution, 429 recovery and complete attack graphs
  remain unfinished; A06/A09/A10 have no SAST detector in this pack.
  Every vulnerability repair, including TLS, needs explicit user approval.
  Ambiguous continuation/handling requests do not count as repair consent;
  an explicit selected-task fix request does. Refusal retains the finding.
  Default mode is ask_before_fix; old smart_auto reads/writes normalize to it.
  Signed old POLICY_AUTO grants are rejected. Confirmed grants can reuse existing
  bounded preparation/tickets and originating-scanner verification; a new episode
  or host session needs new approval. Runtime never edits target code. Internal
  AUTO_FIX means continuing an already approved exact repair, not automatic consent.
  End-to-end elapsed timing includes user wait; it is not edit CPU time.
  Rule gate: Semgrep 1.178.0, 55 rules, 173 positive/142 negative assertions passed.
  Real offline Python Hook/task-fix lifecycle passed detection, no unconfirmed edit,
  line-movement STILL_PRESENT and original-rule SCANNER_VERIFIED_RESOLVED.
  New desktop natural-language prompts/feedback and global installation are PENDING.
  This source work does not upgrade the currently installed global Runtime/Skill.
  Full-suite all-green and production exploitable-chain claims are not made.
  Final targeted verification: audit/task-fix/host contracts 120 passed
  (`artifacts/audit-contracts-final.xml`); consent/timing/exact-envelope loop
  36 passed (`artifacts/consent-loop-final.xml`). These are scoped groups, not
  a complete-suite result. Confirmation/continuation/advisory regression had
  115 passed and the one known Windows temp-alias failure
  (`artifacts/consent-final-approval.xml`). The final wording/Skill regression
  passed 27 cases (`artifacts/consent-language-final.xml`); it overlaps earlier
  groups and must not be added to a unique-case total. The final wheel was rebuilt
  and passed isolated offline
  installation, packaged-Skill lifecycle, rule integrity, mandatory-consent
  policy checks and an empty-project Hook lifecycle. Package SHA-256:
  `8f52f00efee34afa585ae47450ba614546e6827cf20db2f939d36b8f0cb757b4`.
  Offline installation reused already present third-party dependencies without
  downloads; it did not test a new-machine one-command installer or migrate
  real global settings. The previously reproduced Windows temp-alias confirmation
  test failure remains open; fail-closed path checks were not weakened to hide it.
- Branch: `feature/runtime-mvp`
- Milestone: R1 phases complete; Release Blocker Fix and Global Ownership v2
  passed two independent Desktop restart cycles and Windows standalone checks
- Current stage: **Java / JavaScript / TypeScript rule foundation**, built on
  the R2.2 local security review experience. R2.1/1.1 committed
  as an independent finding-quality/evidence baseline. Shared safe triage evidence,
  bounded MCP views and a signed companion Skill lifecycle are implemented.
  New Windows experience requires user Desktop acceptance; earlier Desktop gates
  do not certify this new build's natural-language or Hook visibility.
  Rule pack 1.2.0 adds five Java framework variants and six shared JS/TS
  advisory rules; application version remains 0.3.1. Existing capability
  maturity and automatic-fix eligibility remain unchanged. The bounded Hook
  proof keeps actual detector/version receipts, and Windows state I/O handles
  long paths without changing logical workspace boundaries. See
  [rule foundation](RULE_FOUNDATION.md) for current scope, verification and
  the user's Desktop acceptance checklist.
  Current rule-foundation regression covered all 2,159 collected cases across
  three disjoint groups: 2,109 passed, 24 environment/platform/opt-in skips,
  26 strict expected failures, no unexpected failures or XPASS. The complete
  40-rule synthetic gate and 36 isolated real quick/Hook/re-scans passed.
  Compliance and installed-wheel integrity passed. Native archive receipts
  identify each tested build; this milestone's Desktop acceptance is pending.
- Release/CI work is paused by user direction; no tag or Release is implied
- Personal-version configuration recovery: Codex setup now defaults to one
  user/global integration even with `--path`; per-project setup requires explicit
  legacy/development opt-in. Scan rejection supplies bounded Chinese guidance,
  conflict paths and approval-based migration; CLI repair reuses signed pre-write
  CAS recovery without modifying Skill content. Unknown Hooks/invalid ownership
  remain blocked, and failed MCP probes retain configuration diagnostics. Workspace
  scan state/repair grants remain automatically isolated. Real installed packages,
  user Codex settings, Hook trust and business projects were not migrated by this
  source change; new-build Desktop acceptance remains pending.
  Verification: 14 new connection-recovery tests and two build-consistency reruns
  passed together (16/16). The wider scoped run had 243 passes and three failures:
  one corrected test expectation and two invalidated by concurrent source edits;
  those cases passed in the stable-source rerun. Host workflow checks had 111
  passes and one Windows temp-symlink failure (`test_legacy_fix_without_confirmation_state_under_temp_alias`),
  also reproduced using committed HEAD Python sources loaded in memory. This
  pre-existing failure remains open; no complete-suite/all-green claim is made.
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

Historical rule foundation: `ai-security-core` 1.2.0, mapping 1.1.0 adds
five Java framework variants and six shared JS/TS advisory rules. There are
40 installed execution rules, 32 default-on; TypeScript selection/execution
is separately evidenced. Existing capability IDs/maturity/automatic fixes are
unchanged, old YAML bytes retained. See [rule foundation](RULE_FOUNDATION.md)
and [source review](RULE_SOURCE_INVENTORY.md). Counts below describe the prior
R0/R1 baseline; their synthetic/Benchmark quality is not transferred to new rules.

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
acceptance remains pending. That review-flow milestone did not change maturity;
the current rule additions and their limits are listed under Rule Program above.

Real source-directory scan hardening separates unsupported binary documents
from bounded scanner inputs and records exclusions. Oversized source/config
inputs still fail closed with typed discovery diagnostics. Global integration
status respects explicit scope without requiring a Git project. See
[scan target selection](SCAN_TARGET_SELECTION.md); excluded documents and
languages without applicable rules are not evidence of complete code coverage.

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
- Every vulnerability fix requires explicit user consent. Narrow deterministic
  repairs may be accelerated only after that consent; bounded scope, exact
  envelopes and real re-scan proof remain required.
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
