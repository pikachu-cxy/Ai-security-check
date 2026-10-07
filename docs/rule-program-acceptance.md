# R0 acceptance — Rule Program v1 + Java High-Confidence Pack

2026-10-07. Branch `feature/runtime-mvp`, starting/current Git HEAD
`ee1bfd9c12493683cc313cb3628753a51ae124ac`. These are uncommitted candidate
results. No commit, push, active Runtime replacement or actual user Host
configuration modification occurred. No new scanner, target build, model
invocation, dependency download or sandbox was introduced.

## Phase A gate, completed before Phase B

Removed the temporary CLI probe flag, probe diagnostics/module/script/fixture,
and production wildcard fifth Hook. Default Cursor hooks are sessionStart,
afterFileEdit, afterShellExecution and stop. Internal strict postToolUse parsing
remains dormant: HOST_CAPABILITY_UNAVAILABLE / NOT_ENABLED_BY_DEFAULT, no
scanner, feedback consumption or followup. Generic presentation DTO/outbox
storage remains for compatibility but is not called by the Cursor hot path.
No new permanent PENDING delivery items are created; old saved history is
preserved, not claimed to have been purged.

Capabilities: detection=true; advisory remediation=true; user-visible
feedback=false; agent continuation=false; stop followup=false. These are Host
capabilities, not Cursor checks inserted in shared Core. Signed old Runtime
entries migrate from five to four; user postToolUse hooks/configurations are
preserved. Healthy setup/repair is byte-idempotent and remove deletes only
Runtime-owned definitions. Ownership ambiguity continues to fail closed.

Phase A: 54 passed in 67.59s. Historical user Desktop evidence establishes
Cursor Detection / First-Scan Attribution / Finding-Policy / Advisory
Remediation = COMPLETE / DESKTOP VERIFIED. Native user-visible feedback is
HOST_CAPABILITY_UNAVAILABLE_ON_OBSERVED_PATH on Cursor 3.22.12 edits;
automatic continuation is PENDING_HOST_CAPABILITY. Fresh R0 Desktop was not
run. Installed native command tests use a simulated Cursor with real scanners;
they do not establish native chat visibility or continuation.

## Capability quality and architecture

Versioned product manifest + strict validator → scanner-owned execution rules
→ existing normalized Finding/Family/Episode/Policy. No parallel finding or
authorization system. The manifest/schema, evidence limitations, defaults,
framework mappings and historical identity boundary are documented in
[RULE_PROGRAM](RULE_PROGRAM.md) and [coverage matrix](RULE_COVERAGE_MATRIX.md).

10 capabilities: 2 CORE (TLS + Secret), 8 VALIDATED (SQLi, command injection,
SSRF, path traversal, arbitrary read/write, XXE, deserialization). Only the
existing guarded TLS rule retains auto-fix eligibility. All eight new risk
classes remain detect/evidence/guidance/Agent-or-human-fix + real scanner proof.
Eight unrelated retained Java legacy rules are EXPERIMENTAL/default-off; two
Python legacy rules remain compatible. Installed catalog=29; Java capability
Semgrep variants=19, Java-only AST scope=18; Secret detectors remain Gitleaks-owned.

Final synthetic corpus: 71 cases, **46 TP / 28 TN / 0 FP / 0 FN**. TP/FN/FP
count occurrences; TN counts safe cases. Multiple occurrence cases explain why
TP+TN exceeds fixture count. Per-capability numbers and evidence checks are in
[actual corpus](rule-program-corpus.json). Independent human ground truth is
false; this is not production-grade or exhaustive FP/FN coverage. Existing
internal annotated rule fixtures are a separate gate and are not double-counted.
No new OSS corpus was downloaded.

Containment after untrusted reassignment exposed an actual synthetic FN during
the additional audit. The sanitizer was corrected to sanitize the checked
variable's current value at the guard, not all later uses. Read/write/delete
reassignment regressions are now risk cases and all correctly detected.
Late XML parser hardening also remains a risk case. Safe PreparedStatement,
constants, fixed command+bounded args, fixed/allowlisted URL choices, valid
containment, hardened parser and trusted deserialization cases have TN labels.
Secret placeholders/examples/fixture/env cases do not alter Gitleaks allowlists.

Framework evidence includes Servlet/Jakarta, selected Spring annotations,
JDBC/Spring JDBC/MyBatis, URLConnection/HttpClient/RestTemplate/WebClient,
DOM/SAX/StAX/Transformer and local wrappers. MyBatis is structural matching with
unknown parameter trust; local taint findings are not exported full source
traces or exploitability proof. Unknown runtime reachability/gadgets/redirects,
symlink races and custom sanitizers remain unknown.

Capability anchors unify non-Secret framework variants within the existing
eq-v1 Family scheme; separate coordinates remain occurrences. Read/write
same-sink findings are primary and traversal is related evidence. TLS rule
bytes/eq-v1 identity and Secret detector identity are preserved. Historical
non-TLS raw-rule families are not silently migrated or opaque refs retargeted.
All applicable variants must execute on the original file before absence can
resolve a capability family. Pack checksum changes invalidate old proof;
targeted real scanner re-check remains mandatory.

Language/extension/maturity/default planning selects bounded scopes before
Semgrep preparation. Framework applicability uses typed engine patterns rather
than risky import heuristics/repository-wide discovery. Mapper-only XML edits
select its one variant. Pure Python selects its compatible two rules. Zero
JavaScript applicable rules skips Semgrep entirely; Gitleaks remains independent.
Semgrep/Gitleaks/Trivy/OSV domain ownership is unchanged.

## Tests and Host regressions

- Final focused: 306 passed, 6 subtests passed in 460.88s (0:07:40)
- Final full offline: 1783 passed, 9 skipped, 6 subtests passed in 2326.45s (0:38:46)
- Real managed corpus: PASS, Semgrep 1.178.0 and Gitleaks 8.30.0.
- Retained annotated rule gate: [result](rule-program-rule-gate.json); exact
  expected finding sets, not merely exit 0.
- Actual local MCP + simulated Host TLS inline/envelope/scanner proof/CLOSED
  and new-episode recurrence: [PASS](rule-program-codex-trial.json). Original
  opaque references stay inside that connection; old episode refs are rejected.
  No functional/build/Deep step enters the default Core loop.
- Installed Windows command stdio Cursor + real scanner:
  [candidate native trial](rule-program-cursor-trial-candidate.json) PASS,
  including ordinary delta, same bytes, read-only, TLS finding, manual Host
  fix re-scan, stop convergence and temporary setup lifecycle.
- Fresh actual Codex/Cursor Desktop: NOT_RUN_THIS_R0. Historical user Desktop
  evidence is retained separately, not inferred from simulated Host tests.

## Package and compliance

Candidate [wheel/sdist gate](rule-program-package-candidate.json) PASS:
93 Python modules and formal rule data byte-equal to source, versioned
manifest validated, corpus and new tests/scripts in sdist, removed probe absent,
license/distribution policy and generated notices PASS. Build used a fresh
temporary tree, preserving pre-existing build/egg-info and user work.

[Isolated install](rule-program-clean-install-candidate.json) PASS:
system_site_packages=false, non-editable install, all dependencies installed
from existing local cached wheels with --no-index; pip check, installed module
origin, CLI, manifest loading, licenses and installed native Cursor trial pass.
No network access or active package replacement. Final artifacts are linked
after documentation closure by rule-program-package-final.json and
rule-program-clean-install-final.json; candidate and final hashes are recorded
individually rather than asserted equal by name.

## Actual single-file performance baseline

Each sample runs the real managed adapters on one temporary Java file in a
fresh child process, including cold capability probing followed by warm edits.
It is a diagnostic baseline under the local acceptance workload, not a p95/p99
SLO or Desktop Host/Agent latency result. No fake scanner timings or sleep.

| Case | Incoming scanner wall ms | R0 scanner wall ms | R0 Semgrep ms | R0 Gitleaks ms | R0 files/rules | Findings |
| --- | ---: | ---: | ---: | ---: | --- | ---: |
| safe-cold | 8166.352 | 7914.188 | 6906 | 872 | 1/18 | 0 |
| safe-warm | 4317.231 | 4532.129 | 4012 | 508 | 1/18 | 0 |
| tls-risk | 4657.728 | 4583.415 | 4057 | 515 | 1/18 | 1 |
| fixed-rescan | 4520.622 | 4534.685 | 4009 | 514 | 1/18 | 0 |

Raw [incoming](rule-program-performance-before.json) and
[R0](rule-program-performance-after.json) reports retain provider timing and
scope counts. TLS targeted verification in the MCP trial still uses its
original single-rule proof. Small observed differences cannot establish
production regression or speedup; no daemon/worker or unrelated performance
redesign is justified by this one-file comparison.

## Preservation and remaining work

[Workspace audit](rule-program-workspace-audit.json) compares against the 560
incoming files snapshotted before edits. Only R0-targeted old files and
documentation are changed; the four removed files are explicitly authorized
probe/unused Cursor feedback acceptance code. Unrelated pre-existing files
remain byte-equal; no reset, whole-file restore or clean occurred. No staged
changes or HEAD movement. PROJECT_CONTEXT is updated once only at the major
milestone after required regression has completed.

Next recommendation: broaden labelled local OSS/internal safe/risk corpus and
independent reviews, then graduate selected VALIDATED capabilities on evidence.
No P0-10.1b/c, UI workaround, additional Host, Deep Audit, new crypto/JWT rule,
Plus entitlement or automatic fixer is started here. Independent human ground
truth, three developer trials, remote four-platform rerun and prepared offline
Maven A/B remain Pending with their original boundaries.

Skipped cases from final offline run:

- `tests.performance.test_managed_cache_lifetime::test_real_managed_three_edits_rebuilt_cache_and_five_target_batch`: Explicit managed real Scanner benchmark environment required
- `tests.performance.test_managed_cache_lifetime::test_real_gitleaks_batch_preserves_per_file_findings_and_redaction`: Explicit managed real Scanner benchmark environment required
- `tests.performance.test_managed_hot_path::test_actual_managed_scanner_benchmark`: Explicit managed real Scanner benchmark environment required
- `tests.test_e2e_real.RealDemoTests::test_cli_quick_and_release`: real scanner binaries required
- `tests.test_e2e_real.RealDemoTests::test_mcp_protocol`: real scanner binaries required
- `tests.test_e2e_real.RealDemoTests::test_mcp_rejects_unsafe_workspace_and_reports_partial_coverage`: real scanner binaries required
- `tests.test_e2e_real.RealDemoTests::test_mcp_stdout_contains_only_protocol_json`: real scanner binaries required
- `tests.test_e2e_real.RealDemoTests::test_pre_commit_blocks_then_allows`: real scanner binaries required
- `tests.test_e2e_real.RealDemoTests::test_scan_fix_verify_and_modes`: real scanner binaries required
