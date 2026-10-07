# Rule Program v1 — R0 candidate

2026-10-07. This describes the uncommitted R0 working tree, not a released or
installed Runtime. Runtime package version remains 0.3.1; the execution pack
descriptor remains `ai-security-core 1.1.0`. The new capability program has its
own version, `ai-security-java 1.0.0`, and changes the content checksum.

## Architecture and ownership

`capabilities.json → DetectionCapability → applicable execution rules/files →
Semgrep/Gitleaks → existing Finding → Family multiset → Episode → Policy →
existing bounded remediation → real scanner proof`.

[capabilities.json](../src/security_runtime/rules/capabilities.json) is the
product identity and maturity source. [catalog.json](../src/security_runtime/rules/catalog.json)
and first-party YAML remain execution definitions. The bounded, closed schema
validator rejects duplicate IDs/anchors, unknown maturity/engine, missing or
duplicate underlying ownership, language mismatch, unsupported overlap policy,
experimental defaults and metadata-only graduation of a new automatic fixer.
Every installed Semgrep rule must be owned by a capability or explicitly
declared as a legacy rule. Package integrity includes the manifest.

Required capability fields: `capability_id`, `title`, `language`, `category`,
`severity`, `cwe`, `owasp_mapping`, `maturity`, `scanner_engine`,
`underlying_rule_ids`, `frameworks`, `evidence_contract`, `remediation_mode`,
`auto_fix_eligible`, `test_corpus`. Additional version-1 fields are
`default_enabled` and `family_anchor`. Program fields include version/schema,
rule-pack identity, separate tier profiles, legacy declarations and overlap
policy. Sorted catalog loading and deterministic manifest content participate
in the existing content-validated process caches; result/proof reuse is not
introduced.

Semgrep owns code patterns. Gitleaks owns built-in Secret detectors and maps
through `gitleaks:*` to `HARDCODED_SECRET`; its detector identities, configuration,
redaction and individual family proof remain intact. Trivy/OSV continue to own
dependency/package domains. No new scanner or registry rules are added.

## Maturity and defaults

`EXPERIMENTAL → VALIDATED → CORE → AUTO_FIX_ELIGIBLE` is the product maturity
vocabulary. Automatic eligibility is also an explicit independent flag and
does not replace existing policy, source guards, budget, exact edit envelope
or real scanner proof. CORE is not permission to fix.

Java Core Pack v1 contains **TLS hostname verification disabled** and
**Hardcoded Secret**. The separate Validated Java Pack v1 contains SQLi,
command injection, SSRF, path traversal, arbitrary read/write, XXE and unsafe
deserialization. These eight are enabled for detection/guidance and visibly
labelled VALIDATED; they are not represented as CORE or automatically fixed.
The manifest's named profiles describe the tiers, not a new CLI profile switch.

The older eight unrelated Java rules are explicitly EXPERIMENTAL, retained
and disabled in the default plan. The two existing Python rules remain legacy
VALIDATED/default-on for compatibility; they are not new Java capabilities.
The execution YAML's older `BETA` metadata is retained where compatibility
requires it. `capability_maturity` from the manifest is the product grade;
engine catalog metadata must not be used to silently promote a capability.

Counts: 10 product capabilities (2 CORE, 8 VALIDATED, 0 EXPERIMENTAL); 19 owned
Semgrep variants plus scanner-owned Gitleaks detectors. The total installed
Semgrep catalog is 29 (27 Java including mapper XML, 2 Python), including the
8 disabled legacy Java rules. Gitleaks detector count is provider-owned and
is not inferred from this manifest. See [coverage matrix](RULE_COVERAGE_MATRIX.md).

## Planning and proof

Language, rule target extensions, explicit capability defaults/maturity and
framework rule definitions participate in applicability. Java-only edits
select 18 Java AST variants; Java plus mapper XML selects 19. An explicit XML
edit alone selects the single typed MyBatis mapper variant, without repository
discovery. A Python-only scope selects its existing two Python rules. A pure
JavaScript scope has zero applicable first-party SAST rules and never prepares
or invokes Semgrep. Gitleaks remains independent.

Framework applicability is deliberately conservative: the planner does not
guess a whole-project framework from imports or omit a rule because an import
was absent from a changed file. It reports frameworks and
`ENGINE_TYPED_PATTERNS; CONSERVATIVE_LANGUAGE_EXTENSION_PLAN`; Semgrep's typed
source/sink patterns decide applicability within the bounded file scope. This
does not claim pre-scan framework detection or compiler-grade analysis.

Coverage reports applicable capabilities, selected/executed underlying rule
IDs, file count, engine duration and findings. Installed/available counts are
not execution counts. A successful process without `time.rules` and
`paths.scanned`, or with errors/skipped rules, is insufficient absence proof.

For new non-Secret findings, capability anchors make framework variants share
the existing eq-v1 family key while each underlying rule ID and source
coordinate remains evidence. Distinct sink occurrences retain their count;
2→1 is PERSISTING, only a completely proven 1→0 resolves. A canonical family
requires all its applicable variants on the target to have executed. Targeted
verification expands to those variants on the original file and binds the
existing version/checksum/scan/snapshot/episode proof. It always runs a real
scanner, never a string search.

Occurrence accounting retains the existing line-range convention; this R0
does not introduce column-granular same-line occurrence identities or change
the Hook snapshot schema. The corpus's multiple-occurrence cases occupy
distinct line ranges. Finer same-line accounting needs its own labelled
regression before any broader precision claim.

TLS keeps its original anchor, rule bytes and eq-v1 identity. Secret families
keep Gitleaks detector identity. Historical non-TLS pre-program raw-rule
families are not silently reassigned or migrated; their immutable records and
opaque references remain intact. New capability identity applies to newly
normalized scans. The changed pack checksum invalidates old rule-pack proof
in the existing way. This is not a claim of seamless identity migration for
every historical non-TLS finding.

Read/write at the same file and sink range is primary; traversal is retained
as `related_capabilities` with `supporting_rule_ids`. Traversal-only accesses
(including delete) remain independent. This avoids duplicate product findings
without losing distinct locations or detector evidence. No second Finding or
authorization subsystem is introduced.

## Evidence and limitations

Evidence contracts declare source, sink, basis, dataflow scope, coordinates,
rule identity, confidence and limitations. Normalized findings retain engine
identity and rule provenance. Taint rules express recognized external input
reaching a local typed sink. MyBatis interpolation is structural evidence,
with parameter trust explicitly unknown. `source_location=NOT_EXPORTED` and
`exploitability=NOT_ESTABLISHED` prevent a matched rule from pretending that
Runtime exported a full source trace or proved production exploitation.

SQL covers JDBC execute/query/update, concatenation/formatting, Spring JDBC,
MyBatis annotation/XML, Servlet/Jakarta and selected Spring input annotations.
PreparedStatement binding and constant SQL are safe corpus cases. Command
rules distinguish dynamic executables/shell payloads from a fixed executable
and bounded arguments. SSRF covers URLConnection, HttpClient, RestTemplate and
WebClient; fixed endpoints and an allowlist choosing fixed URLs are safe cases.
This does not prove arbitrary DNS/redirect/host-validation code safe.

File rules require actual accesses rather than any dynamic filename. Recognized
safe containment uses a constant normalized absolute base, normalized resolve
and a throwing Path.startsWith guard. The guard sanitizes the checked value;
a subsequent untrusted reassignment is tainted again. String prefix checks,
guards after access and reassignment have risk regression cases. Symlink races
and arbitrary custom validation remain outside this local AST proof.

XXE covers DOM, SAX, StAX and Transformer; hardening must precede parser/use.
Late hardening remains a risk case. Deserialization requires recognized
untrusted ObjectInputStream input; constants and non-object reads are safe
cases, and gadget availability is unknown. Secret corpus covers synthetic
API keys/tokens/private keys/password-like material plus placeholders,
examples, low-entropy fixtures and env references. No broad test-directory or
placeholder allowlist was added to weaken Gitleaks.

## Ground Truth and acceptance

[corpus.json](../tests/rule_program/corpus.json) declares capability, file,
expected occurrence count, risk/safe label, variant and optional evidence.
[rule_ground_truth.py](../src/security_runtime/rule_ground_truth.py) runs the
actual prepared offline Semgrep/Gitleaks adapters and accounts for normalized
occurrences and unexpected detections. It measures TP/FN by occurrences, FP
by unexpected occurrences, TN by safe fixture cases, not scanner exit code.

The final R0 corpus has 71 synthetic cases: **46 TP, 28 TN, 0 FP, 0 FN**. Total
TP+TN exceeds case count because some fixtures have multiple occurrences.
This is author-declared synthetic ground truth, not independent human or
production-grade accuracy. Existing annotated local rule fixtures provide a
separate execution regression gate; they are not added again to corpus totals.
No new OSS repository was downloaded. Framework variants, local wrappers,
line movement, multiple occurrences and safe/hardened patterns are included.

Run from the source checkout with prepared local engines and offline mode:

```powershell
$env:SECURITY_RUNTIME_OFFLINE = '1'
python scripts/rule_program_acceptance.py --output docs/rule-program-corpus.json
python scripts/test_rules.py --help
python -m pytest -q tests/test_rule_program.py tests/test_rule_coverage.py
```

The run writes no raw Secret or source into its report. Scan copies are
temporary synthetic fixtures, not user source persistence. Full tests, clean
installation, package/compliance, actual local MCP TLS recurrence and native
Cursor command transport evidence are linked by [R0 acceptance](rule-program-acceptance.md).

## Host closure and next work

Cursor Host Adapter v1 detection, first-scan attribution, policy and advisory
remediation are COMPLETE / DESKTOP VERIFIED in the user's observed path.
Cursor 3.22.12 file edits produced afterFileEdit and stop, but postToolUse was
NOT OBSERVED. Default installation now has sessionStart, afterFileEdit,
afterShellExecution and stop only. Native user-visible feedback is
`HOST_CAPABILITY_UNAVAILABLE_ON_OBSERVED_PATH`; automatic continuation remains
`PENDING_HOST_CAPABILITY`. There is no new pending feedback delivery item in
the Cursor hot path. Generic presentation/outbox infrastructure remains dormant
for compatibility; old saved delivery history is not deleted or relabelled.

Signed Runtime-owned old fifth/probe entries are migrated by repair; unknown
user hooks remain intact and ownership ambiguity fails closed. No Cursor UI,
matcher, followup workaround or new Host is pursued. Codex's existing TLS
AUTO_FIX/INLINE_PREPARED/Envelope/proof/CLOSED path remains the primary loop.

Next recommendation is broader labelled OSS/internal FP/FN regression and
independent review of the VALIDATED capabilities, followed by evidence-based
CORE graduation. No capability is promoted merely because this small corpus
is green. Additional auto-fix eligibility, other Hosts, Deep Audit and Plus
remain later work requiring separate authorization.
