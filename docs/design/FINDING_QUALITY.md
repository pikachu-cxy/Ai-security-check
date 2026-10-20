# Finding quality baseline (R2.1)

R2.2 connects the safe local reader to existing AI triage and adds bounded MCP
views and a companion Skill; see [Security review](SECURITY_REVIEW.md). Human
quality labels remain separate. Full-file keyed context revisions invalidate AI
conclusions after changes; old scan context is never promoted to original EXACT.

Scanner observations, quality review decisions and existing AI validation are
separate records. Nothing in this baseline suppresses findings, changes scanner
coverage, authorizes fixes or invokes an LLM. The first corpus is the current
self-dogfood repository scan, including intentional vulnerable fixtures; it is
not a representative production accuracy sample.
Test/example location alone is not FALSE_POSITIVE counterevidence. Review
whether the detector's claim is correct separately from deployment exposure or
an explicit policy choice to accept intentional vulnerable fixtures.

## Existing architecture

`models.Finding` contains id, category, title/plain_title, description, impact,
severity, confidence, relative file_path, line_start/end, redacted evidence,
fix_advice, scanner_sources, fingerprint, OPEN status, technical_details and
equivalence_key. ScanResult serializes these with dataclasses.asdict; SQLite
stores full scan snapshots plus the latest scanner finding per legacy ID.
Scanner-specific rule, capability, framework, advisory and rule-pack metadata
remain in technical_details.

Existing AI TriageRecord is stored separately in triage_records. Its verdicts
are CONFIRMED/LIKELY/NEEDS_REVIEW/UNLIKELY/FALSE_POSITIVE and its record validity
is VALID/STALE/FAILED. It includes confidence, evidence references, context hash,
provider identity and timestamps. These are not the quality-review taxonomy.
No old verdict is automatically converted to a TP or human review.

## Minimal additive contract

`finding_quality.quality_finding` derives a serializable view without changing
the raw scanner dataclass or its persistence/serialization:

| Field | Meaning |
|---|---|
| finding_id | Versioned portable quality identity (`fq1-...`) |
| scanner_finding_id | Existing workspace-scoped scanner/remediation ID |
| rule_id / scanner / capability | Detector attribution, original scanner list |
| file / line / line_end | Relative path and scanner range |
| severity / confidence / message | Original scanner assessment, not AI confidence |
| evidence / scanner_metadata | Derived evidence contract and original metadata |
| observation_hash | Digest of the normalized observation, excluding scan/root/time |
| triage_status | UNREVIEWED, TRUE_POSITIVE, FALSE_POSITIVE, NEEDS_CONTEXT, ACCEPTED_RISK, NOT_APPLICABLE |
| triage_reason / triage_source / triaged_at | Bounded redacted reason, HUMAN/AI/POLICY, server UTC timestamp |

Review history is append-only in a separate finding_reviews SQLite table.
Decisions are bound to workspace + scan + portable ID + observation hash.
The entire batch validates before one transaction; raw scans/findings and the
existing AI triage records are unchanged. New scans start unreviewed even when
IDs match: surrounding source context may have changed. IDs enable explicit
correlation, not automatic transfer of ground truth or cross-project trust.

## Stable identity and compatibility

Legacy id/fingerprint hashes the absolute workspace root, category, relative
file and line (and rule for dependency/configuration). It is stable within one
checkout but changes when the checkout moves. Changing it directly would break
workspace authorization, historical DB references and remediation handoffs.

The additive quality ID excludes absolute root, scan_id, time, severity,
confidence, message and finding/scanner ordering. It retains existing
same-category/same-file/same-line dedup semantics. Configuration includes rule
identity; dependency identity uses normalized ecosystem/package/version,
canonical advisory and manifest, excluding provider alias and manifest line.
Scanner/Finding Family/Episode identities are unchanged. The portable ID is
never a global DB lookup key or authorization token.

Limits: code line movement changes quality identity; existing same-line category
overlap is still collapsed by Runtime. Distinct variants retained only as a
representative scanner observation are not reconstructed here. Neither code
equivalence nor independent vulnerability ground truth is claimed.

## Evidence

evidence_level is DIRECT_MATCH, SECRET_MATCH, DEPENDENCY_MATCH or CONFIG_MATCH
according to the stored scanner observation. source/sink are null, trace is [],
dataflow_available is false for this derived legacy view. Historical adapters
did not retain dataflow; R2.1.1 retains actual scanner trace/metavariable
locations separately in scanner_metadata when provided, without inventing flow.
matched_code is nullable; secret
matches are always redacted. Empty scanner evidence does not become a code
excerpt. The original scanner metadata is retained separately from review.
Known Semgrep `requires login` evidence is a scanner placeholder, not matched
source. It remains in scanner_evidence while matched_code is null and
matched_code_status is UNAVAILABLE_SCANNER_PLACEHOLDER. Missing evidence never
automatically assigns TP, FP or NEEDS_CONTEXT. Actual source context must be
reviewed explicitly via the existing bounded context interface or local file.

Existing MCP prepare_triage can supply bounded redacted lexical context and
evidence references on explicit request. Lexical references are not a proven
dataflow chain. R2.1 does not run prepare/submit or configured AI providers.

## Local review workflow

Export an existing scan without scanning, creating a database, or changing code:

```sh
python scripts/finding_quality.py export --workspace . --scan <scan-id>
```

The resolver first checks the existing Global workspace-specific DB, then the
legacy state DB. --database explicitly selects another local DB. The selected
scan must belong to the requested workspace. Export reads SQLite in read-only
mode, including databases predating the review table.

Private output is fixed to `.security-runtime/finding-quality/` (already Git
ignored): baseline.json, review-template.json and REPORT.md. Linked output
paths are refused. No private corpus, absolute user path, secret or source
excerpt belongs in source control; checked-in tests use synthetic fixtures.

Keep only entries actually reviewed from review-template.json, set status,
reason and source explicitly, save as a local decisions.json, then import:

```sh
python scripts/finding_quality.py review --workspace . --scan <scan-id> --decisions .security-runtime/finding-quality/decisions.json
```

Only this explicit review action writes decision history. No inferred label,
auto-fix, auto-suppression, model call or new MCP mutation tool is introduced.
To see refreshed metrics, export again. The initial real baseline deliberately
leaves all findings UNREVIEWED for the user's design and finding-quality review.

## Metrics and Agent access

Reports aggregate total, reviewed, TP, FP, NEEDS_CONTEXT, ACCEPTED_RISK,
NOT_APPLICABLE and UNREVIEWED by rule and capability. Reviewed includes explicit
non-UNREVIEWED decisions; precision_on_reviewed uses only TP / (TP + FP), or
null when that denominator is zero. AI/POLICY labels are recorded decisions,
not independent ground truth; separate by_source statistics keep this visible.
Recall is null without a labelled missed-finding denominator. FULL describes
scanner execution coverage, not precision, recall or safety.

FP/TP/NEEDS_CONTEXT rule rankings include only groups with nonzero reviewed
counts, with deterministic tie ordering. An unreviewed corpus has empty noise
rankings and no measured precision; finding count is not a noise ranking.

Existing scan_project/scan_diff and get_findings expose an additive `quality`
object with ID, range, evidence and review state. get_findings overlays current
persisted quality review state. Existing top-level id and triage_status keep
their old meaning for compatibility. Details/evidence are already returned by
get_findings and prepare_triage, so no duplicate list/detail tools are added.
No new tool or integration contract version is required. Invalid derived review
locations never remove existing scanner results from MCP output.

## R2.1.1 local finding evidence

### Root cause and data path

The pinned Semgrep 1.178.0 JSON formatter gates logged-out fields:
`Cli_json_output.adjust_fields_cli_output_logged_out` replaces lines and
fingerprint with `Gated_data.msg` (requires login), and removes metavars and
dataflow_trace. Python JsonFormatter delegates to this OCaml RPC formatter.
See [the pinned upstream implementation](https://github.com/semgrep/semgrep/blob/v1.178.0/src/osemgrep/reporting/Cli_json_output.ml).
The actual managed Windows engine reproduces those raw JSON placeholders on a
synthetic local rule. No login, engine patch, downgrade or flag bypass is used.

The complete path is Semgrep raw `extra.lines` → PatternSASTScanner.normalize
→ FindingNormalizer redaction/truncation → ScanResult/SQLite snapshot →
quality_finding.scanner_evidence → get_findings. The snippet is already absent
when Runtime receives JSON. Baseline/MCP serialization did not lose it.
Previously, normalization also discarded start/end columns and scanner trace
metadata. It now retains columns, a genuine scanner fingerprint if provided
(never the login placeholder), and bounded scanner trace/metavariable structure.
Source-valued scanner metadata is omitted; locations remain relative. Historical
snapshots cannot recover discarded columns/trace or scan-time file hashes.

### Locator, freshness and bounded reads

New SAST observations retain `technical_details.evidence_locator`: columns,
scanner fingerprint, file_sha256 and snapshot_reason. Existing Finding fields
provide relative path, line range, rule/scanner identity and finding fingerprint.
Safe file hashes are captured before and after the actual scanner invocation;
only equal successful hashes establish a scan-time revision. Failed auxiliary
evidence capture does not change findings, engine success or coverage.

`LocalEvidenceService` resolves that locator only on explicit detail/export
requests. It never writes source or local evidence to SQLite. It rejects absolute
and drive/UNC paths, traversal, Windows alternate streams, links and junctions;
checks canonical containment, regular-file type and opened file identity before
reading; and rechecks identity/revision/boundaries afterward. Limits: 1 MB per
file, 80 total excerpt lines, 0–20 nearby lines per side, 600 characters per line
and 24,000 excerpt characters. Binary/control-byte files and strict UTF-8 decode
failures fail closed with fixed reasons. No replacement-character decoding.

| evidence_status | Meaning |
|---|---|
| EXACT | Current full-file SHA256 equals the captured scan-time hash; original_evidence contains a redacted excerpt |
| STALE | File hash changed; original_evidence is null, current_context may contain the code at the old coordinates |
| MISSING | File/workspace was deleted; no excerpt |
| UNAVAILABLE | No historical revision proof, unsafe/unreadable/oversized/binary file, decode/range/budget failure, or intentional secret redaction |

Without historical revision proof, reason is SNAPSHOT_FINGERPRINT_MISSING.
Useful current_context can still be provided, explicitly separate from original
scanner evidence. It is not certified as the original match, and line movement
is not semantically relocated. Missing/range/read failures have explicit reasons.
Neither local evidence nor its live hash changes a quality observation hash,
finding identity or persisted review decision.

Secret details return only REDACTED_SECRET and do not read the source file.
Other excerpts scrub known secret ranges, credential values and recognizable
token/private-key formats before selecting a window. Source policy v2 retains
ordinary literals, comments, URLs and long identifiers; sensitive field names
remain visible while their credential values are hidden. Old tasks keep the
policy bound to their original baseline. Repository text is UNTRUSTED_CODE, not instructions. There is no
new source/sink inference, LLM invocation, suppression or code modification.

### Explicit access and private export

Existing `get_findings` defaults to its previous summary behavior. Request
`include_evidence=true`, optionally `finding_id=<existing scanner id>` and
`context_lines=5`, to receive additive `local_evidence`. It includes locator,
evidence_status/reason, original_evidence or current_context with matched_code,
context_before/after and relative line ranges. Existing workspace/scan binding
still applies; a finding ID outside that scan is rejected. No duplicate tool.

Regenerate the same stored corpus without a new scan or review mutation:

```sh
python scripts/finding_quality.py export --workspace . --scan <scan-id> --local-evidence
```

This explicit export writes bounded redacted context only to the existing
ignored private baseline directory, not to Finding storage or version control.
The report counts EXACT/STALE/MISSING/UNAVAILABLE, reasons, current contexts
and redacted secrets separately. An old corpus without hashes can have useful
current context while all original freshness remains unverified. Scanner FULL
coverage, evidence availability, precision and recall remain separate concepts.
The quality finding_id line-movement limitation remains; future Episode/semantic
correlation is independent work, not part of this evidence stage.
