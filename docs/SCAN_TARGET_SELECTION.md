# Scan target selection and discovery failures

Release scans support a source directory without Git. Git-backed quick/hook
scans keep their existing scope and workspace binding. The default recursive
discovery limits remain 10,000 files, 2,000 directories, 12 levels and
1,000,000 bytes per admitted file.

## Unsupported binary documents

Target selection identifies a narrow set of document, image and font formats
using both their extension and up to 16 magic bytes. Office/OpenDocument ZIP
documents, PDF, PNG/JPEG/GIF/BMP/ICO and WOFF fonts are excluded because the
Runtime currently has no analyzer for their contents. A plain-text file renamed
`.docx` is still admitted. Arbitrary text, dotfiles such as `.env`, manifests,
archives and JARs are not excluded by this policy.

Workspace canonicalization and symlink/junction rejection happen before magic
bytes are read. Source, configuration and dependency inputs still fail closed
when they exceed the configured file-size limit. Detection rules, maturity,
triage gates and FULL/PARTIAL computation are unchanged.

Every excluded document is recorded in the private scan snapshot as a relative
path, reason, selection source and size. No document content is copied. CLI JSON
retains the complete `target_profile.skipped_files` ledger. MCP scan responses
and security summaries expose `target_selection`, with counts and at most 20
entries; human scan output reports the exclusion count. Exclusion is not a clean
finding. FULL describes successful execution for the declared eligible scope,
not inspection of excluded document contents or support for every language.

Semgrep-reported skipped targets also reduce applicable-rule execution proof,
even when the target occurs in `paths.scanned`. Bounded skip reasons appear in
rule coverage; raw scanner details are not copied into this diagnostic.

## Hook comparison baselines

Git and ordinary-folder Hook snapshots now use this same binary document policy.
They retain bounded exclusion diagnostics, and a document changed into plain
text becomes eligible again. Relevant oversized text still prevents capture.

A comparison baseline may be READY while its code coverage remains PARTIAL or
NOT_COVERED: recognized inputs such as Vue components have no applicable rules.
This is allowed only when every selected rule and supported target has explicit
successful engine evidence and every other requested quick capability completed.
Localized parser gaps are retained per file: later risks in those paths have
unconfirmed edit attribution and cannot trigger automatic repair. Unscoped errors,
engine skips, missing rule execution, failed or
unavailable tools, moving source and resource limits still prevent readiness.
Readiness exposes baseline coverage/capabilities and security_proof=false.
Unsupported files cannot establish risk absence or automatic repair authority.
Vue SFC code analysis remains unsupported; this change restores supported-file
checks without relabeling the whole project as fully covered.

Baseline SAST batches admit at most 128 selected files with a 16,000 UTF-16-unit
target-argument budget. Normal edit batches retain the 40-file cap. This reduces
engine startup overhead while preserving exact target scope, per-file/rule
evidence, output bounds and the 60-second baseline deadline. Deadline failures
report BASELINE_DEADLINE_EXCEEDED rather than an ambiguous coverage failure.

## Failure contract

An oversized admitted input returns `TARGET_FILE_SIZE_LIMIT_EXCEEDED` and a
bounded relative path. Other discovery resource limits return
`TARGET_DISCOVERY_LIMIT_EXCEEDED`. Both report `failure_stage=TARGET_DISCOVERY`,
`coverage=UNKNOWN`, `scanner_run=false` and `security_proof=false`. CLI JSON exits
2. MCP returns the same diagnostic instead of masking it as a workspace binding
failure. No completed scan snapshot is fabricated.

`integration status codex --scope global` uses Global Codex status even in a
non-Git source directory. Legacy project status still requires its project
binding. An OS-level Global state access failure reports
`GLOBAL_STATE_ACCESS_FAILED`; it does not prove an ownership/configuration
conflict. Signed semantic ownership validation remains unchanged.

## Verification boundary

Synthetic regressions cover oversized documents, retained credential text,
oversized relevant files, workspace escapes, persistence, freshness, CLI/MCP
failure diagnostics, and scanner-reported skip evidence. The standalone verifier
also includes a real oversized DOCX and a separate oversized source input.
Native MCP SDK acceptance is protocol evidence; it is not Codex Desktop restart
acceptance. A running Desktop MCP must use the updated installed build before
its real user scan can validate this fix.
