# Scan target selection and discovery failures

Release scans support a source directory without Git. Git-backed quick/hook
scans keep their existing scope and workspace binding. The default recursive
discovery defaults are 10,000 files, 2,000 directories, 32 levels and
1,000,000 bytes per admitted file.

## User configuration

Discovery reads the optional user-owned `scan-limits.toml` in the Runtime state
directory on each operation. On macOS/Linux the default is
`~/.local/state/ai-security-runtime/scan-limits.toml`; `XDG_STATE_HOME` or
`SECURITY_RUNTIME_STATE_DIR` changes the state location. On Windows the default
is `%LOCALAPPDATA%/AI Security Runtime/scan-limits.toml` when LOCALAPPDATA is set.
No configuration is loaded from the scanned repository or current directory.
Use `SECURITY_RUNTIME_SCAN_LIMITS_FILE` to select a different absolute file path;
an explicitly selected missing file is an error, not a fallback to defaults.

```toml
[discovery]
max_depth = 32
max_files = 10000
max_directories = 2000
max_file_size = 1000000
```

The existing `SECURITY_RUNTIME_MAX_DEPTH`, `SECURITY_RUNTIME_MAX_FILES`,
`SECURITY_RUNTIME_MAX_DIRECTORIES` and `SECURITY_RUNTIME_MAX_FILE_SIZE` environment
variables override the corresponding file values. Explicit internal constructor
arguments take precedence over environment values; built-in defaults have the
lowest priority. Values must be positive integers; zero does not disable limits.
Unknown TOML keys, invalid values, unreadable files, invalid UTF-8/TOML and files
over 65,536 bytes return `TARGET_DISCOVERY_CONFIG_INVALID` before scanner
execution. Diagnostics do not echo raw configuration values or file contents.

The project root has directory depth 0 and counts as one directory. A file at
depth 32 is accepted by default; an eligible child directory at depth 33 fails.
Generated/vendor directory exclusions are applied before recursive limits.
File-count discovery includes discovered file entries before content-based
binary-document exclusions. An explicit file selection is not subject to the
recursive depth limit. These settings do not override separate Hook/task
snapshot, provider, evidence-delivery, memory or timeout budgets.

For CLI use, set the variables in the invoking environment. For an already
running MCP server, environment changes require reconnecting/restarting that
server; editing the user TOML takes effect when the next operation creates its
detector. Configuration changes do not widen or resume an in-flight scan.

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
`TARGET_DISCOVERY_LIMIT_EXCEEDED`, retaining compatibility while distinguishing
the resource through `limit_kind` (`max_files`, `max_directories`, `max_depth`
or `max_file_size`). Failures include a bounded, sanitized `message` and `detail`,
the configured `limit`, an `observed` count or size, the triggering relative path
when available, and actionable `configuration` / `remediation` fields. Recursive
enumeration stops early: `observed_is_lower_bound=true` explicitly means the
observed value is not a completed project total. An explicit file list count or
single-file byte size is exact. No arbitrary first-N subset is scanned, no
automatic retry raises a limit, and no partial scan is presented as complete.

Discovery-limit and configuration failures report `failure_stage=TARGET_DISCOVERY`,
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
