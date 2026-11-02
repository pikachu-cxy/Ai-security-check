# Local processing, network access, and privacy

## What stays in the Runtime

The Runtime runs on your computer and communicates with the host through local stdio MCP. Scanners process files locally. Edited paths, results, evidence, decisions, and verification records are stored in the user data directory and may include source context. Strict tasks also retain their baselines.

The host agent reads code for semantic analysis under its own model-provider and account policies. A local Runtime does **not** mean all code stays on the computer; it cannot make that promise for the host.

## Network access

Initial engine preparation, updates, and vulnerability data can require upstream services. Dependency-check network behavior depends on Trivy and the available vulnerability data. Do not assume a fully offline default. User-selectable online versus local vulnerability lookup remains planned rather than an available switch.

## Source evidence and redaction

Evidence retains ordinary strings, comments, field names, and URLs while masking recognized credential values such as passwords, tokens, and private keys. Recognition depends on supported patterns and cannot guarantee every unknown credential format is detected. Diagnostics have their own redaction rules.

New tasks use the current evidence policy; existing tasks retain their original policy and baseline. Version 0.3.12 preserves complete sanitized long lines for new tasks and fragments large responses. Upgrading does not recover characters already lost from historical evidence. If a hidden value affects the security judgment, its semantics remain unknown.

Version 0.3.12 also distinguishes pure variable references from credential-bearing template expressions and retains provenance for literal redaction markers in source. This reduces false hidden-change gaps for ordinary pattern constants. An upgrade cannot reconstruct missing historical provenance.

Protect local task databases, snapshots, backups, and shared-machine accounts according to the project's sensitivity. Do not commit runtime caches, private evidence, raw diagnostics, or credentials to Git.

## Usage monitoring

Usage monitoring is disabled by default. Existing local statistics are retained.

## Share minimal diagnostics

For support, provide only the necessary sanitized OS, editor, build, failure steps, and error. Do not submit real secrets, full private source, or raw chats. Unavailable data or tools must be reported as incomplete rather than represented as a clean result.
