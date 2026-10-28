# Local processing, network access, and privacy

## What stays in the Runtime

The Runtime runs on your computer and communicates with the host through local stdio MCP. Scanners process files locally. Edited paths, results, evidence, decisions, and verification records are stored in the user data directory and may include source context. Strict tasks also retain their baselines.

The host agent reads code for semantic analysis under its own model-provider and account policies. A local Runtime does **not** mean all code stays on the computer; it cannot make that promise for the host.

## Network access

Initial engine preparation, updates, and vulnerability data can require upstream services. Dependency-check network behavior depends on Trivy and the available vulnerability data. Do not assume a fully offline default. User-selectable online versus local vulnerability lookup remains planned rather than an available switch.

## Source evidence and redaction

Evidence retains ordinary strings, comments, field names, and URLs while masking recognized credential values such as passwords, tokens, and private keys. Recognition depends on supported patterns and cannot guarantee every unknown credential format is detected. Diagnostics have their own redaction rules.

New tasks use the current evidence policy; existing tasks retain their original policy and baseline. Version 0.3.10 preserves complete sanitized long lines for new tasks and fragments large responses. Upgrading does not recover characters already lost from historical evidence. If a hidden value affects the security judgment, its semantics remain unknown.

Version 0.3.10 also distinguishes pure variable references from credential-bearing template expressions and retains provenance for literal redaction markers in source. This reduces false hidden-change gaps for ordinary pattern constants. An upgrade cannot reconstruct missing historical provenance.

Protect local task databases, snapshots, backups, and shared-machine accounts according to the project's sensitivity. Do not commit runtime caches, private evidence, raw diagnostics, or credentials to Git.

## Usage monitoring is separate

Generic monitoring stores tool counts, bytes, timing, limited counters, and opaque identity metadata. Retention is up to 14 days and 10,000 call events. It excludes source code, prompts, tool arguments, response bodies, raw session identifiers, and project paths, and does not upload statistics.

When you start current-chat monitoring, verified session identity is used to match bounded local log metadata and read usage counts. Missing or ambiguous identity does not select another chat. Manual imports read only the chosen file. Raw JSONL may contain project content and should be protected separately; exported reports exclude message bodies, source, log paths, and raw identity.

Monitoring can stop, fail, or be omitted from a source distribution without changing core scans, review, or authorization. Keep managed packages intact. See [monitoring details](../guide/context-cost.md).

## Share minimal diagnostics

For support, provide only the necessary sanitized OS, editor, build, failure steps, and error. Do not submit real secrets, full private source, or raw chats. Unavailable data or tools must be reported as incomplete rather than represented as a clean result.
