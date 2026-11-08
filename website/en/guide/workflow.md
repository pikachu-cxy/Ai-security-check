# Daily workflow

These instructions describe **0.3.14**. After [verifying installation](./verify.md), develop in a chat opened at the actual project root.

## From development to a report

```text
Add filename validation to the export feature, preserving its response format and
existing authorization checks. Use the configured product checks for this task's
recorded files and report risks requiring attention.
```

1. Hooks record edited paths; file watching supplements changes observed during the task. This does not establish a project-wide baseline or scan after every edit.
2. At closeout, scan the combined recorded files. Main and developer child-agent edits belong to the same main task; unchanged saved results are reused.
3. Candidate review is enabled by default; business audit is disabled by default. When enabled, a separate audit task handles incremental development changes and saves its results for closeout.
4. Save candidate judgments and deliver the product's whole-batch report and chat link. Complete, risk-free ordinary checks stay quiet; false positives are summarized, and real risks include details.

The two agent settings are independent. With both off, reports label static candidates as unreviewed. Reading related code does not expand static scan scope.

## Read-only chats, restart and waiting

Connection checks, explanations without edits, and saved-result queries can remain read-only. A read-only turn does not start a new scan of unfinished history. New edits after restart require a new input version; historical results do not establish current source state.

Stop waits up to 18 seconds per call by default; background work may continue afterward. Resume the original check instead of duplicating queued scans. The optional wait-for-result setting still respects host Hook limits and is not unlimited. Cancellation, missing host events and scanner failures retain their actual states. See [configuration](./configuration.md).

## Scope

Project source, configuration, dependency manifests and lockfiles are eligible. Dependency installation directories, compiled outputs and known temporary artifacts are filtered. Disposable agent scripts, synthetic projects and logs belong in unique temporary directories outside the workspace; formal tests remain inside it.

Default scanners are OpenGrep for code, Gitleaks for secrets and Trivy for dependencies. The native-dataflow/native-go-sql providers are retired. OSV is not an automatic fallback for Trivy. Dependency checking is not applicable when there are no applicable dependency inputs.

Completion refers to the recorded files. Not scanning the entire project is not an unknown-change warning. Actual scanner failures or changed input versions still require explanation. Full-project and Git-commit scans are not currently open.

## Repair and management

Ask to fix a selected issue, defer it, or explain why it is a false positive. Repair edits enter ordinary development checks; additional post-repair rescans and separate business re-audits are disabled by default. Original risk history remains; request original-risk verification explicitly when needed.

Risk reports include a chat link. “Open risk statistics” returns the local management link for details, decisions, exports, resources and settings. See [risks and decisions](./risk-handling.md).
