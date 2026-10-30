# Daily workflow

These instructions describe **0.3.11**. After [verifying installation](./verify.md), work in a chat opened at the actual project root.

## Temporary files and project source

Agents place disposable scripts, mock projects, logs, and temporary test fixtures in unique OS temporary directories outside the workspace. No user path configuration is required. Formal source, tests, and project configuration remain inside the project and subject to checks.

Agents can declare known outputs that must stay in the project. Explicit edits and tracked source take precedence; new untracked source remains subject to observation. Ambiguous files are not excluded by name. This is an agent behavior rule, not a process sandbox.

## Develop and check

```text
Add filename validation to the export feature, preserving its response format and
existing authorization checks. Check this task's recorded files and explain the
actual scope and any risks still requiring attention.
```

During editing, Hooks record paths without scanning or creating a project-wide baseline. At closeout, the Runtime scans the combined recorded files. The agent reviews candidates and security-relevant changes, reading related business logic when needed. Related reading does not expand static scan scope.

An ordinary development summary stays quiet when the recorded-file check is complete and no risk needs attention. An explicit request for check results returns the actual scope and state. File notifications describe activity in the task window, not proof of which process wrote a file.

## Select the scope

| Goal | Request |
| --- | --- |
| Connection only | “Query the build, components, and workspace path without scanning or editing.” |
| One file | “Check only `demo.py`; do not expand the scan scope.” |
| Saved result | “Read the original check and saved decisions without creating a check or rescanning.” |
| Project scan | “Scan this project and explain actual coverage; do not edit yet.” |
| Fresh execution | “Rescan the specified scope without reusing a saved scan.” |
| Strict diff audit | “Start a strict task before editing and review the complete workspace before/after difference.” |

Only explicit strict audits use the baseline workflow. A baseline cannot be reconstructed after editing. Ordinary chat, read-only queries, and ordinary Stop events do not start project scans. Pulling source does not upgrade an installed Runtime.

## Waiting and reconnecting

Closeout may continue in the background. Continue the same check after a wait timeout; do not create a replacement. Later edits need a new closeout on the same record. A saved read does not revalidate current disk contents.

Codex/Cursor Hooks supply session ownership so the original chat can read its checks after reconnecting. Users do not enter credentials and agents must not invent them. Verify reconnects by reading the original check and dispositions. Missing credentials or ownership mismatches require integration diagnosis while retaining the original reference.

## Components and partial coverage

The defaults are OpenGrep for code, Gitleaks for secrets, and Trivy for dependencies. OSV is not part of the default scan and is not an automatic fallback. Dependency scanning can be not applicable when no relevant manifest is selected.

Unreadable or excluded files, parser errors, unavailable components/data, and bounded analysis can limit coverage. Explain the actual file, capability, and reason. Not scanning unrelated project files is not itself a gap in a recorded-file check. Static execution and agent business-logic review remain separate facts.

See [preparation](./installation.md#manual-preparation). Dismissing candidates does not complete missing scan coverage.

## Decisions and saved statistics

Ask for impact analysis, authorize a specific fix, defer an issue, or provide exclusion evidence. Existing authorization for the same scope carries forward. Verification follows the original risk. [Risk handling](./risk-handling.md) covers local editor filters and aggregate statistics.

## Optional monitoring

In a supported Codex chat, ask “Start usage monitoring for this chat,” then export the report from the page. Chat tokens are not security-only tokens; uncertain attribution stays unknown. See [monitoring](./context-cost.md).
