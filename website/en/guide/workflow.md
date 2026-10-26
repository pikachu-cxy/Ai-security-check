# Daily workflow

This page describes the **current 0.3.9 release**. After [verifying installation](./verify.md), describe your task in a chat opened at the actual source root. Full Codex / Cursor integration brings check results into the task summary; manual MCP requires an explicit check request. Version history belongs in the [changelog](../reference/changelog.md).

## Start your day

Open the source and Git repository root rather than an outer extraction folder. Restart the editor and verify the connection after installation or upgrades. Routine work does not require reinstalling or scanning the entire project first.

| Goal | Example request |
| --- | --- |
| Develop | "Implement this change and report its check coverage and gaps." |
| Query status | "Only query the connection, actual build, components, and project path. Do not scan or edit." |
| Review existing code | "Check only the upload module, explain risks, and do not edit yet." |
| Read saved results | "Show the previous check and saved decisions without rescanning." |
| Force a new scan | "Rescan this project without reusing the old result. Do not edit code." |

`NEEDS_SCAN` means no project scan has been recorded. `READY` describes available components. Neither state is a passing project check.

Current development builds use **AI development task auditing**. Startup and new chats validate connection, configuration, workspace binding, and signed routing without creating product comparison baseline A or inventorying/scanning project sources. A is explicitly not required. Scanner and vulnerability-data readiness are reported independently; a connected session does not claim that they are ready.

Capture B before the task's first edit and seal C at closeout. Audit the entire actual B-to-C workspace difference and necessary related code, configuration, and dependency effects. Include manual edits, other editors' changes, untracked files, deletions, and both paths of a rename. Scanning and source review bind the same C. Worktrees and independent copies keep separate versions and results. Unknown authorship or overlapping task windows alone do not downgrade new audits; permissions, signatures, cancellation, publication checks, and real evidence gaps still apply.

A completed Hook only means its handler returned. Recorded edit activity may await closeout without running a scanner. Missing B, unavailable original source, failed scans, and version mismatches remain explicit gaps. Historical results and old unknown log states are never upgraded or reconstructed automatically.

## Develop and review the change

```text
Add filename validation to the export feature while preserving its response format
and existing authorization checks. Afterward, check this change and explain the
findings, actual coverage, and anything incomplete.
```

The agent should capture the actual workspace before editing, including existing uncommitted changes, then check the current changes and necessary related code. Required source windows must be read and each review unit submitted before completion. You do not need to commit first. Pulling source follows the same change accounting and does not upgrade a separately installed Runtime. Ordinary chat, read-only queries, and unchanged tasks should not start a project scan.

## Check existing code

```text
Review the upload and download modules, focusing on path boundaries and authorization.
Explain the risks and actual scope. Do not modify code yet.
```

Specify individual files when appropriate. A file-scoped request should retain that scope and distinguish requested files, actual targets, supporting configuration, and exclusions.

## Reuse, progress, and review evidence

Repeated full-project checks can reuse a prior complete result only after verifying source inventory and contents, rules, engines, configuration, and vulnerability-data identity and validity. Changed or unverified evidence requires a new scan. Explicitly request a rescan when you want new execution; history queries do not automatically rescan.

Hosts supporting MCP progress notifications can show phases. Runtime duration excludes host-model reasoning, queues, and human decisions. Scan-result reuse neither replaces contextual review nor authorizes a fix.

### Unavailable components

Version 0.3.9 distinguishes missing tools, unverifiable execution identity, missing databases, expired data, and an unknown update time. Check [preparation status](./installation.md#preparation), retain the component's diagnostic, and retry the same scope after addressing it. An incomplete check alone is not a reason to reinstall or clear caches. Online preparation can create a separate managed Semgrep when an automatically discovered system tool cannot be verified; explicitly selected paths still need attention.

## Long lines and review coverage

Version 0.3.9 preserves full sanitized long lines for new tasks and fragments large responses. All characters must be delivered before a line counts as read. File, storage, and transfer budgets remain; lost historical evidence is not reconstructed.

## Choose how to handle a finding

| Intent | Example reply |
| --- | --- |
| Assess impact only | "Explain which callers and interfaces this fix would affect. Do not edit." |
| Fix a specific issue | "Fix this path traversal issue, preserve authorization checks, and verify the original finding." |
| Defer | "Keep this finding on record and handle it later." |
| Supply exclusion evidence | "The entry already has these checks; verify and record the exclusion rationale." |

Scanner candidates are checked against code before their impact is confirmed. Explanations retain locations, conditions, safeguards, and unknowns. Existing authorization for the same issue and scope carries forward; a fixed reply phrase is not required. See [handling findings](./risk-handling.md). Verification follows the original issue rather than replacing it with a new zero-finding task.

## Optional monitoring

In a supported Codex chat with Runtime 0.3.9, ask **"Start usage monitoring for this chat."** Finish with the page's stop-and-export control. Chat token totals, observation duration, and associated tool time are different measures. Development-only and security-only tokens remain unknown when they cannot be separated reliably. See [monitoring](./context-cost.md).

## Recognize completion

The summary should distinguish the development result, check coverage and gaps, findings needing a decision, and verification of approved fixes. Continue the original chat after interruption so the same task and evidence can be resumed.

**PARTIAL** means some scope could not be confirmed, such as missing source, pre-edit evidence, relevant redacted semantics, or an exhausted budget. It does not mean a vulnerability was found. Scanner scope and code actually read by the agent are separate facts; passing tests or zero static alerts do not replace unfinished review.

For installation maintenance, see [upgrades and removal](./installation.md#uninstall). Keep component caches and original task records during routine use.
