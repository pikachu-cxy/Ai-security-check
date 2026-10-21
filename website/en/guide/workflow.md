# Daily workflow

After [verifying the installation](./verify.md), describe your development task in the project chat. Full integration brings check results into the task summary; manual MCP requires an explicit check request.

## Develop and review the change

```text
Add filename validation to the export feature while preserving its response format
and existing authorization checks. Afterward, check this change and explain the
findings, actual coverage, and anything incomplete.
```

The agent should capture the actual workspace before editing, including existing uncommitted changes, then check the current changes and necessary related code. You do not need to commit first. Pulling source follows the same change accounting and does not upgrade a separately installed Runtime.

## Check existing code

```text
Review the upload and download modules, focusing on path boundaries and authorization.
Explain the risks and actual scope. Do not modify code yet.
```

Specify individual files when appropriate. A file-scoped request should retain that scope and distinguish requested files, actual targets, supporting configuration, and exclusions.

## Reuse, progress, and review evidence

Repeated full-project checks can reuse a prior complete result only after verifying source inventory and contents, rules, engines, configuration, and vulnerability-data identity and validity. Changed or unverified evidence requires a new scan. Explicitly request a rescan when you want new execution; history queries do not automatically rescan.

Hosts supporting MCP progress notifications can show phases. Runtime duration excludes host-model reasoning, queues, and human decisions. Scan-result reuse neither replaces contextual review nor authorizes a fix.

Version 0.3.9 preserves full sanitized long lines for new tasks and fragments large responses. All characters must be delivered before a line counts as read. File, storage, and transfer budgets remain; lost historical evidence is not reconstructed.

## Choose how to handle a finding

| Intent | Example reply |
| --- | --- |
| Assess impact only | "Explain which callers and interfaces this fix would affect. Do not edit." |
| Fix a specific issue | "Fix this path traversal issue, preserve authorization checks, and verify the original finding." |
| Defer | "Keep this finding on record and handle it later." |
| Supply exclusion evidence | "The entry already has these checks; verify and record the exclusion rationale." |

See [handling findings](./risk-handling.md). Verification follows the original issue rather than replacing it with a new zero-finding task.

## Optional monitoring

In a supported Codex chat with Runtime 0.3.9, ask **"Start usage monitoring for this chat."** Finish with the page's stop-and-export control. Chat token totals, observation duration, and associated tool time are different measures. Development-only and security-only tokens remain unknown when they cannot be separated reliably. See [monitoring](./context-cost.md).

## Recognize completion

The summary should distinguish the development result, check coverage and gaps, findings needing a decision, and verification of approved fixes. Continue the original chat after interruption so the same task and evidence can be resumed.

**PARTIAL** means some scope could not be confirmed, such as missing source, pre-edit evidence, relevant redacted semantics, or an exhausted budget. It does not mean a vulnerability was found. Scanner scope and code actually read by the agent are separate facts; passing tests or zero static alerts do not replace unfinished review.
