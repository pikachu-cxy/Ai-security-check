# Risks and decisions

## Open local risk management

Ask **“Open risk statistics.”** Risk reports also include a link filtered to the current project, workspace and chat. The local service starts with the product; reading saved records does not rescan files.

The sidebar provides a dashboard, risks, projects/workspaces/chats, editors, settings and health monitoring. A project contains workspaces such as separate worktrees; chats belong to their workspace. Verified host chat names appear when available, with optional aliases. Resource management supports deletion and restoration with an explicit affected scope.

The dashboard separates scanner candidates from confirmed vulnerabilities and shows type counts and proportions. Counts represent saved records, not globally deduplicated vulnerabilities. Codex, Cursor and WorkBuddy records retain their origin. Details show paths, lines, available code, technical explanations, plain-language impact and repair advice. Batch decisions and SARIF/CSV/JSON export are available; an external security-platform adapter has not been selected.

## Chat reports

Reports include **prominent titles**, severity and source, location, problem, impact and advice. Separators distinguish multiple risks, and a chat risk-management link follows the report. Unreviewed candidates are labelled; dismissed false positives are summarized by count. Complete ordinary checks with no actionable risks remain quiet.

Use the latest whole-batch report returned after review submission, following additional reads only when the response requests pagination or continuation. Saved-result reads do not rescan. When business audit is enabled, it runs during development and saves its results for closeout.

## Decisions and repair

- **Fix:** authorize the selected issue and scope while preserving other behavior.
- **Defer:** save the decision to leave the issue for now, retaining its history.
- **False positive / exclude:** save the decision and rationale separately from the agent's technical judgment.

“Create/retry repair task” sends a request to the original development chat. An available coding agent performs the work; the web page does not edit source itself. An inactive chat leaves the request awaiting pickup.

## Checks after repair

Version 0.3.14 disables **additional post-repair verification** by default. Repair edits still enter ordinary static scanning and whichever candidate review/business audit settings are enabled. No separate repair rescan or business re-audit is automatically added.

Original risk history is retained. A clean ordinary scan does not automatically prove an old issue resolved. Request verification of the original risk explicitly, or enable the extra repair check in product settings when needed. Changing code does not replace rotation of exposed credentials.
