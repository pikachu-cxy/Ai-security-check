# Understand and handle findings

## Local risk statistics

Ask **“Open risk statistics.”** Version 0.3.10 offers **All editors / Codex / Cursor** filters, plus project, disposition, and text filters. Summary cards and project distribution follow the selected filters.

The page reads saved records in the current operating-system user's local data directories, not only the current chat and not every device or account. Confirmed pending risks, unconfirmed candidates, deferred/excluded items, and reviewed resolutions are separate. Raw scanner counts are not confirmed vulnerability counts.

Records keep their editor identity and disposition. The same issue saved by both editors may count twice; this stage does not merge or deduplicate across editors. Read limits and inaccessible data are reported. Zero records alone does not prove project security.

Viewing is read-only: it does not scan, change decisions, or start usage monitoring. Historical records do not establish current disk state.

## Read the evidence

A useful finding identifies the location, concrete problem, trigger conditions, potential impact, existing safeguards, proposed fix, and remaining unknowns. A severity label does not replace this evidence.

Version 0.3.10 distinguishes unverified scanner candidates from risks assessed against code. Missing tools, stale data, and incomplete coverage are check states, not vulnerability findings or reasons to ask for a repair decision. Explanations follow the conversation language rather than requiring fixed headings.

## Choose a disposition

| Choice | Meaning |
| --- | --- |
| Fix | Authorize a specific issue and scope, without extending approval to unrelated modules. |
| Defer | Retain the finding and record without fixing it in this task. |
| Exclude | Record a false-positive assessment or explicit decision not to remind, with its rationale. |

User decisions and technical assessments are recorded separately. Deferral or exclusion is not proof of remediation.

Existing explicit authorization for the same issue and scope carries forward without another choice. "Do not edit yet" alone does not establish that a deferral or exclusion was saved. Saved deferred or excluded items should not prompt again on every query.

## Assess impact before editing

You can ask: "Explain the affected interfaces, callers, and tests before fixing this issue. Do not edit code." This remains read-only. Unresolved execution-blocking assumptions should stay explicit.

## Verify the original issue

After an authorized fix, the agent should examine the original trigger and the new safeguard. Outcomes can be fixed, still present, or unverified. Ordinary passing tests or a fresh scan with no findings cannot replace original-issue verification.

History queries should not repeat disposition questions. For real exposed credentials, follow your incident-response and rotation process; deleting a value from code alone does not establish that exposure has been resolved.
