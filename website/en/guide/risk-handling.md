# Understand and handle findings

## Local risk statistics

With a Runtime build that supports this feature, ask **“Open risk statistics”** in chat to view locally retained project risk records. The dashboard is read-only: it does not scan, change dispositions, or start usage monitoring. Historical candidates may be duplicated or lack a current disposition, and records do not establish the state of current source code. The page reports incomplete reads. Check the actual published build for availability.

## Read the evidence

A useful finding identifies the location, concrete problem, trigger conditions, potential impact, existing safeguards, proposed fix, and remaining unknowns. A severity label does not replace this evidence.

Version 0.3.9 distinguishes unverified scanner candidates from risks assessed against code. Missing tools, stale data, and incomplete coverage are check states, not vulnerability findings or reasons to ask for a repair decision. Explanations follow the conversation language rather than requiring fixed headings.

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
