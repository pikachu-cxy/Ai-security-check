# Understand and handle findings

## Read the evidence

A useful finding identifies the location, concrete problem, trigger conditions, potential impact, existing safeguards, proposed fix, and remaining unknowns. A severity label does not replace this evidence.

## Choose a disposition

| Choice | Meaning |
| --- | --- |
| Fix | Authorize a specific issue and scope, without extending approval to unrelated modules. |
| Defer | Retain the finding and record without fixing it in this task. |
| Exclude | Record a false-positive assessment or explicit decision not to remind, with its rationale. |

User decisions and technical assessments are recorded separately. Deferral or exclusion is not proof of remediation.

## Assess impact before editing

You can ask: "Explain the affected interfaces, callers, and tests before fixing this issue. Do not edit code." This remains read-only. Unresolved execution-blocking assumptions should stay explicit.

## Verify the original issue

After an authorized fix, the agent should examine the original trigger and the new safeguard. Outcomes can be fixed, still present, or unverified. Ordinary passing tests or a fresh scan with no findings cannot replace original-issue verification.

History queries should not repeat disposition questions. For real exposed credentials, follow your incident-response and rotation process; deleting a value from code alone does not establish that exposure has been resolved.
