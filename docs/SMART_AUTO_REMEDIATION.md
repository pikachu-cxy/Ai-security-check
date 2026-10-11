# Smart Auto-Remediation

As of the 2026-10-11 local source change, ALL vulnerability repairs require
explicit user approval. The title and AUTO_FIX enum are retained for compatibility;
neither a policy setting nor scanner confidence can create consent.
Default mode is ask_before_fix; old smart_auto settings normalize to it.
The maintained contract is:

```text
Finding → Family / Episode → explain risk and scope → explicit user approval
→ policy/freshness checks → INLINE_PREPARED or guidance
→ Exact Edit Envelope → real scanner proof → CLOSED
```

`INLINE_PREPARED` prepares a narrow, deterministic edit transport; it is not
proof by itself. The Runtime validates workspace/session binding, scope,
preservation guards, authorization, opaque references, receipts, and the
post-edit scanner result. Recurrence and Episode budgets prevent repeated
unsafe actions.

Only an already approved narrow repair may continue as `AUTO_FIX`. A selected
task request such as “fix this issue” is consent and need not be asked twice.
Ambiguous requests to continue or handle an issue are not repair consent;
clarify the intended repair before editing.
Detection, a scan request, severity, maturity and ordinary development requests
are not consent. No reply or rejection means no vulnerability edits. Changed
scope, expired authorization, a new episode or new session requires a fresh
decision. Old POLICY_AUTO grants fail closed. A confirmation boolean over MCP
is an explicitly marked untrusted host report, not cryptographic human evidence;
the host must never fabricate it. Agent prose cannot replace scanner proof.

Host capability is a separate boundary. Codex's observed Global Runtime path
supported the historical verified inline/envelope/proof loop; this new consent
flow still needs fresh Desktop acceptance. Cursor currently supports
advisory remediation on the observed path; Native Chat Feedback is
`HOST_CAPABILITY_UNAVAILABLE_ON_OBSERVED_PATH` and Automatic Continuation is
`PENDING_HOST_CAPABILITY`.
