# Smart Auto-Remediation

Remediation is evidence- and policy-gated. The maintained contract is:

```text
Finding → Family / Episode → policy decision → INLINE_PREPARED or guidance
→ Exact Edit Envelope → real scanner proof → CLOSED
```

`INLINE_PREPARED` prepares a narrow, deterministic edit transport; it is not
proof by itself. The Runtime validates workspace/session binding, scope,
preservation guards, authorization, opaque references, receipts, and the
post-edit scanner result. Recurrence and Episode budgets prevent repeated
unsafe actions.

Only a narrow deterministic fix may be eligible for `AUTO_FIX`. The CORE grade
does not itself grant fix permission, and VALIDATED capabilities currently
provide detection/guidance rather than automatic fixing. Agent prose cannot
create authorization or replace scanner proof.

Host capability is a separate boundary. Codex's observed Global Runtime path
supports the verified inline/envelope/proof loop. Cursor currently supports
advisory remediation on the observed path; Native Chat Feedback is
`HOST_CAPABILITY_UNAVAILABLE_ON_OBSERVED_PATH` and Automatic Continuation is
`PENDING_HOST_CAPABILITY`.
