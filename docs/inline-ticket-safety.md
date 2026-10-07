# P0-6 preparation feasibility review (before implementation)

The incoming P0-5 source is preserved in `.security-runtime/p06-review/incoming`; the A/B baseline is the hash-verified P0-5 wheel extracted without installation. Starting HEAD remains `ee1bfd9c12493683cc313cb3628753a51ae124ac`.

| Existing prepare responsibility | A: same initial Hook transaction | B: later action |
| --- | --- | --- |
| Bound workspace / no links / state outside source | Existing binding, snapshot and scope guards | No |
| Opaque task and remediation references | Retain the original grant arguments; `_reference` checks signed current Episode | No |
| Current Family / Episode / grant / original scan / membership | Signed workspace history and original TaskFix resolver | No |
| POLICY_AUTO authorization / current mode | `_allowed`, original policy decision and committed grant | No |
| Attempt budget / preparation budget | Existing persistent two-attempt budget and connection-local 32 preparations | No |
| Snapshot / target / source / other-file preservation | Existing `_snapshot`, `_guard`, bounded TaskFix preparation; repeat before attesting | No |
| Evidence, UNTRUSTED_CODE and context | Existing bounded preparation plus source-free context formatter | No |
| Prepared attestation | Existing connection-local `prepared` set; inline adds a bounded, expiring ticket | No |
| Expiry | Existing USER_CONFIRMED expiry; POLICY_AUTO previously has no preparation TTL. Inline ticket adds a monotonic 900-second lifetime, lost on restart | No |
| State / receipt dependency | Original grant is committed first; no resolved receipt is needed to prepare | Resolved receipt requires a later real scanner proof |
| USER_CONFIRMED approval | Not eligible for inline | Explicit user choice; retain legacy prepare |
| Actual edit freshness / post-edit preservation | Cannot be observed before edit by either old prepare or inline | Current Episode, target bytes, preservation, policy, snapshot stability and real scanner proof at verification |

All necessary *preparation* checks for the eligible POLICY_AUTO TLS case are A. The original `_prepare` will be reused, not bypassed. Later edit/proof checks remain B. Inline is restricted further to a single standalone whole-line removal whose resulting file bytes can be checked, and only when Fast Fix Host capability is unavailable. Ambiguous formatting retains prepare.

This is an ordinary Agent edit authorization, not `ATOMIC_BOUND_EDIT_V1`. Runtime does not write source, take a Host editor lock, infer Host identity from text, or prove which ticket a model read. An observed intervening/unexpected change invalidates the ticket; post-edit mismatch, scope drift, expiration, changed policy/Episode and lost connection attestation cannot close the Episode. A hidden edit-and-restore (ABA) between observations cannot be detected by the existing model, including legacy prepare. No stronger atomic guarantee is claimed.

The formal ticket belongs in MCP `structuredContent.remediation.agent_fix_ticket`; prose is advisory. A bounded Hook context projection can repeat this *same* object without re-encoding references. Official [Codex Hooks documentation](https://learn.chatgpt.com/docs/hooks) was fetched on 2026-10-05: MCP hooks use the command output contract, and oversized model-visible output can spill or truncate. It does not promise that arbitrary structuredContent is independently presented to the model. SDK transport integrity and text-loss tests do not constitute Desktop host visibility validation. No new Hook schema, input claims or configuration variables are invented.
