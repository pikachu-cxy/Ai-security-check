# Core P0-6.1: exact target verification review

Before product changes, incoming 168 files are preserved in `.security-runtime/p061-review/incoming`. HEAD remains `ee1bfd9c12493683cc313cb3628753a51ae124ac`.

The existing path is `FastFix.removal(raw UTF-8 bytes) → AgentFixTickets.offer → signed ticket → post_failure → whole-file SHA equality → original security recheck`. The plan records the original whole-file SHA, snapshot and one canonical result SHA. Fast Fix calculates a whole-line byte range and segment SHA, but the Agent Ticket drops them. The post-edit gate accepts only that single result SHA; it cannot distinguish a legal statement/empty-line operation from unrelated edits.

Read-only Desktop evidence: the risk patch adds one 8-space-indented TLS statement and one following empty line; the repair patch removes both, without other changed lines in the recorded patch. The current file has UTF-8 BOM and mixed EOLs. The old canonical result would retain the following empty line. The complete old Ticket/raw pre-image was not captured; reconstructed SHA/offset diagnostics in `inline-exactness-forensic.json` are explicitly labelled assumptions, not original credential values. No old opaque refs are used, no message is sent to the trial chat, and no trial source is edited/copied/persisted. This is forensic inspection, not a new Desktop E2E.

| Candidate cause | Evidence / treatment |
| --- | --- |
| Whole-file versus bounded-edit contract | Confirmed design mismatch: one fixed whole-line result excludes the recorded following-empty-line cleanup |
| Surrounding blank line / replacement semantics | Recorded repair removes risk line and exactly one following empty line |
| CRLF/LF and BOM | Current file is mixed EOL + UTF-8 BOM; old raw-byte helper does not normalize either. Independently test LF/CRLF/mixed/BOM and reject changes outside the envelope |
| Byte range / pre-post-image / constructor error | Old helper uses raw decode without universal-newline conversion, encodes offsets from the same original string, and constructs deletion from original bytes. No constructor/offset bug established |
| Indentation / trailing whitespace | Only exact original whitespace in the authorized line can be retained; no arbitrary new whitespace |
| Line/range drift, stale snapshot, unexpected neighboring edits | Remain rejection cases; no scanner absence can override them |

The new envelope is derived from the **same** raw bytes as the existing removal plan. It contains the statement's entire physical line and, only when present, one immediately following truly empty LF/CRLF line. It never includes neighboring code, comments, an indented blank line or a second empty line. Prefix and suffix SHA/length establish byte identity outside this explicit range. The original segment/statement hashes and up to three precomputed segment/result hashes are signed into the existing Ticket.

Enumerated results: (1) remove only the whole risk line, retaining the original following empty line; (2) remove only the statement text, retaining exactly its original whitespace/EOL and following empty line; (3) optionally remove the single following empty line as well as the whole risk line. Duplicate byte results are collapsed. No post-edit whitespace normalization, formatter tolerance, approximate diff, fuzzy match or semantic-equivalence model is used. Hashes/counts/EOL/BOM/reasons may leave Runtime; source bytes and byte diffs may not.

The top-level `TICKET_TARGET_NOT_EXACT` remains compatible. Add bounded subreasons for outside-envelope, line-ending/encoding identity, unexpected envelope result, range drift and result-hash mismatch. Signature/ref/Episode/policy/TTL/snapshot/source/preservation checks and the original **real scanner** recheck remain mandatory. Legacy tickets without an envelope keep their strict original single-result check. Security Context, Fast Fix, timing, receipt, scanner/cache, Functional/BOM and CET implementations are not changed. No prepare RPC is added to the inline path.

Hidden edit-and-restore between observations remains unobservable, as in P0-6; this is an Agent post-validation contract, not an atomic editor bridge. Desktop re-trial remains user-run after local gates; no new stage begins.
