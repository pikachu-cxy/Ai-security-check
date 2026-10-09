# R2.2 security review contract

R2.1/1.1 is a separate committed baseline. R2.2 reuses Finding, quality review,
AI TriageRecord, task references and originating-scanner verification. No new
rule, maturity change, Runtime LLM pipeline or relaxed suppression gate.

## Evidence and validity

EvidenceBuilder and LocalEvidenceService share WorkspaceReader: canonical
workspace containment, no traversal/ADS/links/junctions, inode/revision checks,
1 MB file cap, binary rejection and strict UTF-8. Triage requires the scan's file
plan and existing packet/line budgets. Whole-file scrubbing precedes excerpt
selection, including multiline secrets. Fixed public constants survive only in
recognized MessageDigest/SSLContext.getInstance calls. Known secret lines and
credential assignments remain hidden. No credential value improves usability.

Packet local_evidence distinguishes EXACT/STALE/UNAVAILABLE and labels current
workspace context. Historical scans without a hash cannot become EXACT.
Changed scan-time revisions force NEEDS_REVIEW, including FP claims. Missing
evidence has fixed reasons; lexical references are not dataflow. Full-file keyed
revisions bind context_hash, including changes outside excerpts or hidden literals.
No raw secret or guessable secret-file revision hash enters triage storage.
triage-v0.2.0 makes old AI records stale. Scanner snapshots, identity and human
quality labels remain unchanged.

## Additive MCP options

Whole-project intent invokes `scan_project` (release), changes-only intent invokes
`scan_diff`, and explicit rescan never reuses history. Task continuation retains
the originally displayed task_ref. Summary adds `scan_context` with mode/time,
scope, actual files/languages, scanner execution and HMAC-bound source inventory
freshness, including zero-finding scans and newly untracked files. Quick/Hook FULL
is not a full-project verdict. Summary remains read-only and does not revalidate
engines or their DBs, so `full_project_reusable` is currently conservatively false.
Missing keys/old contexts/budget limits are UNKNOWN, not a reset or false current
claim. A conflicting Runtime is reported as not executed, not silently replaced.

| Existing tool | Options |
|---|---|
| scan_project / scan_diff | summary=true retains execution/coverage, omits candidates, returns findings access |
| get_findings | view=summary/page, offset, limit 1–50 (evidence 1–5), finding_id for one detail |
| prepare_triage | pending_only/retry_failed for resumable selection |
| prepare_task_triage | include_existing_reviews=false; same exact task_ref |
| submit_triage | compact=true returns counts, result access and continuation |
| get_triage | view=summary/page with bounded pagination |

Default complete shapes remain. Invalid bounds fail closed; detail IDs remain
scan/workspace bound. Generic continuation retains original IDs/categories; task
continuation retains task_ref. Handoffs stay expiring, bounded, connection-local
and context-validated. AI conclusions never redefine scanner coverage.

Official SDK wire envelopes for a 114-item **synthetic** corpus: complete findings
419,560 bytes, five summaries 7,485 (98.2% smaller); single legacy submission
43,534 bytes, compact 1,347 (96.9% smaller). These compare navigation workloads,
not equal-size full-corpus transfers. No accuracy or Desktop usability is inferred.

## Skill lifecycle

`review-skill` installs SKILL.md, UI metadata and a canonical reference generated
from HOST_INSTRUCTIONS. Live MCP supplies the same instructions. A signed sidecar
binds USER scope, Skill name/root identity, contract, Runtime version and exact
file hashes. Only these files may be updated/removed. User edits, extra files,
unattested name collisions and invalid ownership are preserved. Interrupted
updates retain signed old/new hashes for repair. Status is read-only.

Skill lifecycle is independent of Global MCP/Hook ownership. It never edits shared
Codex config, sibling MCPs, marketplaces, plugins or Host trust. Host activation
is separate from installation. Skill guidance is not authorization, suppression
or final security authority. See the [Windows checklist](WINDOWS_EXPERIENCE.md).
SDK protocol tests, real frozen scanner gates and Desktop acceptance are distinct.
