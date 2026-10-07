# P0-9 Cursor Host Adapter v1 — mapping before implementation

Official contracts checked 2026-10-06: [Hooks](https://prod.cursor.com/docs/hooks), [MCP](https://cursor.com/docs/mcp). The official Hook inventory includes lifecycle, file/shell/MCP, generic tool, subagent, prompt/compaction, response/thought, Tab and workspaceOpen surfaces. This iteration selects four local Agent events only. No cloud/remote support is claimed.

| Cursor raw event | Normalized event | Operation | Documented output used |
| --- | --- | --- | --- |
| sessionStart | SESSION_START | UNKNOWN | additional_context, bounded status only |
| afterFileEdit | WORKSPACE_ACTIVITY | DIRECT_FILE_MUTATION | {} |
| afterShellExecution | WORKSPACE_ACTIVITY | existing shell classifier | {} |
| stop | SESSION_STOP | UNKNOWN | {}; no automatic followup |

User hooks live in `~/.cursor/hooks.json`; project hooks live in `<project>/.cursor/hooks.json`. Native command Hooks exchange stdin/stdout JSON. Relative user commands run from the config directory, so the generated launcher uses an absolute executable. Config reload is Host-managed. Runtime does not infer Desktop delivery from installation. Windows command launch and paths with spaces must be tested with the installed candidate in a temporary config root.

Claims: conversation_id is the session namespace, generation_id is required as the documented generation claim, sessionStart session_id must equal conversation_id. One workspace_roots entry is admitted using the existing canonical resolver; CURSOR_PROJECT_DIR, when provided, must resolve to the same root. File events require an absolute contained non-link file, and reject nested-repository cross-root attribution. Session/root bindings persist as hashes with HMAC integrity, bounded to 64 sessions/16 roots and never evict an active binding to silently rebind it. Remote workspaces fail closed. This is claim consistency, not cryptographic authentication.

These four official event schemas do not guarantee a per-invocation ID. `supports_invocation_id=false`; no Codex turn/tool-use ID is fabricated. A locally issued persistent sequence is diagnostic bookkeeping, not Host identity. Repeated deliveries converge via the existing filesystem digest, cooldown and single-flight; exact Host replay detection cannot be claimed. Multi-root attribution is unsupported rather than guessed.

Transport: Cursor command → installed Python/frozen CLI `cursor-hook` → CursorHostEventAdapter → NormalizedHostEvent → existing dispatch → HookCoordinator. The adapter never runs payload command text or reads transcript/output/edit strings. Session bootstrap uses existing bounded baseline capture with an explicit Host namespace. Publication and repeated-session preservation retain the same workspace lock and byte recheck. Missing startup baseline keeps first-edit attribution unavailable.

Continuation: Cursor documents Stop followup, but neither selected post-event documents Agent context delivery. A command process also cannot transfer an existing connection-local prepared Ticket or authorization into an independently connected MCP service. This iteration uses existing report_only remediation policy for the transport, never changes user policy config, never grants a source writer, and explicitly reports PENDING_CURSOR_CONTINUATION_CAPABILITY. Finding/Policy/Family scanning is reusable; automatic Agent Fix/Ticket/receipt/closed-loop equivalence is not claimed. Native MCP has separate user/project mcp.json; this installer leaves both untouched. Existing Codex MCP and legacy project command adapters remain compatible.

Global installer: signed ownership records identify exact generated definitions; safe merge preserves custom Hooks, prompt Hooks, unknown JSON fields and all MCP settings. Missing owned entries can be repaired; modified/unowned lookalikes and ambiguous duplicate entries fail closed. Healthy setup/repair preserve config bytes, not just values. Config updates use atomic writes and a compare-before-write check. No source path/PYTHONPATH is installed; editable development requires explicit opt-in, and loading a candidate remains the user's later choice.

Recent diagnostics reuse the existing SQLite journal (32/workspace, 1024 total), with a closed Cursor event/schema/tool vocabulary plus normalized fields. Only safe hashes/booleans/enums/counts persist; no raw identity, command, tool output, edits, source, transcript or tokens. The same independent read-only `hooks recent` command reads it across process/restart.

P0-7/P0-8 Desktop verification is user-reported evidence. Cursor real Desktop E2E is not performed in this iteration. No real .cursor/.codex writes, active Runtime replacement, commit or push.
