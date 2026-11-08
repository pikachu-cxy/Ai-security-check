"""Host transport composition. Capabilities describe transport, never authority."""
from .host_lifecycle import HostConnector, connector_profile


CONNECTORS = {
    host: connector_profile(host).connector for host in ('codex', 'cursor', 'workbuddy')
}


def connector(host):
    try:
        return CONNECTORS[host]
    except (KeyError, TypeError):
        raise ValueError('UNSUPPORTED_HOST_CONNECTOR') from None


CURSOR_INSTRUCTIONS = """
Cursor automatic connector uses command Hooks to record observed edit paths.
Ordinary development does not capture a full-project baseline and does not need
begin/finish tool calls. Stop closes the current batch. Follow the session's
compact check reference using development_review/get_development_risks with
view=closeout. Only REVIEW permits review submission; REPORT and INCOMPLETE
must deliver the saved report_text and session_url without scans or polling.
Read-only work and zero-candidate successful checks stay silent.
Always supply the current absolute workspace_path and the Hook's session_ref.
Tool discovery uses grouped operations; raw operation aliases remain compatible.
Business audit runs during development only when enabled: a fresh native child
per round, reused within the round, receiving the complete child_call and saving
through MCP itself. Missing host child/MCP support must remain unsupported, never
claimed complete or silently replaced with serial parent audit.
Explicit strict security tasks retain their existing version-3 protocol and exact
task_ref: finish_security_task, prepare_task_security_review, evidence units,
submit_task_review_batch and submit_task_security_review. Do not create or migrate
such tasks for ordinary observed-file checks, or invent a post-edit baseline.
A followup is a check/report handoff, never human approval to repair a risk.
"""
