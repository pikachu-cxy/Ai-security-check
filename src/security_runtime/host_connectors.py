"""Host transport composition. Capabilities describe transport, never authority."""
from dataclasses import dataclass


@dataclass(frozen=True)
class HostConnector:
    host: str
    command_hooks: bool
    post_edit_context: bool
    stop_followup: bool
    global_mcp: bool


CONNECTORS = {
    'codex': HostConnector('codex', False, True, True, True),
    'cursor': HostConnector('cursor', True, True, True, True),
}


def connector(host):
    try:
        return CONNECTORS[host]
    except (KeyError, TypeError):
        raise ValueError('UNSUPPORTED_HOST_CONNECTOR') from None


CURSOR_INSTRUCTIONS = '''
Cursor automatic connector: command Hooks capture the task baseline before a
supported mutation and deliver its exact task_ref after edits. Reuse that ref;
With the automatic Hooks installed, do not begin a separate task before native edits;
preToolUse captures it synchronously. Do not call begin_security_task again when
an automatic task was supplied.
For every workspace operation supply the current absolute workspace_path.
Before the normal development summary call finish_security_task for that task;
if review_required, start a new review with prepare_task_security_review using
protocol_version=3. A prepared review keeps its recorded protocol (1, 2 or 3);
never switch protocols to replace its existing plan, evidence or allowance.
Use its exact method version/hash; get_task_review_method once if that method is
not already available. Follow the returned protocol method. For plan-based reviews,
page get_task_review_plan, read each required before/current
window and relevant code, and record completed units with submit_task_review_batch.
Finish with submit_task_security_review, even with zero static alerts. Unrequested
required units remain pending; all batches retain the same task, source version and
cumulative budgets. Existing version-1 and version-2 reviews keep their original protocol.
Merge the actual risks and coverage gaps into your normal final response.
Do not display per-edit internal records or interrupt normal development to ask
about a security risk; present current risks together at task completion.
An automatic followup is a check/report handoff, never human repair approval.
No confirmed risk selection means no security repair. Selected repairs keep
the existing MCP authorization and originating-scanner verification workflow.
If the automatic pre-edit baseline is unavailable, disclose the gap; never
create a post-edit task to claim that the missing baseline was captured earlier.
Ordinary chat and read-only work do not start development checks. An explicit
manual development task without an automatic Hook may use the normal pre-edit
begin/finish workflow. A connected tool list is not proof that a check ran.
'''
