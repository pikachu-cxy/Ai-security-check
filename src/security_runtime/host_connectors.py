"""Host transport composition. Capabilities describe transport, never authority."""
from .host_lifecycle import HostConnector, connector_profile


CONNECTORS = {
    host: connector_profile(host).connector for host in ('codex', 'cursor')
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
protocol_version=3, the only executable development review protocol. First verify
the v3 capability and all required task tools in the main instructions; otherwise
request a Runtime upgrade and stop the review. Older tasks remain read-only; never
migrate them, rebuild their baseline or reset existing evidence or allowances.
Use its exact method version/hash; get_task_review_method once if that method is
not already available. Use only the v3 method;
page get_task_review_plan, read each required before/current
window and relevant code, and record completed units with submit_task_review_batch.
Finish with submit_task_security_review, even with zero static alerts. Unrequested
required units remain pending; all batches retain the same task, source version and
cumulative budgets. Version-1 and version-2 history cannot resume.
Merge the actual risks and coverage gaps into your normal final response.
Do not display per-edit internal records or interrupt normal development to ask
about a security risk; present current risks together at task completion.
An automatic followup is a check/report handoff, never human repair approval.
No confirmed risk selection means no security repair. Selected repairs keep
the existing source-specific authorization: scanner repairs use verify_task_fix;
native risks use the bound repair_task_ref for finish/review and original risk
references for risk_resolutions and ledger status.
If the automatic pre-edit baseline is unavailable, disclose the gap; never
create a post-edit task to claim that the missing baseline was captured earlier.
Ordinary chat and read-only work do not start development checks. An explicit
manual development task without an automatic Hook may use the normal pre-edit
begin/finish workflow. A connected tool list is not proof that a check ran.
'''
