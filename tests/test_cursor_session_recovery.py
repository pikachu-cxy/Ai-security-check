"""Missed startup context is recovered without guessing a check's owner."""
import re

import pytest

from security_runtime.tasks.ownership import verify_session_ref, session_owner
from security_runtime.workspace_application import WorkspaceApplication
from test_cursor_automatic import ingress, tool
from test_hook_runtime import repo, coordinator, FakeRuntime


@pytest.mark.parametrize('name', ['Read', 'Write'])
def test_feedback_recovers_compact_session_without_scan(repo, tmp_path, name):
    runtime = FakeRuntime()
    core = coordinator(tmp_path, runtime)
    core.task_audit_mode = True
    tool(repo, tmp_path, core, name, file_path=str(repo/'A.java'))
    output, result = ingress(repo, tmp_path, core, 'postToolUse', tool_name=name,
                             tool_input={'file_path': str(repo/'A.java')}, tool_use_id='opaque')
    token = re.search(r'sh1-[a-f0-9]{32}', output['additional_context']).group()
    assert verify_session_ref(core.store, repo, token) == session_owner('cursor', 'private-cursor-conversation')
    assert not runtime.calls and not result['scanner_run']
    again, _ = ingress(repo, tmp_path, core, 'postToolUse', tool_name=name,
                       tool_input={'file_path': str(repo/'A.java')}, tool_use_id='opaque')
    assert token in again['additional_context']
    assert not (core.store.workspace_directory(repo)/'task-security.db').exists()


def test_recovered_session_survives_new_connection_but_not_other_chat(repo, tmp_path):
    core = coordinator(tmp_path, FakeRuntime())
    core.task_audit_mode = True
    tool(repo, tmp_path, core, 'Read')
    output, _ = ingress(repo, tmp_path, core, 'postToolUse', tool_name='Read', tool_input={}, tool_use_id='opaque')
    token = re.search(r'sh1-[a-f0-9]{32}', output['additional_context']).group()

    def connection():
        return WorkspaceApplication(core.runtime, core.store, scan_path_provider=lambda: tmp_path/'scans.db')

    first = connection()
    service = first.development_service(session_ref=token, workspace=str(repo))
    check = service.begin(repo, 'cursor-reconnect')
    second = connection()
    assert first.connection_owner != second.connection_owner
    restored = second.development_service(session_ref=token, workspace=str(repo)).get(repo, check['check_ref'])
    assert restored['check_ref'] == check['check_ref']
    with pytest.raises(ValueError):
        second.development_service(workspace=str(repo)).get(repo, check['check_ref'])
    from security_runtime.tasks.ownership import issue_session_ref
    other = issue_session_ref(core.store, repo, 'cursor', 'other-chat', compact=True)
    with pytest.raises(ValueError):
        second.development_service(session_ref=other, workspace=str(repo)).get(repo, check['check_ref'])


def test_unverified_feedback_does_not_issue_context(repo, tmp_path):
    core = coordinator(tmp_path, FakeRuntime())
    core.task_audit_mode = True
    output, result = ingress(repo, tmp_path, core, 'postToolUse', tool_name='Read', tool_input={},
                             tool_use_id='opaque', conversation_id='')
    assert 'additional_context' not in output
    assert not result['scanner_run']
