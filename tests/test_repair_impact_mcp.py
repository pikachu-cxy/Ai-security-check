"""The product tools analyse before editing and never turn analysis into consent."""
import asyncio
import copy
import hashlib
import json
from unittest.mock import patch

from summary_fixtures import sample, snapshot
from test_task_triage import task
from security_runtime.hook_runtime import HookCoordinator
from security_runtime.hook_state import HookStateStore
from security_runtime.mcp_server import create_server
from security_runtime.runtime import SecurityRuntime


def make_server(sample):
    root, _, store = sample
    runtime = SecurityRuntime(store=store)
    private = root.parent / ('ip-' + hashlib.sha256(root.name.encode()).hexdigest()[:8])
    hooks = HookCoordinator(runtime, HookStateStore(private))
    return create_server(runtime, hook_coordinator=hooks, global_mode=False)


def call(server, tool, **arguments):
    # Invoke the public callable; SDK/schema rejection is tested separately.
    return server._tool_manager.get_tool(tool).fn(**arguments)


def prepare(server, sample):
    root = sample[0]
    source = dict(kind='SCANNER_TASK_GROUP', task_ref=task(sample)['task_ref'])
    proposal = dict(summary='Keep permitted sharing while correcting the selected TLS check.',
        security_goal='Retain certificate and hostname checks.', preserve=['Keep normal calls.'],
        changes=[dict(file_path='App.java', start_line=2, end_line=3,
                      reason='The displayed group identifies these two checks.')])
    result = call(server, 'prepare_repair_impact', workspace_path=str(root),
                  source=source, proposal=proposal)
    return source, result


def submit(server, sample, prepared, *, business=False):
    root = str(sample[0])
    ref = prepared['assessment_ref']
    read = call(server, 'read_repair_impact_context', workspace_path=root,
                assessment_ref=ref, file_path='App.java', start_line=1, end_line=5)
    assert read.get('evidence_ref'), read
    return call(server, 'submit_repair_impact', workspace_path=root, assessment_ref=ref,
        impacts=[dict(kind='BUSINESS_BEHAVIOR_CHANGE' if business else 'EXPECTED_SECURITY_RESTRICTION',
                      summary='Shared member access remains permitted.', evidence_refs=[read['evidence_ref']])],
        unknowns=[])


def test_query_does_not_scan_finish_edit_or_grant(sample):
    server = make_server(sample)
    before = snapshot(sample[0])
    scans = copy.deepcopy(sample[2].get_scan('scan-a'))
    with patch('security_runtime.task_security.TaskSecurityService.finish', side_effect=AssertionError('no task finish')), \
         patch.object(SecurityRuntime, 'scan', side_effect=AssertionError('no scan')):
        source, prepared = prepare(server, sample)
        assert prepared.get('assessment_ref'), prepared
        saved = submit(server, sample, prepared)
        assert saved['gate'] == 'READY_FOR_EXISTING_AUTH', saved
        assert saved['repair_authorized'] is False
        history = call(server, 'get_repair_impact', workspace_path=str(sample[0]),
                       assessment_ref=prepared['assessment_ref'])
        assert history['gate'] == 'READY_FOR_EXISTING_AUTH'
        assert history['reply_plan']['grants_authority'] is False
    assert snapshot(sample[0]) == before
    assert sample[2].get_scan('scan-a') == scans


def test_host_preparation_requires_impact_but_does_not_claim_consent(sample):
    server = make_server(sample)
    source, prepared = prepare(server, sample)
    waiting = call(server, 'prepare_task_fix', task_ref=source['task_ref'], workspace_path=str(sample[0]))
    assert waiting['status'] == 'IMPACT_REQUIRED'
    assert not waiting['ready_for_host_fix']
    saved = submit(server, sample, prepared)
    assert saved['gate'] == 'READY_FOR_EXISTING_AUTH', saved
    ready = call(server, 'prepare_task_fix', task_ref=source['task_ref'], workspace_path=str(sample[0]),
                 impact_ref=prepared['assessment_ref'])
    assert ready['repair_impact'].get('gate') == 'READY_FOR_EXISTING_AUTH', ready['repair_impact']
    assert ready['status'] == 'READY_FOR_HOST_FIX', ready
    assert ready['ready_for_host_fix']
    assert ready['authorization_requirements']['user_consent_required']


def test_business_choice_is_separate_from_fix_authority(sample):
    server = make_server(sample)
    _, prepared = prepare(server, sample)
    saved = submit(server, sample, prepared, business=True)
    assert saved['gate'] == 'BUSINESS_CHOICE_REQUIRED'
    changed = call(server, 'submit_repair_impact', workspace_path=str(sample[0]),
        assessment_ref=prepared['assessment_ref'], impacts=saved['impacts'], unknowns=[],
        business_choice=dict(user_requested=True, proposal_revision=saved['proposal_revision'],
                             decision='ACCEPT_PROPOSED_CHANGE'))
    assert changed['gate'] == 'READY_FOR_EXISTING_AUTH'
    assert changed['repair_authorized'] is False


def test_other_connection_can_read_history_but_not_submit(sample):
    first = make_server(sample)
    _, prepared = prepare(first, sample)
    saved = submit(first, sample, prepared)
    other = make_server(sample)
    history = call(other, 'get_repair_impact', workspace_path=str(sample[0]),
                   assessment_ref=prepared['assessment_ref'])
    assert history.get('owner_matches') is False, history
    rejected = call(other, 'submit_repair_impact', workspace_path=str(sample[0]),
                    assessment_ref=prepared['assessment_ref'], impacts=saved['impacts'], unknowns=[])
    assert rejected['reason_code'].endswith('OWNER_MISMATCH')
    assert not rejected['repair_authorized']


def test_source_change_invalidates_impact_before_edit(sample):
    server = make_server(sample)
    source, prepared = prepare(server, sample)
    submit(server, sample, prepared)
    (sample[0] / 'App.java').write_text('class App { boolean other() { return true; } }\n')
    history = call(server, 'get_repair_impact', workspace_path=str(sample[0]),
                   assessment_ref=prepared['assessment_ref'])
    assert history.get('lifecycle') == 'STALE', history
    assert history['gate'] == 'REASSESS_REQUIRED'


def test_new_tools_have_closed_top_level_schema(sample):
    server = make_server(sample)
    for name in ('prepare_repair_impact', 'read_repair_impact_context',
                 'submit_repair_impact', 'get_repair_impact'):
        tool = server._tool_manager.get_tool(name)
        assert tool.parameters['additionalProperties'] is False
    info = call(server, 'get_runtime_info')
    assert 'repair-impact-v1' in info['features']['repair_impact']
    assert 'prepare_functional_verification' not in {t.name for t in server._tool_manager.list_tools()}


def test_presentation_overhead_preserves_the_actual_page_and_cursor(sample, monkeypatch):
    server = make_server(sample)
    _, prepared = prepare(server, sample)
    monkeypatch.setattr('security_runtime.reply_render.render_reply', lambda _: 'x' * 16000)
    page = call(server, 'get_repair_impact', workspace_path=str(sample[0]),
                assessment_ref=prepared['assessment_ref'], offset=0, limit=1)
    assert page.get('items'), page
    assert page.get('page'), page
    assert page['assessment_ref'] == prepared['assessment_ref']
    assert page.get('status') != 'REPAIR_IMPACT_RESULT_SAVED'
    assert len(json.dumps(page, ensure_ascii=False).encode('utf-8')) <= 16000
