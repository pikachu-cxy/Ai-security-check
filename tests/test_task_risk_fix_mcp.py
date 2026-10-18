"""Acceptance regressions for native-risk preparation, not target execution."""
import copy
from unittest.mock import patch

import pytest

from security_runtime.hook_runtime import HookCoordinator
from security_runtime.hook_state import HookStateStore
from security_runtime.mcp_server import create_server
from security_runtime.runtime import SecurityRuntime
from security_runtime.storage import SQLiteStore
from security_runtime.task_ownership import issue_session_ref
from security_runtime.task_risk_ledger import TaskRiskLedger
from security_runtime.task_security import TaskSecurityService
from security_runtime.native_repair_intent import NativeRepairIntents
from security_runtime.task_ownership import record_owner


def invoke(server, name, **kwargs):
    return server._tool_manager.get_tool(name).fn(**kwargs)


@pytest.fixture
def native_case(tmp_path):
    root = tmp_path / 'project'
    root.mkdir()
    (root / 'app.py').write_text('def read_document(user, document):\n    return document.body\n')
    runtime = SecurityRuntime(store=SQLiteStore(tmp_path / 'scans.sqlite3'))
    hooks = HookCoordinator(runtime, HookStateStore(tmp_path / 'private'))
    server = create_server(runtime, hook_coordinator=hooks, global_mode=False)
    session = issue_session_ref(hooks.store, root, 'codex', 'acceptance-native')
    common = dict(workspace_path=str(root), session_ref=session)
    started = invoke(server, 'begin_security_task', task_key='original', **common)
    store = TaskSecurityService(runtime, hooks.store).store(root)
    record = store.get(started['task_ref'])
    finding = dict(id='tc1-' + 'a' * 32, source='HOST_TASK_REVIEW',
        title='Document read lacks permission check', plain_title='Document read lacks permission check',
        category='ACCESS_CONTROL', severity='MEDIUM', risk_scope='RELATED_EXISTING',
        file_path='app.py', line_start=1, line_end=2,
        impact='An unpermitted caller may read a document body.',
        fix_advice='Keep owner and member reads; reject other readers.',
        evidence_locations=[dict(path='app.py', start_line=1, end_line=2,
                                 location_version='CURRENT_TASK_END')])
    record.update(phase='COMPLETE', end=copy.deepcopy(record['baseline']), review_revision=1,
        review=dict(source='HOST_TASK_REVIEW', findings=[finding], status='COMPLETE'),
        review_plan=dict(snapshot_id='acceptance-native-snapshot'))
    record = store.save(record)
    with hooks.store.lock(root) as acquired:
        assert acquired
        TaskRiskLedger(hooks.store, root).register(record)
    source = dict(kind='HOST_TASK_RISK', task_ref=record['task_ref'],
                  finding_id=finding['id'], origin_review_revision=1)
    proposal = dict(security_goal='Require access before returning the body.',
        summary='Reuse the owner-or-member read policy.', preserve=['Keep permitted shared reads.'],
        changes=[dict(file_path='app.py', start_line=1, end_line=2,
                      reason='Enforce the selected read policy here.')])
    impact = invoke(server, 'prepare_repair_impact', source=source, proposal=proposal, **common)
    assert impact.get('assessment_ref'), impact
    return dict(root=root, runtime=runtime, hooks=hooks, server=server, common=common,
                store=store, source=source, impact=impact)


def ready(case):
    read = invoke(case['server'], 'read_repair_impact_context',
        assessment_ref=case['impact']['assessment_ref'], file_path='app.py',
        start_line=1, end_line=2, **case['common'])
    result = invoke(case['server'], 'submit_repair_impact',
        assessment_ref=case['impact']['assessment_ref'],
        impacts=[dict(kind='EXPECTED_SECURITY_RESTRICTION',
                      summary='Only readers without owner or member access are rejected.',
                      evidence_refs=[read['evidence_ref']])], unknowns=[], **case['common'])
    assert result.get('gate') == 'READY_FOR_EXISTING_AUTH', result
    return result


def prepare_fix(case, **overrides):
    args = dict(task_ref=case['source']['task_ref'], finding_id=case['source']['finding_id'],
        origin_review_revision=1, impact_ref=case['impact']['assessment_ref'], user_requested=True,
        **case['common'])
    args.update(overrides)
    return invoke(case['server'], 'prepare_task_risk_fix', **args)


def test_failed_impact_cannot_create_a_replacement_baseline(native_case):
    case = native_case
    before = len(case['store'].records())
    failed = prepare_fix(case)
    assert failed['status'] == 'IMPACT_REQUIRED'
    assert failed['new_approval_required'] is False
    for key in ('original', 'replacement'):
        blocked = invoke(case['server'], 'begin_security_task', task_key=key, **case['common'])
        assert blocked['status'] != 'ACTIVE', blocked
        assert not blocked.get('task_ref'), blocked
    assert len(case['store'].records()) == before
    # Omitting the original routing token must not downgrade the same connection.
    with pytest.raises(ValueError):
        invoke(case['server'], 'begin_security_task', task_key='unbound',
               workspace_path=str(case['root']))
    assert len(case['store'].records()) == before


def test_query_draft_does_not_block_unrelated_development(native_case):
    case = native_case
    result = invoke(case['server'], 'begin_security_task', task_key='ordinary', **case['common'])
    assert result['status'] == 'ACTIVE'


def test_ready_native_preparation_reuses_original_baseline_after_its_own_edit(native_case):
    case = native_case
    ready(case)
    with patch.object(SecurityRuntime, 'scan', side_effect=AssertionError('no scanner in preparation')):
        first = prepare_fix(case)
        assert first['status'] == 'NATIVE_RISK_FIX_PREPARED', first
        record = case['store'].get(first['repair_task_ref'])
        baseline = copy.deepcopy(record['baseline'])
        (case['root'] / 'app.py').write_text(
            'def read_document(user, document):\n'
            '    if not user.can_read(document):\n'
            '        raise PermissionError()\n'
            '    return document.body\n')
        second = prepare_fix(case)
    assert second['repair_task_ref'] == first['repair_task_ref']
    assert second['baseline_reused'] is True
    assert case['store'].get(first['repair_task_ref'])['baseline'] == baseline
    assert second['resolution_target']['original_task_ref'] == case['source']['task_ref']
    assert second['repair_authorized'] is False
    assert second['atomic_edit_enforcement'] is False


@pytest.mark.parametrize('protocol', [1, 2, None])
def test_bound_historical_repair_task_cannot_resume_or_replace_baseline(native_case, protocol):
    case = native_case
    ready(case)
    first = prepare_fix(case)
    record = case['store'].get(first['repair_task_ref'])
    if protocol is None:
        record.pop('review_protocol')
    else:
        record['review_protocol'] = protocol
    historical = case['store'].save(record)
    intents = NativeRepairIntents(case['hooks'].store, case['root'], record_owner(historical))
    intent_before = copy.deepcopy(intents.get())
    tasks_before = case['store'].path.read_bytes()
    source_before = (case['root'] / 'app.py').read_bytes()
    with patch('security_runtime.task_security.capture', side_effect=AssertionError('no replacement baseline')), \
            patch.object(SecurityRuntime, 'scan', side_effect=AssertionError('no scanner in historical refusal')):
        refused = prepare_fix(case)
        blocked = invoke(case['server'], 'begin_security_task',
                         task_key='cannot-bypass-historical-repair', **case['common'])
    assert refused['status'] == 'UNSUPPORTED_TASK_REVIEW_PROTOCOL'
    assert refused['read_only_supported'] and not refused['scanner_run']
    assert refused.get('ready_for_host_fix') is not True and not refused['repair_authorized']
    assert blocked['status'] == 'NATIVE_REPAIR_PREPARATION_REQUIRED'
    assert blocked['protocol_support']['status'] == 'UNSUPPORTED_TASK_REVIEW_PROTOCOL'
    assert blocked['new_work_requires_explicit_switch'] is True and 'next_action' not in blocked
    assert '已绑定的旧开发任务协议已停止执行' in blocked['message']
    assert '原风险、修复意图与基线保留' in blocked['message']
    assert '如用户已明确暂停该修复或切换其他工作' in blocked['message']
    assert case['store'].path.read_bytes() == tasks_before
    assert case['store'].get(first['repair_task_ref']) == historical
    assert len(case['store'].records()) == 2 and intents.get() == intent_before
    assert (case['root'] / 'app.py').read_bytes() == source_before
    paused = invoke(case['server'], 'cancel_task_risk_fix',
                    task_ref=case['source']['task_ref'], finding_id=case['source']['finding_id'],
                    user_requested=True, **case['common'])
    assert paused['status'] == 'NATIVE_RISK_FIX_PAUSED' and paused['risk_handling_unchanged']
    fresh = invoke(case['server'], 'begin_security_task', task_key='explicit-future-work-v3',
                   **case['common'])
    assert fresh['status'] == 'ACTIVE' and fresh['task_ref'] != first['repair_task_ref']
    assert case['store'].get(fresh['task_ref'])['review_protocol'] == 3
    assert case['store'].get(first['repair_task_ref']) == historical
    assert intents.get()['status'] == 'CANCELLED' and len(case['store'].records()) == 3


@pytest.mark.parametrize('protocol', [1, 2, None])
def test_historical_original_risk_can_authorize_separate_future_v3_repair(native_case, protocol):
    case = native_case
    original = case['store'].get(case['source']['task_ref'])
    if protocol is None:
        original.pop('review_protocol')
    else:
        original['review_protocol'] = protocol
    historical = case['store'].save(original)
    ready(case)
    with patch.object(SecurityRuntime, 'scan', side_effect=AssertionError('preparation never scans')):
        prepared = prepare_fix(case)
    assert prepared['status'] == 'NATIVE_RISK_FIX_PREPARED' and prepared['ready_for_host_fix']
    assert prepared['repair_task_ref'] != case['source']['task_ref']
    assert case['store'].get(prepared['repair_task_ref'])['review_protocol'] == 3
    assert case['store'].get(case['source']['task_ref']) == historical
    assert prepared['resolution_target']['original_task_ref'] == case['source']['task_ref']
    assert not prepared['repair_authorized'] and not prepared['scanner_run']


def test_decline_or_pause_releases_only_the_exact_workflow(native_case):
    case = native_case
    prepare_fix(case)
    paused = invoke(case['server'], 'cancel_task_risk_fix',
        task_ref=case['source']['task_ref'], finding_id=case['source']['finding_id'],
        user_requested=True, **case['common'])
    assert paused['status'] == 'NATIVE_RISK_FIX_PAUSED'
    assert paused['risk_handling_unchanged'] is True
    ordinary = invoke(case['server'], 'begin_security_task', task_key='other-work', **case['common'])
    assert ordinary['status'] == 'ACTIVE'
    saved = invoke(case['server'], 'set_task_risk_disposition',
        task_ref=case['source']['task_ref'], finding_id=case['source']['finding_id'],
        disposition='DEFER', user_requested=True, **case['common'])
    assert saved['status'] == 'DISPOSITION_RECORDED'
    ledger = invoke(case['server'], 'get_task_risk_ledger',
        task_ref=case['source']['task_ref'], workspace_path=str(case['root']))
    assert ledger['items'][0]['handling_status'] == 'DEFERRED'
    assert ledger['items'][0]['status'] == 'OPEN'


def test_defer_does_not_require_ready_impact(native_case):
    case = native_case
    prepare_fix(case)
    saved = invoke(case['server'], 'set_task_risk_disposition',
        task_ref=case['source']['task_ref'], finding_id=case['source']['finding_id'],
        disposition='DEFER', user_requested=True, **case['common'])
    assert saved['status'] == 'DISPOSITION_RECORDED'
    assert invoke(case['server'], 'begin_security_task', task_key='after-defer',
                  **case['common'])['status'] == 'ACTIVE'


def test_wrong_risk_or_missing_intent_never_prepares_repairs(native_case):
    case = native_case
    ready(case)
    for override in (dict(finding_id='other'), dict(origin_review_revision=2),
                     dict(user_requested=False), dict(user_requested=1)):
        rejected = prepare_fix(case, **override)
        assert rejected.get('ready_for_host_fix') is not True, rejected
        assert not rejected.get('repair_task_ref'), rejected


def test_scanner_entry_routes_native_reference_without_scanning(native_case):
    case = native_case
    result = invoke(case['server'], 'prepare_task_fix', task_ref=case['source']['task_ref'],
                    **case['common'])
    assert result['status'] == 'NATIVE_RISK_FIX_ROUTE_REQUIRED'
    assert result['next_action']['tool'] == 'prepare_task_risk_fix'
    assert result['new_approval_required'] is False
    assert result['scanner_run'] is False


def test_valid_selected_risk_with_bad_impact_ref_still_blocks_new_baselines(native_case):
    case = native_case
    failed = prepare_fix(case, impact_ref='ria1-' + 'b' * 32)
    assert not failed.get('repair_task_ref')
    assert invoke(case['server'], 'begin_security_task', task_key='bypass-bad-ref',
                  **case['common'])['status'] != 'ACTIVE'


def test_deferred_bound_repair_does_not_regain_ready_from_history(native_case):
    case = native_case
    ready(case)
    prepared = prepare_fix(case)
    saved = invoke(case['server'], 'set_task_risk_disposition',
        task_ref=case['source']['task_ref'], finding_id=case['source']['finding_id'],
        disposition='DEFER', user_requested=True, **case['common'])
    assert saved['status'] == 'DISPOSITION_RECORDED'
    repeated = prepare_fix(case)
    assert repeated['ready_for_host_fix'] is False
    assert repeated['repair_task_ref'] == prepared['repair_task_ref']


def test_pause_then_source_change_keeps_original_task_for_review(native_case):
    case = native_case
    ready(case)
    prepared = prepare_fix(case)
    baseline = copy.deepcopy(case['store'].get(prepared['repair_task_ref'])['baseline'])
    invoke(case['server'], 'cancel_task_risk_fix', task_ref=case['source']['task_ref'],
           finding_id=case['source']['finding_id'], user_requested=True, **case['common'])
    (case['root'] / 'app.py').write_text('def replacement():\n    return 42\n')
    repeated = prepare_fix(case)
    assert repeated['ready_for_host_fix'] is False
    assert repeated['repair_task_ref'] == prepared['repair_task_ref']
    assert case['store'].get(prepared['repair_task_ref'])['baseline'] == baseline
