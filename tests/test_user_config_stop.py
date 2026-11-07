"""Product preferences and bounded Stop behavior on real isolated journals."""
import json
import pytest

from test_development_check import check, execute, OWNER
from security_runtime.user_config import read_config, describe_config
from security_runtime.development_stop import fallback
from security_runtime.development_check import DevelopmentCheckStore
from security_runtime.tasks.durable import TaskOperationError


@pytest.fixture(autouse=True)
def config(tmp_path, monkeypatch):
    path = tmp_path/'config.toml'
    monkeypatch.setenv('SECURITY_RUNTIME_CONFIG', str(path))
    return path


def test_defaults_and_invalid_settings(config):
    values = read_config()['values']
    assert values['storage']['development_max_records'] == 1024
    assert values['agent'] == dict(review_scanner_findings=True, audit_business_logic=False)
    assert values['development']['stop_fallback']['enabled']
    for text in ['oops = true', '[agent]\nreview_scanner_findings=1',
                 '[storage]\ndevelopment_max_records=0', 'invalid [']:
        config.write_text(text)
        assert describe_config()['status'] == 'INVALID'


def test_default_analysis_policy_and_explicit_audit_opt_in(check, config):
    root, service, _, _ = check
    ref = service.begin(root, 'default-policy')['check_ref']
    assert service.get(root, ref)['analysis_requirements'] == {
        'review_scanner_findings': 'REQUIRED', 'audit_business_logic': 'SKIPPED_BY_CONFIG'}
    config.write_text('[agent]\naudit_business_logic=true\n')
    enabled = service.begin(root, 'audit-opt-in')['check_ref']
    assert service.get(root, enabled)['analysis_requirements']['audit_business_logic'] == 'REQUIRED'
    assert service.get(root, ref)['analysis_requirements']['audit_business_logic'] == 'SKIPPED_BY_CONFIG'


@pytest.mark.parametrize('host', ['codex', 'cursor'])
def test_global_config_read_never_requires_or_admits_a_workspace(config, host):
    import asyncio
    from types import SimpleNamespace
    from security_runtime.global_mcp import create_global_server

    def forbidden(*_args, **_kwargs):
        pytest.fail('User configuration must not resolve or admit a workspace')

    server = create_global_server(workspaces=SimpleNamespace(host=host, root=forbidden))
    tools = {t.name: t for t in asyncio.run(server.list_tools())}
    schema = (tools['runtime_status'].inputSchema['$defs']['get_development_config']
              if host == 'codex' else tools['get_development_config'].inputSchema)
    assert 'workspace_path' not in schema.get('required', [])
    result = structured(asyncio.run(server.call_tool('get_development_config', {})))
    assert result['status'] == 'VALID'
    assert result['values']['storage']['development_max_records'] == 1024
    config.write_text('[agent]\nreview_scanner_findings=false\n')
    result = structured(asyncio.run(server.call_tool('get_development_config', {})))
    assert result['values']['agent']['review_scanner_findings'] is False
    config.write_text('unknown=true')
    assert structured(asyncio.run(server.call_tool('get_development_config', {})))['status'] == 'INVALID'


def test_capacity_lowering_and_disabled_limit_preserve_completion(check, config):
    root, service, _, _ = check
    ref = service.begin(root, 'first')['check_ref']
    service.record(root, ref, ['app.ts'])
    config.write_text('[storage]\ndevelopment_max_records=1\n')
    assert service.get(root, ref)['dirty_seq'] == 1
    with pytest.raises(TaskOperationError):
        service.begin(root, 'second')
    assert service.finish(root, ref)['status'] == 'QUEUED'
    config.write_text('[storage]\ndevelopment_record_limit_enabled=false\n')
    assert service.begin(root, 'second')['check_ref'] != ref
    assert len(service.store(root).rows()) > 1


def test_stop_submits_once_waits_and_is_bounded(check):
    root, service, _, _ = check
    calls = []
    service.launcher = lambda *args: calls.append(args)
    ref = service.begin(root, 'work')['check_ref']
    service.record(root, ref, ['app.ts'])
    first = fallback(service.hooks, root, OWNER, service=service, turn_id='edit-turn')
    assert first['decision'] == 'block' and len(calls) == 1
    second = fallback(service.hooks, root, OWNER, service=service, stop_hook_active=True, turn_id='edit-turn')
    assert second['decision'] == 'block' and len(calls) == 1
    third = fallback(service.hooks, root, OWNER, service=service, stop_hook_active=True, turn_id='edit-turn')
    assert third['status'] == 'STOP_FALLBACK_INCOMPLETE' and 'decision' not in third
    assert service.get(root, ref)['finish_requested']


def test_expired_stop_budget_preserves_pending_check(check):
    root, service, _, _ = check
    ref = service.begin(root, 'deadline')['check_ref']
    service.record(root, ref, ['app.ts'])
    fallback(service.hooks, root, OWNER, service=service, turn_id='edit-turn')
    store = service.store(root)
    with store.transaction() as db:
        row = store._get(db, ref)
        row['stop_fallback']['deadline'] = 0
        store._put(db, ref, row)
    result = fallback(service.hooks, root, OWNER, service=service, stop_hook_active=True, turn_id='edit-turn')
    assert result['status'] == 'STOP_FALLBACK_INCOMPLETE'
    assert service.get(root, ref)['status'] == 'QUEUED'


def test_stop_empty_disabled_cancelled_and_legacy_do_not_dispatch(check, config):
    root, service, _, _ = check
    service.launcher = lambda *args: pytest.fail('unexpected scan launch')
    assert fallback(service.hooks, root, OWNER, service=service) is None
    config.write_text('[development.stop_fallback]\nenabled=false\n')
    ref = service.begin(root, 'disabled')['check_ref']
    service.record(root, ref, ['app.ts'])
    assert fallback(service.hooks, root, OWNER, service=service) is None
    config.unlink()
    ref = service.begin(root, 'new')['check_ref']
    service.record(root, ref, ['app.ts'])
    assert fallback(service.hooks, root, OWNER, service=service, stopped_normally=False) is None
    store = service.store(root)
    with store.transaction() as db:
        row = store._get(db, ref)
        row.pop('effective_config')
        store._put(db, ref, row)
    assert fallback(service.hooks, root, OWNER, service=service) is None


@pytest.mark.parametrize('review,audit', [(True,True),(True,False),(False,True),(False,False)])
def test_analysis_policy_is_snapshotted(check, config, review, audit):
    root, service, _, _ = check
    config.write_text('[agent]\nreview_scanner_findings='+str(review).lower()+'\naudit_business_logic='+str(audit).lower())
    ref = service.begin(root, 'policy')['check_ref']
    config.unlink()
    result = service.get(root, ref)
    assert result['analysis_requirements'] == {
        'review_scanner_findings': 'REQUIRED' if review else 'SKIPPED_BY_CONFIG',
        'audit_business_logic': 'REQUIRED' if audit else 'SKIPPED_BY_CONFIG'}


def test_static_only_scanner_import_without_agent_review(check, config, monkeypatch):
    root, service, _, _ = check
    config.write_text('[agent]\nreview_scanner_findings=false\naudit_business_logic=false')
    ref = service.begin(root, 'static')['check_ref']
    service.record(root, ref, ['app.ts'])
    execute(check, monkeypatch)
    from security_runtime.development_risks import DevelopmentRisks
    risks = DevelopmentRisks(service, root, ref)
    assert risks.get()['review_versions'] == []
    assert service.get(root, ref)['host_review_completed'] is False
    with pytest.raises(ValueError, match='DEVELOPMENT_AGENT_ANALYSIS_DISABLED'):
        risks.submit([], 1)


def test_stop_does_not_select_other_owner_or_previous_task(check):
    root, service, _, _ = check
    old = service.begin(root, 'old')['check_ref']
    service.record(root, old, ['app.ts'])
    service.begin(root, 'current-empty')
    assert fallback(service.hooks, root, OWNER, service=service) is None
    assert fallback(service.hooks, root, dict(host='codex', session='f'*64)) is None


def test_new_edit_does_not_reset_continuation_budget(check):
    root, service, _, _ = check
    ref = service.begin(root, 'work')['check_ref']
    service.record(root, ref, ['app.ts'])
    fallback(service.hooks, root, OWNER, service=service, turn_id='edit-turn')
    deadline = service.store(root).load(ref)['stop_fallback']['deadline']
    service.record(root, ref, ['app.ts'])
    fallback(service.hooks, root, OWNER, service=service, stop_hook_active=True, turn_id='edit-turn')
    row = service.store(root).load(ref)
    assert row['stop_fallback']['deadline'] == deadline
    assert row['stop_fallback']['count'] == 2

from test_development_check_mcp import development_server, call
from test_global_integration import structured, projects, installed
from test_development_delivery_mcp import prepare


def test_codex_native_stop_timeout_notifies_without_agent_poll(development_server, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_DEVELOPMENT_WAIT_SECONDS', '0')
    import asyncio
    from test_development_check import DevelopmentCheckService
    server, root, hooks, launches = development_server
    ref, token = prepare(development_server)
    monkeypatch.setattr(DevelopmentCheckService, '_wake', lambda self, store: launches.append(str(store.root)))
    response = asyncio.run(server.call_tool('handle_stop_event', dict(event='Stop',
        workspace_path=str(root), session_id='delivery-session', stop_hook_active=False, turn_id='turn')))
    assert structured(response)['status'] == 'STOP_FALLBACK_INCOMPLETE'
    wire = json.loads(response.content[0].text)
    assert wire['decision'] == 'block' and ref in wire['reason']
    assert len(launches) == 1
    assert call(server, 'get_development_check', workspace_path=str(root), check_ref=ref,
                session_ref=token)['finish_requested']


def test_cursor_cli_stop_followup_and_abort(check, tmp_path, monkeypatch):
    from security_runtime.cursor_automatic import handle_automatic_event
    from security_runtime.cursor_hook import CursorBindings
    from security_runtime.recent_hooks import RecentHookStore
    from security_runtime.tasks.ownership import session_owner
    from security_runtime.development_check import DevelopmentCheckService
    from test_cursor_host_adapter import payload
    root, original, runtime, _ = check
    session = 'private-cursor-conversation'
    service = DevelopmentCheckService(None, original.hooks, owner=session_owner('cursor', session),
                                     scan_path_provider=runtime.store.path, launcher=lambda *a: None)
    ref = service.begin(root, 'cursor-cli')['check_ref']
    service.record(root, ref, ['app.ts'])
    # The bridge also exposes explicit task services, but this lightweight path must not use them.
    from test_hook_runtime import coordinator, FakeRuntime
    core = coordinator(tmp_path, FakeRuntime(), task_audit_mode=True)
    core.store = original.hooks
    bindings = CursorBindings(tmp_path/'bindings')
    monkeypatch.setattr(DevelopmentCheckService, '_wake', lambda *a: None)
    args = dict(core=core, bindings=bindings, project_dir=str(root), store=RecentHookStore(tmp_path/'recent'))
    output, result = handle_automatic_event(payload(root, 'stop', status='aborted', loop_count=0), **args)
    assert output == {} and not service.get(root, ref)['finish_requested']
    output, result = handle_automatic_event(payload(root, 'stop', status='completed', loop_count=0), **args)
    assert 'followup_message' in output, result
    assert ref in output['followup_message']
    assert '提交成功后必须从 offset=0 重新读取' in output['followup_message']
    assert service.get(root, ref)['finish_requested']
    handle_automatic_event(payload(root, 'stop', status='completed', loop_count=1), **args)
    output, result = handle_automatic_event(payload(root, 'stop', status='completed', loop_count=2), **args)
    assert output == {}
    assert result['development_stop']['status'] == 'STOP_FALLBACK_INCOMPLETE'


def test_static_only_keeps_stop_enabled_and_preserves_batch_config(check, config):
    root, service, _, _ = check
    config.write_text('[agent]\nreview_scanner_findings=false\naudit_business_logic=false\n')
    ref = service.begin(root, 'static-stop')['check_ref']
    service.record(root, ref, ['app.ts'])
    config.write_text('[development.stop_fallback]\nenabled=false\n')
    result = fallback(service.hooks, root, OWNER, service=service)
    assert result['decision'] == 'block'
    assert set(result['analysis_requirements'].values()) == {'SKIPPED_BY_CONFIG'}
    assert service.get(root, ref)['finish_requested']
    assert '不能冒充 Agent 确认' in result['reason']


def test_disabled_stop_snapshot_survives_reenable_until_new_check(check, config):
    root, service, _, _ = check
    config.write_text('[agent]\nreview_scanner_findings=false\naudit_business_logic=false\n'
                      '[development.stop_fallback]\nenabled=false\n')
    old = service.begin(root, 'disabled-batch')['check_ref']
    service.record(root, old, ['app.ts'])
    config.unlink()
    assert fallback(service.hooks, root, OWNER, service=service) is None
    assert not service.get(root, old)['finish_requested']
    new = service.begin(root, 'new-enabled-batch')['check_ref']
    service.record(root, new, ['app.ts'])
    assert fallback(service.hooks, root, OWNER, service=service)['decision'] == 'block'
    assert not service.get(root, old)['finish_requested']


from test_development_risks import sample, scanner


@pytest.mark.parametrize('partial', [False, True])
def test_terminal_stop_is_not_repeated_after_inconclusive_review(check, config, monkeypatch, partial):
    from security_runtime.development_risks import DevelopmentRisks
    root, service, _, state = check
    config.write_text('[agent]\nreview_scanner_findings=true\naudit_business_logic=false')
    (root/'app.ts').write_text('eval(userInput);\n')
    ref = service.begin(root, 'terminal-stop')['check_ref']
    service.record(root, ref, ['app.ts'])
    execute(check, monkeypatch)
    store = service.store(root)
    if not partial:
        with store.transaction() as db:
            row = store._get(db, ref)
            store._put(db, ref, dict(row, state='RESULTS_READY',
                result=dict(row['result'], gaps=[], status='COMPLETED', coverage='FULL')))
    saved = service.get(root, ref)
    assert saved['next_action']['tool'] == 'get_development_risks'
    assert '最终回复前' in saved['review_instruction']
    assert fallback(service.hooks, root, OWNER, service=service, turn_id='turn')['decision'] == 'block'
    risks = DevelopmentRisks(service, root, ref)
    candidate = risks.get()['risks'][0]
    evidence = risks.read('app.ts', 1, 1)
    risks.submit([dict(same_issue_as=candidate['id'], scan_id=saved['scan_id'],
        decision='INCONCLUSIVE', rationale='Synthetic missing caller context.',
        evidence_refs=[evidence['evidence_ref']])], saved['dirty_seq'])
    risks.get()
    assert fallback(service.hooks, root, OWNER, service=service,
                    stop_hook_active=True, turn_id='turn') is None
    after = service.get(root, ref)
    assert after['review_progress']['scanner_review'] == 'PENDING'
    assert not after['host_review_completed']
    assert after['gaps'] == saved['gaps']
    assert store.load(ref)['stop_fallback']['count'] == 1
    assert state['calls'] == 1
    # A new edit must still get its own fallback, within the original budget.
    service.record(root, ref, ['app.ts'])
    assert service.get(root, ref)['next_action']['tool'] == 'finish_development_check'
    assert fallback(service.hooks, root, OWNER, service=service,
                    stop_hook_active=True, turn_id='turn')['decision'] == 'block'


def test_waiting_stop_does_not_suppress_new_terminal_result(check, config, monkeypatch):
    root, service, _, state = check
    config.write_text('[agent]\naudit_business_logic=true\n')
    ref = service.begin(root, 'waiting-stop')['check_ref']
    service.record(root, ref, ['app.ts'])
    assert fallback(service.hooks, root, OWNER, service=service, turn_id='turn')['decision'] == 'block'
    execute(check, monkeypatch)
    assert fallback(service.hooks, root, OWNER, service=service,
                    stop_hook_active=True, turn_id='turn')['decision'] == 'block'
    assert fallback(service.hooks, root, OWNER, service=service,
                    stop_hook_active=True, turn_id='turn') is None
    assert state['calls'] == 1


@pytest.mark.parametrize('scanner_review,business_review', [
    (True, True), (True, False), (False, True), (False, False)])
@pytest.mark.parametrize('prior_stop', [False, True])
def test_reviewed_partial_result_does_not_continue_for_coverage_gaps(
        check, config, monkeypatch, scanner_review, business_review, prior_stop):
    from security_runtime.development_risks import DevelopmentRisks
    root, service, _, state = check
    config.write_text('[agent]\n'
        f'review_scanner_findings={str(scanner_review).lower()}\n'
        f'audit_business_logic={str(business_review).lower()}\n')
    ref = service.begin(root, 'partial-reviewed')['check_ref']
    service.record(root, ref, ['app.ts'])
    if prior_stop:
        assert fallback(service.hooks, root, OWNER, service=service,
                        turn_id='turn')['decision'] == 'block'
    execute(check, monkeypatch)
    saved = service.get(root, ref)
    # The real lexical-only fixture leaves scanner coverage incomplete.
    assert saved['status'] == 'PARTIAL' and saved['gaps']
    risks = DevelopmentRisks(service, root, ref)
    if business_review:
        evidence = risks.read('app.ts', 1, 2)
        risks.submit([], saved['dirty_seq'], business_reviews=[dict(
            file_path='app.ts', rationale='Reviewed the synthetic passthrough function.',
            evidence_refs=[evidence['evidence_ref']], limitations=[])])
    reviewed = service.get(root, ref)
    assert reviewed['host_review_completed'] == (scanner_review or business_review)
    before = service.store(root).load(ref).get('stop_fallback')
    # Neither first Stop nor an active/reset continuation flag can create work
    # solely because terminal coverage remains partial. This is no report ack.
    for active in (False, True, False, True):
        assert fallback(service.hooks, root, OWNER, service=service,
                        stop_hook_active=active, turn_id='turn') is None
    after = service.get(root, ref)
    assert after['status'] == 'PARTIAL'
    assert after['gaps'] == saved['gaps']
    assert after['scan_id'] == saved['scan_id']
    assert service.store(root).load(ref).get('stop_fallback') == before
    assert state['calls'] == 1
    # A subsequent edit invalidates completion and must retain normal fallback.
    (root/'app.ts').write_text('export const changed = 2;\n')
    service.record(root, ref, ['app.ts'])
    assert fallback(service.hooks, root, OWNER, service=service,
                    turn_id='next')['decision'] == 'block'


def test_static_only_result_does_not_request_agent_review(check, config, monkeypatch):
    root, service, _, _ = check
    config.write_text('[agent]\nreview_scanner_findings=false\naudit_business_logic=false')
    ref = service.begin(root, 'static-next-action')['check_ref']
    service.record(root, ref, ['app.ts'])
    execute(check, monkeypatch)
    saved = service.get(root, ref)
    assert 'review_instruction' not in saved
    assert saved['next_action']['tool'] == 'get_development_check'


@pytest.mark.parametrize('has_finding', [False, True])
def test_successful_import_recovers_old_failure_and_stop_is_quiet(check, config, monkeypatch, has_finding):
    from security_runtime.development_risks import DevelopmentRisks
    root, service, _, _ = check
    config.write_text('[agent]\nreview_scanner_findings=true\naudit_business_logic=false')
    if has_finding:
        (root/'app.ts').write_text('eval(userInput);\n')
    ref = service.begin(root, 'recovered-import')['check_ref']
    service.record(root, ref, ['app.ts'])
    store = service.store(root)
    with store.transaction() as db:
        row = store._get(db, ref)
        store._put(db, ref, dict(row, risk_import_status='UNAVAILABLE'))
    execute(check, monkeypatch)
    assert store.load(ref)['risk_import_status'] == 'AVAILABLE'
    # This fixture runs only the local lexical scanner. Model the other
    # scanners' completion to isolate Stop's review-completion decision.
    with store.transaction() as db:
        row = store._get(db, ref)
        assert row['result']['gaps'] == ['SCANNER_COVERAGE_LIMITED']
        store._put(db, ref, dict(row, state='RESULTS_READY',
            result=dict(row['result'], gaps=[], status='COMPLETED', coverage='FULL')))
    risks = DevelopmentRisks(service, root, ref)
    result = risks.get()
    assert result['total'] == int(has_finding)
    if has_finding:
        assert not result['review_progress']['host_review_completed']
        evidence = risks.read('app.ts', 1, 1)
        risks.submit([dict(same_issue_as=result['risks'][0]['id'], scan_id=result['scan_id'],
            decision='DISMISSED', rationale='Synthetic review for the Stop lifecycle test.',
            evidence_refs=[evidence['evidence_ref']])], result['dirty_seq'])
    assert service.get(root, ref)['host_review_completed']
    assert fallback(service.hooks, root, OWNER, service=service) is None


@pytest.mark.parametrize('outcome', ['failure'])
def test_unsuccessful_or_stale_import_cannot_clear_failure(sample, monkeypatch, outcome):
    root, service, ref, risks = sample
    scanner(sample, monkeypatch)
    store = service.store(root)
    with store.transaction() as db:
        row = store._get(db, ref)
        store._put(db, ref, dict(row, risk_import_status='UNAVAILABLE'))
    original = risks.import_scanner
    def import_scanner(row, check):
        if outcome == 'failure':
            raise ValueError('Synthetic import failure')
        original(row, check)
        with store.transaction() as db:
            current = store._get(db, ref)
            store._put(db, ref, dict(current, scan_id='scan-2'))
    monkeypatch.setattr(risks, 'import_scanner', import_scanner)
    if outcome == 'failure':
        with pytest.raises(ValueError, match='Synthetic import failure'):
            risks.sync_scanner()
    else:
        risks.sync_scanner()
    assert store.load(ref)['risk_import_status'] == 'UNAVAILABLE'


def test_static_candidate_import_keeps_raw_findings_without_review(sample, config, monkeypatch):
    root, service, ref, risks = sample
    config.write_text('[agent]\nreview_scanner_findings=false\naudit_business_logic=false')
    # Set the batch snapshot before the synthetic saved scan is imported.
    store = service.store(root)
    with store.transaction() as db:
        row = store._get(db, ref)
        store._put(db, ref, dict(row, effective_config=read_config()))
    original = scanner(sample, monkeypatch)
    risks.sync_scanner()
    result = risks.get()
    assert result['total'] == 1 and result['review_versions'] == []
    assert result['risks'][0]['sources'] == ['SCANNER']
    assert result['risks'][0]['finding']['id'] == original['id']
    assert not risks.current_check().get('has_development_review')
    risks.sync_scanner()
    assert risks.get()['risks'][0]['observation_count'] == 1


@pytest.mark.parametrize('old_turn,new_turn', [('old', 'new'), ('old', None), (None, 'new'), (None, None)])
def test_historical_stop_cannot_block_later_turn(check, old_turn, new_turn):
    root, service, _, _ = check
    calls = []
    service.launcher = lambda *args: calls.append(args)
    ref = service.begin(root, 'old-work')['check_ref']
    service.record(root, ref, ['app.ts'])
    assert fallback(service.hooks, root, OWNER, service=service, turn_id=old_turn)['decision'] == 'block'
    for active in (False, True):
        assert fallback(service.hooks, root, OWNER, service=service,
                        turn_id=new_turn, stop_hook_active=active) is None
    assert len(calls) == 1
    assert service.get(root, ref)['finish_requested']


def test_new_edit_turn_retains_its_own_fallback(check):
    root, service, _, _ = check
    ref = service.begin(root, 'work')['check_ref']
    service.record(root, ref, ['app.ts'])
    fallback(service.hooks, root, OWNER, service=service, turn_id='old')
    service.record(root, ref, ['app.ts'])
    result = fallback(service.hooks, root, OWNER, service=service, turn_id='new')
    assert result['decision'] == 'block'
    assert service.store(root).load(ref)['stop_fallback']['turn'] is not None


def test_exhausted_stop_notice_is_emitted_only_once(check):
    root, service, _, _ = check
    ref = service.begin(root, 'exhausted-repeat')['check_ref']
    service.record(root, ref, ['app.ts'])
    args = dict(service=service, turn_id='turn')
    fallback(service.hooks, root, OWNER, **args)
    fallback(service.hooks, root, OWNER, stop_hook_active=True, **args)
    assert fallback(service.hooks, root, OWNER, stop_hook_active=True, **args)['status'] == 'STOP_FALLBACK_INCOMPLETE'
    for _ in range(3):
        assert fallback(service.hooks, root, OWNER, stop_hook_active=True, **args) is None
    assert service.get(root, ref)['status'] == 'QUEUED'


def test_same_turn_new_versions_cannot_reset_budget_when_host_flag_is_false(check):
    root, service, _, _ = check
    ref = service.begin(root, 'same-turn')['check_ref']
    args = dict(service=service, turn_id='turn', stop_hook_active=False)
    service.record(root, ref, ['app.ts'])
    assert fallback(service.hooks, root, OWNER, **args)['decision'] == 'block'
    deadline = service.store(root).load(ref)['stop_fallback']['deadline']
    service.record(root, ref, ['app.ts'])
    assert fallback(service.hooks, root, OWNER, **args)['decision'] == 'block'
    row = service.store(root).load(ref)
    assert row['stop_fallback']['count'] == 2
    assert row['stop_fallback']['deadline'] == deadline
    service.record(root, ref, ['app.ts'])
    assert fallback(service.hooks, root, OWNER, **args)['status'] == 'STOP_FALLBACK_INCOMPLETE'
    service.record(root, ref, ['app.ts'])
    assert fallback(service.hooks, root, OWNER, **args) is None
    # A later actual editing turn still receives its own bounded opportunity.
    service.record(root, ref, ['app.ts'])
    assert fallback(service.hooks, root, OWNER, service=service, turn_id='next')['decision'] == 'block'


def test_failed_stop_notices_once_without_blocking_and_new_edit_recovers(check):
    root, service, _, _ = check
    ref = service.begin(root, 'failed-stop')['check_ref']
    service.record(root, ref, ['app.ts'])
    store = service.store(root)
    with store.transaction() as db:
        row = store._get(db, ref)
        store._put(db, ref, dict(row, state='FAILED', failed_seq=row['dirty_seq'],
                                finish_requested=True, reason_code='DEVELOPMENT_SCAN_FAILED'))
    first = fallback(service.hooks, root, OWNER, service=service, turn_id='turn')
    assert first['status'] == 'STOP_FALLBACK_INCOMPLETE'
    assert 'decision' not in first
    for active in (True, False):
        assert fallback(service.hooks, root, OWNER, service=service,
                        turn_id='turn', stop_hook_active=active) is None
    # A fresh service reads the same durable failure-notice marker.
    from security_runtime.development_check import DevelopmentCheckService
    fresh = DevelopmentCheckService(None, service.hooks, owner=OWNER,
                                   scan_path_provider=service.scan_path())
    assert fallback(service.hooks, root, OWNER, service=fresh, turn_id='turn') is None
    service.record(root, ref, ['app.ts'])
    assert fallback(service.hooks, root, OWNER, service=service, turn_id='next')['decision'] == 'block'

@pytest.mark.parametrize('business', [False, True])
def test_native_handoff_issues_evidence_and_consumes_edit_round(check, config, monkeypatch, business):
    from security_runtime.development_risks import DevelopmentRisks
    root, service, _, _ = check
    config.write_text('[agent]\naudit_business_logic=' + str(business).lower())
    (root / 'app.ts').write_text('eval(userInput);\n')
    ref = service.begin(root, 'native-review')['check_ref']
    service.record(root, ref, ['app.ts'])
    execute(check, monkeypatch)
    args = dict(service=service, turn_id='turn', automatic=True)
    result = fallback(service.hooks, root, OWNER, **args)
    reason = result['reason']
    assert result['decision'] == 'block' and reason == f'正在整理安全检查结果。（检查编号 {ref}）'
    assert all(value not in reason for value in ('{', 'eval(', 'scan_id', 'submit_development_review'))
    ledger = DevelopmentRisks(service, root, ref)
    from security_runtime.development_views import closeout_page
    page = closeout_page(ledger, 0, 20)
    assert page['closeout_mode'] == 'REVIEW'
    assert len(page['candidates']) == 1 and page['evidence']
    page = ledger.get()
    assert len(page['review_progress']['pending_scanner_ids']) == 1
    assert page['review_progress']['pending_business_paths'] == (['app.ts'] if business else [])
    assert 'eval(userInput)' in ledger.read('app.ts', 1, 1)['content']
    assert fallback(service.hooks, root, OWNER, stop_hook_active=True, **args) is None
    assert fallback(service.hooks, root, OWNER, **args) is None
