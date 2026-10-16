"""Dedicated reviewer transport: immutable binding and no privileged tools."""
import json

import pytest

from security_runtime.batch_reviewer import (
    CONTRACT, REVIEWER_TOOLS, SESSION_ENV, HOOK_STATE_ENV, create_reviewer_server, reviewer_handoff,
)


def run_sdk(coroutine):
    """Drive the SDK's synchronous handlers without a Windows socketpair loop.

    These operations do not suspend: SDK validation and serialization still run.
    A real stdio transport belongs to the host integration test suite.
    """
    try:
        coroutine.send(None)
    except StopIteration as done:
        return done.value
    finally:
        coroutine.close()
    raise AssertionError('Unexpected asynchronous suspension in SDK handler')


class Reader:
    def __init__(self):
        self.calls = []

    def read(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return {'status': 'OK', 'source_version': 'SNAPSHOT', 'content': 'safe'}


def worker(tmp_path):
    reader = Reader()
    server = create_reviewer_server(reader, workspace=tmp_path, task_ref='task-A',
                                    batch_ref='batch-A', review_session='session-A')
    return reader, server


def structured(result):
    if isinstance(result, tuple):
        return result[1]
    return json.loads(result[0].text)


def test_worker_has_only_snapshot_reader_and_budget_metadata_hint(tmp_path):
    reader, server = worker(tmp_path)
    tools = run_sdk(server.list_tools())
    assert [tool.name for tool in tools] == list(REVIEWER_TOOLS)
    assert tools[0].annotations.readOnlyHint is False
    assert tools[0].annotations.destructiveHint is False
    assert tools[0].annotations.openWorldHint is False
    assert set(tools[0].inputSchema['properties']) == {'path', 'start_line', 'end_line'}
    assert tools[0].inputSchema['additionalProperties'] is False
    out = structured(run_sdk(server.call_tool(
        REVIEWER_TOOLS[0], {'path': 'routes.py', 'start_line': 4, 'end_line': 9})))
    assert out['content'] == 'safe'
    assert reader.calls == [((str(tmp_path.resolve()), 'task-A', 'batch-A', 'session-A',
                              'routes.py'),
                             dict(start_line=4, end_line=9, source_version='SNAPSHOT'))]


@pytest.mark.parametrize('extra', [
    {'workspace': 'secret-rebind'}, {'task_ref': 'secret-rebind'},
    {'batch_ref': 'secret-rebind'}, {'review_session': 'secret-rebind'},
    {'source_version': 'CURRENT'}, {'background_supported': True},
])
def test_worker_cannot_rebind_or_claim_capabilities(tmp_path, extra):
    reader, server = worker(tmp_path)
    with pytest.raises(Exception) as exc:
        run_sdk(server.call_tool(REVIEWER_TOOLS[0], {'path': 'routes.py', **extra}))
    assert 'secret-rebind' not in str(exc.value)
    assert not reader.calls


@pytest.mark.parametrize('args', [
    {'path': 'x.py', 'start_line': '1'},
    {'path': 'x.py', 'start_line': True},
    {'path': 'x.py', 'start_line': 0},
    {'path': 'x.py', 'start_line': 10, 'end_line': 2},
    {'path': ''}, {'path': 4},
])
def test_worker_rejects_invalid_ranges_without_reading(tmp_path, args):
    reader, server = worker(tmp_path)
    with pytest.raises(Exception):
        run_sdk(server.call_tool(REVIEWER_TOOLS[0], args))
    assert not reader.calls


@pytest.mark.parametrize('tool', [
    'begin_security_task', 'finish_security_task', 'scan_project', 'scan_diff',
    'submit_security_batch_review', 'read_task_review_context', 'shell', 'edit',
])
def test_privileged_and_live_tools_are_absent(tmp_path, tool):
    reader, server = worker(tmp_path)
    with pytest.raises(Exception):
        run_sdk(server.call_tool(tool, {}))
    assert not reader.calls


def test_context_gap_returns_bounded_contract(tmp_path):
    from security_runtime.task_security import TaskContextError

    class Exhausted:
        def read(self, *args, **kwargs):
            raise TaskContextError('TASK_CONTEXT_READ_BUDGET', 'Shared budget exceeded',
                                   recoverable=False, guidance='Submit PARTIAL')

    server = create_reviewer_server(Exhausted(), workspace=tmp_path, task_ref='task-A',
                                    batch_ref='batch-A', review_session='session-A')
    out = structured(run_sdk(server.call_tool(REVIEWER_TOOLS[0], {'path': 'x.py'})))
    assert out['status'] == 'CONTEXT_REQUEST_REJECTED'
    assert out['recoverable'] is False
    assert not out['scanner_run']


def test_handoff_is_requirements_not_unverified_isolation_claim(tmp_path):
    from jsonschema import Draft202012Validator
    packet = {'snapshot_id': 'immutable-1'}
    profile = reviewer_handoff(tmp_path, 'task-A', 'batch-A', 'session-A', packet)
    assert profile['contract'] == CONTRACT
    assert profile['expected_agent_tools'] == list(REVIEWER_TOOLS)
    assert 'serve-batch-reviewer' in profile['launch']['args']
    assert 'session-A' not in profile['launch']['args']
    assert profile['launch']['environment'][SESSION_ENV] == 'session-A'
    assert profile['host_requirements']['inherited_parent_tools'] is False
    assert profile['host_requirements']['verify_actual_child_tool_inventory'] == 'EXACT_ALLOWLIST_BEFORE_MODEL_START'
    assert 'USE_EXISTING_TASK_END_REVIEW' in profile['fallback']
    assert not {'isolation_verified', 'host_supported', 'agent_started'} & profile.keys()
    packet['snapshot_id'] = 'changed'
    assert profile['packet']['snapshot_id'] == 'immutable-1'
    assert len(profile['profile_sha256']) == 64
    validator = Draft202012Validator(profile['output_schema'])
    result = dict(task_ref='task-A', batch_ref='batch-A', review_session='session-A',
                  coverage='REVIEWED', findings=[], limitations=[])
    assert not list(validator.iter_errors(result))
    assert list(validator.iter_errors({**result, 'batch_ref': 'other'}))
    assert list(validator.iter_errors({**result, 'coverage': 'PARTIAL'}))
    assert not list(validator.iter_errors({**result, 'coverage': 'PARTIAL',
                                           'limitations': ['unread auth context']}))


def test_worker_candidate_schema_matches_runtime_text_and_related_contract(tmp_path):
    from jsonschema import Draft202012Validator
    profile = reviewer_handoff(tmp_path, 't', 'b', 's')
    validator = Draft202012Validator(profile['output_schema'])
    finding = dict(title='ownership missing', category='authorization', severity='MEDIUM',
                   primary_evidence='related', evidence_refs=['related', 'changed'],
                   impact='possible data exposure', fix_advice='Bind owner',
                   preconditions=['reachable caller'], unknowns=['caller deployment'],
                   counterevidence=[])
    result = dict(task_ref='t', batch_ref='b', review_session='s', coverage='REVIEWED',
                  findings=[finding], limitations=[])
    assert not list(validator.iter_errors(result))
    finding['impact'] = 'x' * 1201
    assert list(validator.iter_errors(result))
    finding['impact'] = 'possible exposure'
    finding['risk_scope'] = 'RELATED_EXISTING'
    assert list(validator.iter_errors(result))
    finding.update(task_evidence='changed', current_protections=['protected new route'])
    assert not list(validator.iter_errors(result))
    finding['unknowns'] = []
    assert list(validator.iter_errors(result))


def test_bad_startup_binding_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        create_reviewer_server(Reader(), workspace='relative', task_ref='t',
                               batch_ref='b', review_session='s')
    with pytest.raises(ValueError):
        reviewer_handoff(tmp_path, 'task-A', 'batch-A', '')
    with pytest.raises(ValueError):
        reviewer_handoff(tmp_path, 'task-A', 'batch-A', 's', hooks_directory='relative')


def test_trusted_per_workspace_state_is_propagated_only_in_launch_environment(tmp_path):
    hooks = tmp_path / 'global-workspace-state' / 'hooks'
    profile = reviewer_handoff(tmp_path, 'task-A', 'batch-A', 's', hooks_directory=hooks)
    assert profile['launch']['environment'][HOOK_STATE_ENV] == str(hooks.resolve())
    assert str(hooks) not in profile['launch']['args']
    assert set(profile['binding']) == {'workspace', 'task_ref', 'batch_ref'}


def test_source_handoff_binds_actual_runtime_and_excludes_reviewed_cwd(tmp_path):
    import os
    from pathlib import Path
    import subprocess
    import security_runtime.batch_reviewer as module

    # A reviewed project can contain a same-named Python module. Its import must
    # not shadow the trusted reviewer implementation or its independently stored
    # snapshots, even if the original venv is editable to the baseline version.
    project = tmp_path / 'untrusted-cwd'
    project.mkdir()
    malicious = project / 'security_runtime'
    malicious.mkdir()
    (malicious / '__init__.py').write_text("raise RuntimeError('cwd was imported')\n")
    profile = reviewer_handoff(project, 'task-A', 'batch-A', 's')
    launch = profile['launch']
    trusted_source = Path(module.__file__).resolve().parent.parent
    assert launch['args'][:3] == ['-P', '-m', 'security_runtime.cli']
    assert launch['environment']['PYTHONPATH'] == str(trusted_source)
    assert launch['environment']['PYTHONSAFEPATH'] == '1'
    assert str(project) != launch['environment']['PYTHONPATH']
    environment = {**os.environ, **launch['environment']}
    result = subprocess.run([launch['command'], '-P', '-c',
        'import security_runtime.batch_reviewer as m; print(m.__file__)'],
        cwd=project, env=environment, capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert Path(result.stdout.strip()).resolve() == Path(module.__file__).resolve()


def test_optional_guidance_preserves_default_tools_and_unobserved_host_capability():
    from security_runtime.host_guidance import runtime_info, REQUIRED_GUIDANCE_TOOLS
    from security_runtime.host_connectors import batch_review_requirements

    class Config:
        def read(self):
            return 'report_only'

    default = runtime_info(remediation_config=Config())
    experimental = runtime_info(remediation_config=Config(), include_batch_review=True)
    assert not default['optional_guidance_tools']
    assert 'task_batch_review' not in default['features']
    assert experimental['required_guidance_tools'] == default['required_guidance_tools']
    assert 'prepare_security_batch' not in REQUIRED_GUIDANCE_TOOLS
    assert experimental['features']['task_batch_review'] == CONTRACT
    for host in ('codex', 'cursor'):
        requirements = batch_review_requirements(host)
        assert requirements['child_tool_isolation'] == 'NOT_OBSERVED_BY_RUNTIME'
        assert requirements['fallback'] == 'EXISTING_TASK_END_REVIEW'


def test_worker_reads_real_frozen_snapshot_and_never_live_source(tmp_path):
    import subprocess
    from security_runtime.hook_state import HookStateStore
    from security_runtime.task_security import TaskSecurityService
    from security_runtime.task_security_batch import TaskSecurityBatchService

    class NoScan:
        def scan(self, *args, **kwargs):
            pytest.fail('Worker must not invoke static scans')

    root = tmp_path / 'source'
    root.mkdir()
    subprocess.run(['git', 'init', '-q', str(root)], check=True)
    source = root / 'routes.py'
    source.write_text('def route(user):\n    return checked(user)\n')
    task = TaskSecurityService(NoScan(), HookStateStore(tmp_path / 'state'))
    task_ref = task.begin(root, 'worker-isolation')['task_ref']
    source.write_text('def route(user):\n    return frozen_batch(user)\n')
    batches = TaskSecurityBatchService(task)
    packet = batches.prepare(root, task_ref, 'endpoint-complete')
    server = create_reviewer_server(batches, workspace=root, task_ref=task_ref,
                                    batch_ref=packet['batch_ref'],
                                    review_session=packet['review_session'])
    source.write_text('def route(user):\n    return live_replacement(user)\n')
    result = structured(run_sdk(server.call_tool(REVIEWER_TOOLS[0], {'path': 'routes.py'})))
    assert 'frozen_batch' in json.dumps(result)
    assert 'live_replacement' not in json.dumps(result)
    assert 'live_replacement' in source.read_text()
    # The source stays untouched, but the exact shared evidence budget is charged.
    assert task.load(root, task_ref)['batch_state']['budget']['context_reads'] == 1
    assert task.load(root, task_ref)['phase'] == 'ACTIVE'


def test_worker_issued_pagination_is_callable_without_rebinding(tmp_path):
    import subprocess
    from security_runtime.hook_state import HookStateStore
    from security_runtime.task_security import TaskSecurityService
    from security_runtime.task_security_batch import TaskSecurityBatchService

    class NoScan:
        def scan(self, *args, **kwargs):
            pytest.fail('Snapshot pagination must not scan')

    root = tmp_path / 'source'
    root.mkdir()
    subprocess.run(['git', 'init', '-q', str(root)], check=True)
    source = root / 'routes.py'
    source.write_text('def route():\n    return None\n')
    task = TaskSecurityService(NoScan(), HookStateStore(tmp_path / 'state'))
    ref = task.begin(root, 'worker-pagination')['task_ref']
    source.write_text('\n'.join(f'item_{i} = {i}' for i in range(1, 126)) + '\n')
    batches = TaskSecurityBatchService(task)
    packet = batches.prepare(root, ref, 'large-file')
    server = create_reviewer_server(batches, workspace=root, task_ref=ref,
                                    batch_ref=packet['batch_ref'],
                                    review_session=packet['review_session'])
    first = structured(run_sdk(server.call_tool(REVIEWER_TOOLS[0],
                            {'path': 'routes.py', 'start_line': 1, 'end_line': 125})))
    assert first['returned_range'] == {'start_line': 1, 'end_line': 80}
    assert first['next_read'] == {'path': 'routes.py', 'start_line': 81, 'end_line': 125}
    second = structured(run_sdk(server.call_tool(REVIEWER_TOOLS[0], first['next_read'])))
    assert second['returned_range'] == {'start_line': 81, 'end_line': 125}
    assert second['next_read'] is None
    assert second['has_more'] is False
    assert first['evidence_id'] != second['evidence_id']
    record = task.load(root, ref)
    assert record['batch_state']['budget']['context_reads'] == 2
    from security_runtime.task_security import _unread_context
    assert _unread_context(record['batch_state']['batches'][0]) == []
