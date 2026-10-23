"""Product entry points share strict validation and immutable delivery identity."""
import asyncio
import copy
from types import SimpleNamespace

import pytest

from security_runtime.delivery_manifest import delivery_manifest
from security_runtime.global_mcp import GlobalWorkspaces, create_global_server
from security_runtime.guidance.host_guidance import HOST_INSTRUCTIONS
from security_runtime.mcp_contracts import MCPRegistry
from security_runtime.mcp_server import create_server
from security_runtime.workspace_services import bind_impact_gate
from test_global_integration import structured
from summary_fixtures import sample


def runtime_info():
    return dict(version='synthetic', build_identity=dict(status='IDENTIFIED', build_id='b' * 64,
        state_schema='runtime-state-v1'), features=dict(task_security_review_protocol='task-review-plan-v3; ONLY_V3; LEGACY_HISTORY_READ_ONLY',
            task_security_result_delivery='task-result-delivery-v1'),
        rule_inventory=dict(status='AVAILABLE', rule_pack_version='1', rule_pack_checksum='c' * 64))


def test_manifest_binds_actual_routed_schema_without_admitting_a_workspace(tmp_path, monkeypatch):
    state = tmp_path / 'private'
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(state))
    monkeypatch.setenv('SECURITY_RUNTIME_WORKSPACE', '')
    monkeypatch.setattr('security_runtime.guidance.host_guidance.runtime_info', lambda **_: runtime_info())
    monkeypatch.setattr('security_runtime.review_skill.skill_files',
                        lambda: {'SKILL.md': b'core', 'references/quick-task-review-v3.md': b'method'})
    local = create_server(global_mode=False)
    # Any attempted workspace admission or lifespan work fails on this sentinel.
    routed = create_global_server(workspaces=object())
    before = list(tmp_path.rglob('*'))
    local_info = MCPRegistry(local).tool('get_runtime_info').fn()
    result = asyncio.run(routed.call_tool('get_runtime_info', {}))
    global_info = result.structuredContent
    first, second = local_info['delivery_manifest'], global_info['delivery_manifest']
    assert first['skill'] == second['skill']
    assert first['rules'] == second['rules']
    assert first['tools']['schema_sha256'] != second['tools']['schema_sha256']
    assert second['tools']['schema_sha256'] == delivery_manifest(
        global_info, asyncio.run(routed.list_tools()))['tools']['schema_sha256']
    assert first['protocols']['task_security_review_protocol'] == 'task-review-plan-v3; ONLY_V3; LEGACY_HISTORY_READ_ONLY'
    assert not first['security_proof'] and not first['repair_authorized']
    assert list(tmp_path.rglob('*')) == before


def test_manifest_changes_with_methods_rules_and_schema_without_changing_existing_refs():
    tool = SimpleNamespace(name='read', parameters={'type': 'object', 'properties': {}},
                           output_schema=None, annotations=None)
    info = runtime_info()
    before = copy.deepcopy(info)
    manifest = delivery_manifest(info, [tool], skill_contents={'SKILL.md': b'one'})
    assert delivery_manifest(info, [tool], skill_contents={'SKILL.md': b'two'})['manifest_sha256'] != manifest['manifest_sha256']
    changed = copy.deepcopy(info)
    changed['rule_inventory']['rule_pack_checksum'] = 'd' * 64
    assert delivery_manifest(changed, [tool], skill_contents={'SKILL.md': b'one'})['manifest_sha256'] != manifest['manifest_sha256']
    changed_tool = copy.deepcopy(tool)
    changed_tool.parameters['required'] = ['workspace_path']
    assert delivery_manifest(info, [changed_tool], skill_contents={'SKILL.md': b'one'})['manifest_sha256'] != manifest['manifest_sha256']
    assert info == before
    assert 'PRESERVE_ORIGINAL_OWNER_REFERENCE_PROTOCOL' in manifest['existing_tasks']


def test_missing_skill_is_unavailable_identity_not_a_successful_empty_install(monkeypatch):
    def unavailable():
        raise OSError('unreadable')
    monkeypatch.setattr('security_runtime.review_skill.skill_files', unavailable)
    manifest = delivery_manifest(runtime_info(), [])
    assert manifest['skill'] == dict(status='UNAVAILABLE', content_sha256=None, files=None)
    assert manifest['security_proof'] is False


def test_skill_upgrade_identity_distinguishes_shipped_installed_and_user_changes(tmp_path):
    from security_runtime.review_skill import ReviewSkillManager
    manager = ReviewSkillManager(tmp_path / 'skills', tmp_path / 'state')
    installed = manager.execute('install')
    assert installed['installed_content_sha256'] == installed['shipped_content_sha256']
    manager.expected['SKILL.md'] += b'\nnew shipped guidance\n'
    upgrade = manager.status()
    assert upgrade['status'] == 'UPGRADE_AVAILABLE'
    assert upgrade['installed_content_sha256'] == installed['installed_content_sha256']
    assert upgrade['shipped_content_sha256'] != upgrade['installed_content_sha256']
    (manager.root / 'SKILL.md').write_bytes(b'user changed content')
    changed = manager.status()
    assert changed['status'] == 'USER_MODIFIED'
    assert changed['installed_content_sha256'] is None


@pytest.mark.parametrize('name,arguments', [
    ('submit_repair_impact', dict(assessment_ref='ria1-' + '0' * 32, impacts=[], unknowns=[
        dict(summary='specific normal operation', critical=False, classification='BLOCKING_CONTEXT',
             decision_basis='needs a decision', evidence_refs=[])])),
    ('submit_task_security_review', dict(task_ref='retained-task', review_session='retained-session',
        findings=[dict(title='candidate', category='access', severity='HIGH',
            primary_evidence={'evidence_id': 'issued'}, evidence_refs=['issued'], impact='effect',
            preconditions=[], unknowns=[], counterevidence=[], fix_advice='change')],
        coverage='REVIEWED', limitations=[])),
])
def test_same_raw_contract_rejects_local_and_global_before_service_or_admission(name, arguments, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_WORKSPACE', '')
    local = create_server(global_mode=False)
    routed = create_global_server(workspaces=object())
    arguments = dict(arguments, workspace_path='C:/synthetic-should-never-be-admitted')
    local_result = asyncio.run(MCPRegistry(local).dispatch(name, arguments, convert_result=True))
    global_result = asyncio.run(routed.call_tool(name, arguments))
    assert structured(local_result) == global_result.structuredContent
    failure = global_result.structuredContent
    assert failure['field_errors']
    assert not failure['scanner_run'] and not failure['source_modified']


def test_impact_gate_cannot_be_omitted_by_custom_global_factory(sample, tmp_path, monkeypatch):
    from test_task_triage import task
    from security_runtime.hook_runtime import HookCoordinator
    from security_runtime.hook_state import HookStateStore
    from security_runtime.integration_state import WorkspaceBinding
    from security_runtime.remediation import RemediationService
    from security_runtime.runtime import SecurityRuntime

    runtime = SecurityRuntime(store=sample[2])
    core = HookCoordinator(runtime, HookStateStore(tmp_path / 'hooks'))
    monkeypatch.setattr('security_runtime.workspace_services.workspace_services',
                        lambda *_: (runtime, core, True))
    created = []

    def factory(*args, **kwargs):
        result = RemediationService(*args, **kwargs)
        created.append(result)
        return result

    monkeypatch.setattr('security_runtime.remediation.RemediationService', factory)
    root = sample[0]
    binding = WorkspaceBinding('synthetic', str(root), str(root), 'codex', 'PROJECT', '')
    _, returned_core = GlobalWorkspaces._child(root, tmp_path, binding)
    assert returned_core is core and len(created) == 1
    assert callable(created[0].impact_gate)
    required = created[0].impact_gate(root, task(sample)['task_ref'], None)
    assert required['status'] == 'IMPACT_REQUIRED'
    assert not required['repair_authorized'] and not required['scanner_run']
    with pytest.raises(ValueError, match='PRODUCT_IMPACT_GATE_REQUIRED'):
        bind_impact_gate(created[0], None)


def test_native_guidance_does_not_send_host_risks_to_scanner_verification():
    from security_runtime.guidance.host_guidance import REPAIR_IMPACT_GUIDANCE
    assert 'do not call scanner verify_task_fix for a native risk' in REPAIR_IMPACT_GUIDANCE
    assert 'Native task repairs use their bound\nrepair_task_ref for finish/review' in REPAIR_IMPACT_GUIDANCE
