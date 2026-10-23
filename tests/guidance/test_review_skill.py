"""Only synthetic homes; never touch real Host configuration or skills."""
import json
import re

import pytest

from security_runtime.review_skill import ReviewSkillManager, RETIRED_METHODS, digest, skill_files
from security_runtime.guidance.host_guidance import HOST_INSTRUCTIONS, RUNTIME_WORKFLOW


def manager(tmp_path):
    return ReviewSkillManager(tmp_path/'home/.agents/skills',tmp_path/'state')


def legacy_manager(tmp_path):
    service = manager(tmp_path)
    # Synthetic bytes enrolled by the real signer, representing a previous
    # managed delivery. Matching unowned files never establish ownership.
    service.expected |= {name:('old managed method ' + name).encode() for name in RETIRED_METHODS}
    service.expected['SKILL.md'] += b'\nprevious managed entry\n'
    assert service.execute('install')['status'] == 'INSTALLED'
    return service


def test_repair_impact_examples_use_the_accepted_domain_contract():
    from pydantic import TypeAdapter
    from security_runtime.repair_impact_models import KINDS, proposal, reasoning, source, validate_impact_request
    from security_runtime.tasks.risk_fix import (
        NativeTaskReference, NativeFindingReference, NativeImpactReference,
    )

    reference = skill_files()['references/repair-impact.md'].decode('utf-8')
    examples = [json.loads(block) for block in re.findall(r'```json\n(.*?)\n```', reference, re.S)]
    assert [item['tool'] for item in examples] == [
        'prepare_repair_impact', 'prepare_task_risk_fix', 'submit_repair_impact', 'submit_repair_impact',
        'prepare_task_risk_fix', 'cancel_task_risk_fix', 'submit_repair_impact']
    prepare, intent, complete, partial, fix, cancel, blocked = [item['arguments'] for item in examples]
    for item in examples:
        if item['tool'] in {'prepare_repair_impact', 'submit_repair_impact'}:
            validate_impact_request(item['tool'], item['arguments'])
    assert source(prepare['source'])['kind'] == 'HOST_TASK_RISK'
    assert proposal(prepare['proposal'])['changes'][0]['file_path'] == 'documents.py'
    for submitted in (complete, partial, blocked):
        evidence = {ref for row in submitted['impacts'] + submitted['unknowns']
                    for ref in row['evidence_refs']}
        reasoning(submitted['impacts'], submitted['unknowns'], evidence)
        assert submitted['coverage'] in {'REVIEWED', 'PARTIAL'}
    assert complete['coverage'] == 'REVIEWED' and partial['coverage'] == 'PARTIAL'
    assert partial['unknowns'][0]['critical'] is True
    scope_unknowns = [row for row in complete['unknowns']
                      if row.get('classification') == 'SCOPE_LIMITATION']
    assert scope_unknowns
    assert all(row['critical'] is False and row['decision_basis'].strip() and row['evidence_refs']
               for row in scope_unknowns)
    blocking_unknowns = [row for row in blocked['unknowns']
                         if row.get('classification') == 'BLOCKING_CONTEXT']
    assert blocking_unknowns
    assert all(row['critical'] is True and row['decision_basis'].strip() and row['evidence_refs']
               for row in blocking_unknowns)
    assert fix['task_ref'] == prepare['source']['task_ref']
    assert fix['finding_id'] == prepare['source']['finding_id']
    assert fix['impact_ref'] == complete['assessment_ref']
    assert fix['user_requested'] is True and 'scan_id' not in fix
    TypeAdapter(NativeTaskReference).validate_python(fix['task_ref'])
    TypeAdapter(NativeFindingReference).validate_python(fix['finding_id'])
    TypeAdapter(NativeImpactReference).validate_python(fix['impact_ref'])
    assert intent == fix  # Retrying cannot select a fresh source or replacement baseline.
    assert cancel == dict(task_ref=fix['task_ref'], finding_id=fix['finding_id'], user_requested=True)
    assert all(kind in reference for kind in KINDS)


def test_native_fix_and_failed_impact_rules_reach_the_managed_skill():
    from security_runtime.guidance.host_guidance import REPAIR_IMPACT_GUIDANCE, REQUIRED_GUIDANCE_TOOLS

    files = skill_files()
    entry = files['SKILL.md'].decode('utf-8')
    assert 'references/repair-impact.md' in entry
    assert {'prepare_task_risk_fix', 'cancel_task_risk_fix'} <= REQUIRED_GUIDANCE_TOOLS
    for name in ('references/repair-impact.md',):
        method = files[name].decode('utf-8')
        assert REPAIR_IMPACT_GUIDANCE in method
        for rule in ('不能传入任务原生风险的 ts1 引用', '不通过新 begin_security_task',
                     '技术性提交失败不重复索取同一批准', '只读查询不索取新的修复或业务批准',
                     '直接保存对应处置', '任意外部编辑', 'risk_resolutions 仍绑定原 task_ref／finding_id',
                     'cancel_task_risk_fix', '取消不代表 DEFER／EXCLUDE', '只保存 WAITING 意图、不建基线'):
            assert rule in method
    assert '不能用普通 begin_security_task 绕过' in entry
    assert '明确暂缓则直接保存 DEFER' in entry
    assert '尽早登记原修复意图' in entry
    workflow = files['references/runtime-workflow.md'].decode('utf-8')
    assert 'topic=repair-impact' in workflow
    assert REPAIR_IMPACT_GUIDANCE not in workflow


def test_lifecycle_canonical_workflow_and_user_bytes_preserved(tmp_path):
    service=manager(tmp_path)
    home=tmp_path/'home'
    sibling=home/'.agents/skills/other/SKILL.md'
    sibling.parent.mkdir(parents=True)
    sibling.write_bytes(b'user skill\r\n')
    assert service.status()['status']=='NOT_INSTALLED'
    assert not service.state.exists()  # status is read-only
    assert service.execute('install')['status']=='INSTALLED'
    reference=service.root/'references/runtime-workflow.md'
    assert RUNTIME_WORKFLOW in reference.read_text(encoding='utf-8')
    assert 'references/quick-task-review-v3.md' in reference.read_text(encoding='utf-8')
    assert 'prepare_task_security_review(protocol_version=3)' in (service.root/'SKILL.md').read_text(encoding='utf-8')
    assert not RETIRED_METHODS & service.manifest()['files'].keys()
    assert all(not (service.root/name).exists() for name in RETIRED_METHODS)
    v3_method=service.root/'references/quick-task-review-v3.md'
    assert v3_method.read_bytes()==skill_files()['references/quick-task-review-v3.md']
    assert 'references/quick-task-review-v3.md' in service.manifest()['files']
    assert service.manifest()['scope']=='USER'
    custom=service.root/'custom-notes.txt';custom.write_bytes(b'personal\r\n')
    assert service.execute('repair')['changed'] is False
    service.expected['SKILL.md']+=b'\nUpdated synthetic guidance\n'
    assert service.status()['status']=='UPGRADE_AVAILABLE'
    assert service.execute('upgrade')['status']=='INSTALLED'
    reference.unlink()
    assert service.status()['status']=='REPAIR_REQUIRED'
    assert service.execute('repair')['status']=='INSTALLED'
    assert service.execute('remove')['status']=='REMOVED'
    assert custom.read_bytes()==b'personal\r\n'
    assert sibling.read_bytes()==b'user skill\r\n'
    assert not reference.exists()
    assert not v3_method.exists()


@pytest.mark.parametrize('method',['references/quick-task-review-v3.md','references/risk-decisions.md','references/repair-impact.md'])
def test_legacy_skill_upgrade_adds_signed_versioned_method_without_replacing_user_files(tmp_path,method):
    legacy=manager(tmp_path)
    legacy.expected.pop(method)
    assert legacy.execute('install')['status']=='INSTALLED'
    custom=legacy.root/'custom-notes.txt';custom.write_bytes(b'user notes\r\n')
    upgraded=manager(tmp_path)
    assert upgraded.status()['status']=='UPGRADE_AVAILABLE'
    assert upgraded.execute('upgrade')['status']=='INSTALLED'
    assert (upgraded.root/method).read_bytes()==skill_files()[method]
    assert method in upgraded.manifest()['files']
    assert custom.read_bytes()==b'user notes\r\n'


@pytest.mark.parametrize('method',['references/quick-task-review-v3.md','references/risk-decisions.md','references/repair-impact.md'])
def test_legacy_skill_upgrade_does_not_adopt_unowned_versioned_method(tmp_path,method):
    legacy=manager(tmp_path)
    legacy.expected.pop(method)
    legacy.execute('install')
    path=legacy.root/method;path.write_bytes(b'user authored review method\r\n')
    upgraded=manager(tmp_path)
    before=upgraded.manifest()
    assert upgraded.execute('upgrade')['status']=='USER_MODIFIED'
    assert path.read_bytes()==b'user authored review method\r\n'
    assert upgraded.manifest()==before and method not in before['files']


@pytest.mark.parametrize('action',['install','upgrade','repair','remove'])
def test_managed_user_edits_never_overwritten_or_deleted(tmp_path,action):
    service=manager(tmp_path);service.execute('install')
    path=service.root/'SKILL.md';path.write_bytes(b'customized instructions')
    result=service.execute(action)
    assert result['status']=='USER_MODIFIED' and not result['changed']
    assert path.read_bytes()==b'customized instructions'


def test_unattested_matching_files_not_automatically_claimed(tmp_path):
    service=manager(tmp_path);service.root.mkdir(parents=True)
    (service.root/'SKILL.md').write_bytes(skill_files()['SKILL.md'])
    assert service.execute('install')['status']=='USER_MANAGED'
    assert not (service.state/'ownership.json').exists()


def test_manifest_tamper_fail_closed(tmp_path):
    service=manager(tmp_path);service.execute('install')
    path=service.state/'ownership.json'
    data=json.loads(path.read_bytes());data['signature']='0'*64
    path.write_text(json.dumps(data))
    before=(service.root/'SKILL.md').read_bytes()
    assert service.execute('repair')['status']=='OWNERSHIP_CONFLICT'
    assert (service.root/'SKILL.md').read_bytes()==before


def test_interrupted_upgrade_recoverable(tmp_path,monkeypatch):
    import security_runtime.review_skill as module
    service=manager(tmp_path);service.execute('install')
    service.expected['SKILL.md']+=b'\nnew\n'
    original=module.atomic_bytes
    def fail(path,content):
        if path.name=='openai.yaml': raise OSError('synthetic write failure')
        return original(path,content)
    monkeypatch.setattr(module,'atomic_bytes',fail)
    with pytest.raises(OSError): service.execute('upgrade')
    assert service.status()['status']=='REPAIR_REQUIRED'
    monkeypatch.setattr(module,'atomic_bytes',original)
    assert service.execute('repair')['status']=='INSTALLED'


def test_changed_during_write_not_claimed(tmp_path,monkeypatch):
    service=manager(tmp_path);service.execute('install')
    service.expected['SKILL.md']+=b'\nnew\n'
    original=service.save
    def interfere(value):
        original(value)
        if value['phase']=='UPDATING': (service.root/'SKILL.md').write_bytes(b'user edit')
    monkeypatch.setattr(service,'save',interfere)
    with pytest.raises(ValueError,match='CHANGED_DURING_UPDATE'): service.execute('upgrade')
    assert service.status()['status']=='USER_MODIFIED'


def test_install_never_changes_codex_config_or_trust(tmp_path):
    service=manager(tmp_path)
    codex=tmp_path/'home/.codex';codex.mkdir(parents=True)
    files={'config.toml':b'[marketplaces]\n', 'hooks.json':b'{"hooks":{},"state":"user"}',
           'trust.json':b'user host metadata'}
    for name,raw in files.items(): (codex/name).write_bytes(raw)
    for action in ('install','status','upgrade','repair','remove'): service.execute(action)
    assert {name:(codex/name).read_bytes() for name in files}==files


@pytest.mark.parametrize('action', ['upgrade', 'repair'])
def test_v3_upgrade_removes_only_attested_retired_methods(tmp_path, action):
    old = legacy_manager(tmp_path)
    key = (old.state/'ownership.key').read_bytes()
    notes = old.root/'references/user-method.md'
    notes.write_bytes(b'user reference\r\n')
    service = manager(tmp_path)
    assert service.status()['status'] == 'UPGRADE_AVAILABLE'
    assert service.execute(action)['status'] == 'INSTALLED'
    assert all(not (service.root/name).exists() for name in RETIRED_METHODS)
    assert service.manifest()['files'] == {name:digest(raw) for name,raw in skill_files().items()}
    assert service.manifest()['cleanup'] == service.manifest()['previous'] == {}
    assert (service.state/'ownership.key').read_bytes() == key
    assert notes.read_bytes() == b'user reference\r\n'


def test_modified_retired_method_is_detached_and_survives_upgrade_and_removal(tmp_path):
    old = legacy_manager(tmp_path)
    name = sorted(RETIRED_METHODS)[0]
    path = old.root/name
    path.write_bytes(b'personal legacy method\r\n')
    service = manager(tmp_path)
    status = service.status()
    assert status['status'] == 'UPGRADE_AVAILABLE'
    assert status['preserved_retired_files'] == [name]
    assert status['installed_content_sha256'] is None
    result = service.execute('upgrade')
    assert result['status'] == 'INSTALLED' and result['preserved_retired_files'] == [name]
    assert path.read_bytes() == b'personal legacy method\r\n'
    receipt = service.manifest()
    assert name not in receipt['files'] and name not in receipt['previous'] and name not in receipt['cleanup']
    assert (service.root/'SKILL.md').read_bytes() == skill_files()['SKILL.md']
    assert service.execute('remove')['status'] == 'REMOVED'
    assert path.read_bytes() == b'personal legacy method\r\n'


def test_unowned_retired_methods_are_not_adopted_even_if_bytes_match_old_delivery(tmp_path):
    service = manager(tmp_path)
    service.execute('install')
    originals = {name:('old managed method ' + name).encode() for name in RETIRED_METHODS}
    for name, raw in originals.items(): (service.root/name).write_bytes(raw)
    service.expected['SKILL.md'] += b'\nnew managed guidance\n'
    assert service.execute('upgrade')['status'] == 'INSTALLED'
    assert not RETIRED_METHODS & service.manifest()['files'].keys()
    assert service.execute('remove')['status'] == 'REMOVED'
    assert {name:(service.root/name).read_bytes() for name in originals} == originals


def test_modified_current_entry_blocks_retired_method_cleanup(tmp_path):
    old = legacy_manager(tmp_path)
    originals = {name:(old.root/name).read_bytes() for name in RETIRED_METHODS}
    (old.root/'SKILL.md').write_bytes(b'personal entry')
    service = manager(tmp_path)
    assert service.execute('upgrade')['status'] == 'USER_MODIFIED'
    assert (service.root/'SKILL.md').read_bytes() == b'personal entry'
    assert {name:(service.root/name).read_bytes() for name in originals} == originals


@pytest.mark.parametrize('failure', ['between_deletions', 'before_commit'])
def test_interrupted_retired_cleanup_resumes_from_signed_receipt(tmp_path, monkeypatch, failure):
    legacy_manager(tmp_path)
    service = manager(tmp_path)
    original_write, original_save = service.write, service.save
    deleted = []
    def write(path, raw):
        if raw is None and path.relative_to(service.root).as_posix() in RETIRED_METHODS:
            if failure == 'between_deletions' and deleted:
                raise OSError('synthetic cleanup interruption')
            original_write(path, raw)
            deleted.append(path)
        else:
            original_write(path, raw)
    def save(value):
        if failure == 'before_commit' and value['phase'] == 'COMMITTED':
            raise OSError('synthetic commit interruption')
        original_save(value)
    monkeypatch.setattr(service, 'write', write)
    monkeypatch.setattr(service, 'save', save)
    with pytest.raises(OSError): service.execute('upgrade')
    assert len(deleted) == (1 if failure == 'between_deletions' else 2)
    receipt = service.manifest()
    assert receipt['phase'] == 'UPDATING' and set(receipt['cleanup']) == RETIRED_METHODS
    assert not RETIRED_METHODS & receipt['files'].keys()
    assert service.status()['status'] == 'REPAIR_REQUIRED'
    monkeypatch.setattr(service, 'write', original_write)
    monkeypatch.setattr(service, 'save', original_save)
    assert service.execute('repair')['status'] == 'INSTALLED'
    assert all(not (service.root/name).exists() for name in RETIRED_METHODS)
    assert service.manifest()['cleanup'] == {}


def test_retired_user_edit_during_cleanup_is_preserved_on_recovery(tmp_path, monkeypatch):
    legacy_manager(tmp_path)
    service = manager(tmp_path)
    name = sorted(RETIRED_METHODS)[0]
    path = service.root/name
    original = service.save
    def interfere(value):
        original(value)
        if value['phase'] == 'UPDATING': path.write_bytes(b'user edit during cleanup')
    monkeypatch.setattr(service, 'save', interfere)
    with pytest.raises(ValueError, match='CHANGED_DURING_UPDATE'): service.execute('upgrade')
    assert path.read_bytes() == b'user edit during cleanup'
    monkeypatch.setattr(service, 'save', original)
    result = service.execute('repair')
    assert result['status'] == 'INSTALLED' and result['preserved_retired_files'] == [name]
    assert path.read_bytes() == b'user edit during cleanup'
    assert name not in service.manifest()['cleanup']


@pytest.mark.parametrize('name', ['../outside.md', 'SKILL.md', 'references/unknown-method.md'])
def test_cleanup_receipt_rejects_paths_outside_fixed_retirement_set(tmp_path, name):
    service = manager(tmp_path)
    service.execute('install')
    receipt = service.manifest()
    service.save(receipt | {'phase':'UPDATING', 'cleanup':{name:'a'*64}})
    before = (service.root/'SKILL.md').read_bytes()
    assert service.execute('repair')['status'] == 'OWNERSHIP_CONFLICT'
    assert (service.root/'SKILL.md').read_bytes() == before


def test_overlapping_upgrade_cannot_change_signed_ownership_or_delete_methods(tmp_path):
    from security_runtime.hook_state import HookStateStore
    legacy_manager(tmp_path)
    service = manager(tmp_path)
    before = (service.state/'ownership.json').read_bytes()
    originals = {name:(service.root/name).read_bytes() for name in RETIRED_METHODS}
    with HookStateStore(service.state/'locks').lock(service.root) as acquired:
        assert acquired
        with pytest.raises(ValueError, match='SKILL_BUSY'): service.execute('upgrade')
        assert (service.state/'ownership.json').read_bytes() == before
        assert {name:(service.root/name).read_bytes() for name in originals} == originals
    assert service.execute('upgrade')['status'] == 'INSTALLED'


def test_user_edit_after_status_is_not_resigned_as_previous_content(tmp_path, monkeypatch):
    legacy_manager(tmp_path)
    service = manager(tmp_path)
    original = service.status
    receipt = (service.state/'ownership.json').read_bytes()
    def interfere():
        result = original()
        (service.root/'SKILL.md').write_bytes(b'user entry changed after status')
        return result
    monkeypatch.setattr(service, 'status', interfere)
    with pytest.raises(ValueError, match='CHANGED_DURING_UPDATE'): service.execute('upgrade')
    assert (service.state/'ownership.json').read_bytes() == receipt
    assert (service.root/'SKILL.md').read_bytes() == b'user entry changed after status'
