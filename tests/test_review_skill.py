"""Only synthetic homes; never touch real Host configuration or skills."""
import json
import re

import pytest

from security_runtime.review_skill import ReviewSkillManager, skill_files
from security_runtime.host_guidance import HOST_INSTRUCTIONS


def manager(tmp_path):
    return ReviewSkillManager(tmp_path/'home/.agents/skills',tmp_path/'state')


def test_repair_impact_examples_use_the_accepted_domain_contract():
    from pydantic import TypeAdapter
    from security_runtime.repair_impact_models import KINDS, proposal, reasoning, source, validate_impact_request
    from security_runtime.task_risk_fix import NativeTaskReference, NativeFindingReference, NativeImpactReference

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
    from security_runtime.host_guidance import REPAIR_IMPACT_GUIDANCE, REQUIRED_GUIDANCE_TOOLS

    files = skill_files()
    entry = files['SKILL.md'].decode('utf-8')
    assert 'references/repair-impact.md' in entry
    assert {'prepare_task_risk_fix', 'cancel_task_risk_fix'} <= REQUIRED_GUIDANCE_TOOLS
    for name in ('references/runtime-workflow.md', 'references/repair-impact.md'):
        method = files[name].decode('utf-8')
        assert REPAIR_IMPACT_GUIDANCE in method
        for rule in ('不能传入任务原生风险的 ts1 引用', '不通过新 begin_security_task',
                     '技术性提交失败不重复索取同一批准', '只读查询不索取新的修复或业务批准',
                     '直接保存对应处置', '任意外部编辑', 'risk_resolutions 仍绑定原 task_ref／finding_id',
                     'cancel_task_risk_fix', '取消不代表 DEFER／EXCLUDE', '只保存 WAITING 意图、不建基线'):
            assert rule in method
    assert '不能用普通 begin_security_task 绕过' in entry
    assert '明确暂缓则直接保存 DEFER' in entry
    assert '尽早调用 prepare_task_risk_fix 登记意图' in entry


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
    assert HOST_INSTRUCTIONS in reference.read_text(encoding='utf-8')
    assert 'prepare_task_security_review(protocol_version=3)' in reference.read_text(encoding='utf-8')
    v2_method=service.root/'references/quick-task-review-v2.md'
    assert v2_method.read_bytes()==skill_files()['references/quick-task-review-v2.md']
    assert 'references/quick-task-review-v2.md' in service.manifest()['files']
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
    assert not v2_method.exists()
    assert not v3_method.exists()


@pytest.mark.parametrize('method',['references/quick-task-review-v2.md','references/quick-task-review-v3.md','references/risk-decisions.md','references/repair-impact.md'])
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


@pytest.mark.parametrize('method',['references/quick-task-review-v2.md','references/quick-task-review-v3.md','references/risk-decisions.md','references/repair-impact.md'])
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
