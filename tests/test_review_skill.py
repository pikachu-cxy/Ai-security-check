"""Only synthetic homes; never touch real Host configuration or skills."""
import json

import pytest

from security_runtime.review_skill import ReviewSkillManager, skill_files
from security_runtime.host_guidance import HOST_INSTRUCTIONS


def manager(tmp_path):
    return ReviewSkillManager(tmp_path/'home/.agents/skills',tmp_path/'state')


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
