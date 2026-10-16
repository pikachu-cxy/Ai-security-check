"""Routine preapprovals preserve existing grants and never add repair authority."""
import json
import os
import sqlite3
import sys
from pathlib import Path

import pytest

from security_runtime.cursor_permissions import CursorRoutinePermissions, ENTRIES, document, edit_allowlist, ide_allowlist
from security_runtime.hook_state import HookStateStore
from security_runtime.owned_json import WriteTransaction
from test_cursor_automatic import integration


@pytest.fixture
def permissions(tmp_path):
    home = tmp_path/'cursor home'
    home.mkdir()
    return CursorRoutinePermissions(home, HookStateStore(tmp_path/'state'))


def test_setup_exact_routine_tools_idempotent_remove(permissions):
    permissions.execute('setup')
    entries = json.loads(permissions.path.read_bytes())['mcpAllowlist']
    assert len(entries) == 10 and len(set(entries)) == 10
    assert all(v.startswith('ai-security-runtime:') and '*' not in v for v in entries)
    assert not any(v.rsplit(':', 1)[1] in {
        'confirm_remediation', 'refresh_remediation_confirmation', 'prepare_task_fix',
        'generate_fix', 'verify_task_fix', 'scan_project', 'scan_diff'} for v in entries)
    before = permissions.path.read_bytes(), permissions.manifest.read_bytes()
    permissions.execute('repair')
    assert before == (permissions.path.read_bytes(), permissions.manifest.read_bytes())
    assert permissions.status()['status'] == 'CONFIGURED'
    assert permissions.status()['live_no_prompt_verified'] is False
    permissions.execute('remove')
    assert not permissions.path.exists() and not permissions.manifest.exists()


@pytest.mark.parametrize('array', [
    '[]', '["github:list_issues"]', '["github:list_issues",]',
    '[/* before */ "github:list_issues" // after\n]',
    '["github:list_issues", /* comma */]',
    '["github:list_issues", "AI-SECURITY-RUNTIME:GET_RUNTIME_INFO"]',
])
def test_jsonc_existing_grants_comments_and_other_fields_preserved(permissions,array):
    original = ('{ // top\n "mcpAllowlist": '+array+',\n'
                ' "terminalAllowlist": ["git status"], "autoRun": {"block_instructions":["user policy"]},\n}').encode()
    permissions.path.write_bytes(original)
    original_value = document(original)[3]
    permissions.execute('setup')
    current = permissions.path.read_bytes()
    value = document(current)[3]
    assert value['terminalAllowlist'] == original_value['terminalAllowlist']
    assert value['autoRun'] == original_value['autoRun']
    assert value['mcpAllowlist'][:len(original_value['mcpAllowlist'])] == original_value['mcpAllowlist']
    for comment in ['// top', '/* before */', '// after', '/* comma */']:
        if comment.encode() in original:
            assert comment.encode() in current
    permissions.execute('remove')
    removed = permissions.path.read_bytes()
    assert document(removed)[3] == original_value
    for comment in ['// top', '/* before */', '// after', '/* comma */']:
        if comment.encode() in original:
            assert comment.encode() in removed


def test_missing_key_removal_preserves_comments_and_user_fields(permissions):
    permissions.path.write_bytes(b'{"terminalAllowlist":["git status"] // comment\n}')
    permissions.execute('setup')
    permissions.execute('remove')
    raw = permissions.path.read_bytes()
    assert document(raw)[3] == {'terminalAllowlist':['git status']}
    assert b'// comment' in raw


def test_import_ide_allowlist_before_file_overrides_it(permissions):
    permissions.existing_allowlist = lambda _: ['github:list_issues', 'AI-SECURITY-RUNTIME:GET_RUNTIME_INFO']
    permissions.execute('setup')
    value = document(permissions.path.read_bytes())[3]
    assert value['mcpAllowlist'][:2] == ['github:list_issues', 'AI-SECURITY-RUNTIME:GET_RUNTIME_INFO']
    assert 'ai-security-runtime:get_runtime_info' not in value['mcpAllowlist']
    assert 'ai-security-runtime:get_runtime_info' not in permissions.inspect()[3]['added']


def test_uninstall_without_manifest_does_not_adopt_existing_grants(permissions):
    raw = json.dumps({'mcpAllowlist':list(ENTRIES)}).encode()
    permissions.path.write_bytes(raw)
    permissions.execute('remove')
    assert permissions.path.read_bytes() == raw


def test_user_added_grants_and_policy_survive_uninstall(permissions):
    permissions.execute('setup')
    value = document(permissions.path.read_bytes())[3]
    value['mcpAllowlist'].append('github:list_issues')
    value['terminalAllowlist'] = ['git status']
    permissions.path.write_text(json.dumps(value))
    permissions.execute('remove')
    assert document(permissions.path.read_bytes())[3] == {
        'mcpAllowlist':['github:list_issues'], 'terminalAllowlist':['git status']}


def test_ambiguous_user_duplicate_not_deleted(permissions):
    permissions.execute('setup')
    value = document(permissions.path.read_bytes())[3]
    value['mcpAllowlist'].append(ENTRIES[0])
    permissions.path.write_text(json.dumps(value))
    permissions.execute('remove')
    assert document(permissions.path.read_bytes())[3]['mcpAllowlist'] == [ENTRIES[0], ENTRIES[0]]


@pytest.mark.parametrize('raw', [b'{"mcpAllowlist":true}', b'{"mcpAllowlist":[1]}',
    b'{"mcpAllowlist":[],"mcpAllowlist":[]}', b'{/* unfinished', b'[]', b'{"a":"unfinished}'])
def test_invalid_configuration_never_replaced(permissions,raw):
    permissions.path.write_bytes(raw)
    with pytest.raises(ValueError):
        permissions.execute('setup')
    assert permissions.path.read_bytes() == raw
    assert not permissions.manifest.exists()


def test_tampered_ownership_preserves_permissions(permissions):
    permissions.execute('setup')
    raw = permissions.path.read_bytes()
    value = json.loads(permissions.manifest.read_bytes())
    value['added'] = ['ai-security-runtime:confirm_remediation']
    permissions.manifest.write_text(json.dumps(value))
    with pytest.raises(ValueError):
        permissions.execute('remove')
    assert permissions.path.read_bytes() == raw


def test_permission_failure_rolls_back_connector_install(integration,monkeypatch):
    def fail(*a):
        raise OSError('fixture')
    monkeypatch.setattr(CursorRoutinePermissions,'execute',fail)
    with pytest.raises(OSError):
        integration.execute('setup')
    assert not (integration.home/'hooks.json').exists()
    assert not (integration.home/'mcp.json').exists()
    assert integration.skill.status()['status'] == 'NOT_INSTALLED'


def test_concurrent_user_edit_preserved_on_rollback(permissions):
    tx = WriteTransaction()
    permissions.observer = tx.observe
    permissions.execute('setup')
    permissions.path.write_bytes(b'{"mcpAllowlist":["user:tool"]}')
    assert not tx.rollback()
    assert permissions.path.read_bytes() == b'{"mcpAllowlist":["user:tool"]}'


def test_unavailable_ide_source_does_not_override_permissions(permissions):
    def fail(_):
        raise ValueError('CURSOR_PERMISSION_SOURCE_UNAVAILABLE')
    permissions.existing_allowlist = fail
    with pytest.raises(ValueError,match='SOURCE_UNAVAILABLE'):
        permissions.execute('setup')
    assert not permissions.path.exists()


def test_read_existing_ide_approvals_without_modifying_database(tmp_path,monkeypatch):
    monkeypatch.setattr(Path,'home',classmethod(lambda cls: tmp_path))
    monkeypatch.setenv('APPDATA',str(tmp_path/'roaming'))
    monkeypatch.setenv('XDG_CONFIG_HOME',str(tmp_path/'config'))
    profile = (tmp_path/'roaming/Cursor' if os.name=='nt' else
               tmp_path/'Library/Application Support/Cursor' if sys.platform=='darwin' else
               tmp_path/'config/Cursor')
    path=profile/'User/globalStorage/state.vscdb'
    path.parent.mkdir(parents=True)
    key='src.vs.platform.reactivestorage.browser.reactiveStorageServiceImpl.persistentStorage.applicationUser'
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE ItemTable(key TEXT,value TEXT)')
        db.execute('INSERT INTO ItemTable VALUES (?,?)',(key,json.dumps({'composerState':{
            'mcpAllowedTools':['github:list_issues'], 'yoloCommandAllowlist':['user command']}})))
    before=path.read_bytes()
    assert ide_allowlist(tmp_path/'.cursor') == ['github:list_issues']
    assert path.read_bytes()==before
    assert ide_allowlist(tmp_path/'isolated') == []


def test_existing_user_approvals_not_reformatted_when_uninstall_owns_none(permissions):
    raw=('/* user */ {"mcpAllowlist":'+json.dumps(list(ENTRIES))+',}').encode()
    permissions.path.write_bytes(raw)
    permissions.execute('setup')
    permissions.execute('remove')
    assert permissions.path.read_bytes()==raw


def test_bom_and_comments_on_owned_entry_survive_remove(permissions):
    original=b'\xef\xbb\xbf{"mcpAllowlist":[],"other":{"url":"https://example.test/x//y"}}'
    permissions.path.write_bytes(original)
    permissions.execute('setup')
    changed=permissions.path.read_bytes().replace(b'"ai-security-runtime:finish_security_task"',
        b'/* retained user note */ "ai-security-runtime:finish_security_task"')
    permissions.path.write_bytes(changed)
    permissions.execute('remove')
    assert permissions.path.read_bytes().startswith(b'\xef\xbb\xbf')
    assert b'/* retained user note */' in permissions.path.read_bytes()
    assert document(permissions.path.read_bytes())[3]==document(original)[3]
