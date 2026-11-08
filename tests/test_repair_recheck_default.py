"""Repair edits keep ordinary scanning; an extra verifier requires opt-in."""
import os
from pathlib import Path

from test_remediation import setup, prepare, FIXED, repo
from security_runtime.user_config import read_config
from security_runtime.remediation import automatic_recheck_enabled, confirmed_guidance


def test_extra_recheck_is_disabled_in_omitted_configuration(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_CONFIG', str(tmp_path/'absent.toml'))
    assert read_config()['values']['development']['repair_recheck_enabled'] is False
    assert automatic_recheck_enabled() is False
    assert 'do not start an extra scan' in confirmed_guidance()


def test_repair_post_hook_never_invokes_extra_verifier_when_disabled(setup, monkeypatch):
    root, runtime, provider, service, hook, grant = setup
    Path(os.environ['SECURITY_RUNTIME_CONFIG']).write_text('[development]\nrepair_recheck_enabled=false\n')
    packet = prepare(setup)
    assert packet['verification_plan']['automatic'] is False
    assert 'do not start an extra scan' in packet['host_protocol']['instructions']
    def forbidden(*a, **kw):
        raise AssertionError('Disabled repair recheck must not scan')
    monkeypatch.setattr(service, '_security_recheck', forbidden)
    (root/'A.java').write_text(FIXED)
    runtime.findings = provider.findings = []
    result = hook()
    assert result['status'] == 'SCANNED'
    assert result.get('remediation', {}).get('reason_code') != 'SCANNER_VERIFIED_RESOLVED'
