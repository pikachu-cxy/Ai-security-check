"""The installed child's progress is live, bounded and never raw scanner output."""
import json
import sys
from types import SimpleNamespace

from security_runtime.install_progress import STAGE_PREFIX
from security_runtime.processes import run_process
import security_runtime.personal_install as personal
from test_personal_install_readiness import readiness


def test_fixed_stage_tokens_only_and_receipt_remains_authoritative(monkeypatch):
    stages = []
    def child(argv, **kwargs):
        relay = kwargs['on_stderr_line']
        for line in ['private scanner output', STAGE_PREFIX + 'INSTALL_DATA',
                     STAGE_PREFIX + 'INSTALL_DATA', STAGE_PREFIX + 'UNKNOWN',
                     STAGE_PREFIX + 'INSTALL_DATA private', STAGE_PREFIX + 'VERIFY_SCAN_READINESS']:
            relay(line)
        return SimpleNamespace(returncode=2, stdout=json.dumps(readiness(ready=False, freshness='STALE')))
    monkeypatch.setattr(personal, 'run_process', child)
    receipt, diagnostic = personal._prepare_child('validated-executable', offline=True, progress=stages.append)
    assert stages == ['CHECK_SCAN_CACHE', 'VERIFY_SCAN_READINESS']
    assert receipt['ready'] is False and diagnostic is None
    assert 'private' not in json.dumps(receipt)


def test_stage_arrives_before_child_completes(tmp_path):
    acknowledgement = tmp_path / 'parent-received-stage'
    script = ("import sys,time;from pathlib import Path;"
              f"p=Path({str(acknowledgement)!r});"
              f"print({(STAGE_PREFIX + 'INSTALL_DATA')!r},file=sys.stderr,flush=True);"
              "deadline=time.monotonic()+4\n"
              "while not p.exists() and time.monotonic()<deadline: time.sleep(.01)\n"
              "sys.exit(0 if p.exists() else 3)")
    lines = []
    def receive(line):
        lines.append(line)
        acknowledgement.touch()
    result = run_process([sys.executable, '-c', script], on_stderr_line=receive, timeout=6)
    assert result.returncode == 0
    assert lines == [STAGE_PREFIX + 'INSTALL_DATA']


def test_oversized_stderr_line_cannot_reappear_as_a_valid_suffix():
    lines = []
    script = ("import sys;"
              "sys.stderr.write('x'*10000+'AI_SECURITY_INSTALL_STAGE:INSTALL_DATA\\n');"
              "sys.stderr.flush();"
              "print('AI_SECURITY_INSTALL_STAGE:VERIFY_SCAN_READINESS',file=sys.stderr,flush=True)")
    result = run_process([sys.executable, '-c', script], on_stderr_line=lines.append)
    assert result.returncode == 0
    assert lines == [STAGE_PREFIX + 'VERIFY_SCAN_READINESS']
