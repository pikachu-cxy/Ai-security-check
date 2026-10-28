"""Exercise the CLI byte boundary, including Cursor's Windows PS transport."""
import io
import json
import os
import subprocess
import sys
from types import SimpleNamespace

import pytest

from security_runtime import cursor_hook

BOM = b'\xef\xbb\xbf'


@pytest.mark.parametrize('count', [0, 1, 2])
def test_preamble_preserves_claims_and_unicode(count):
    value = {'hook_event_name': 'preToolUse', 'conversation_id': 'fixture',
             'tool_input': {'text': '\ufeff中文'}}
    assert cursor_hook.parse_hook_input(BOM * count + json.dumps(value, ensure_ascii=False).encode()) == value


@pytest.mark.parametrize('raw', [BOM * 3 + b'{}', BOM * 2 + b'{"a":1,"a":2}',
                                b'{', b'', BOM * 2 + b'\xff', b' ' * 1_000_001],
                         ids=['excess-bom', 'duplicate-key', 'syntax', 'empty', 'encoding', 'oversized'])
def test_invalid_input_still_rejected(raw):
    with pytest.raises((ValueError, UnicodeError)):
        cursor_hook.parse_hook_input(raw)


def test_cli_passes_double_bom_event_and_diagnoses_invalid_input(monkeypatch, capsys):
    seen = []
    def handler(payload, **kwargs):
        seen.append(payload)
        return {}, {}
    monkeypatch.setattr(cursor_hook, 'handle_cursor_event', handler)
    for raw in (BOM * 2 + b'{"hook_event_name":"preToolUse"}', b'private-invalid-content'):
        monkeypatch.setattr(cursor_hook.sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(raw)))
        assert cursor_hook.main(automatic=True) == 0
    assert seen == [{'hook_event_name': 'preToolUse'}, None]
    output = capsys.readouterr()
    assert output.out == '{}\n{}\n'
    assert 'CURSOR_HOOK_INPUT_INVALID' in output.err
    assert 'private-invalid-content' not in output.err


@pytest.mark.skipif(os.name != 'nt', reason='Windows PowerShell transport')
def test_real_windows_powershell_pipeline(tmp_path):
    payload = tmp_path/'payload.json'
    payload.write_text('{"hook_event_name":"preToolUse","conversation_id":"fixture"}', encoding='utf-8')
    probe = tmp_path/'probe.py'
    probe.write_text('import sys, json\nfrom security_runtime.cursor_hook import parse_hook_input\n'
                     'print(json.dumps(parse_hook_input(sys.stdin.buffer.read(1000001))))\n', encoding='utf-8')
    def quote(value):
        return "'" + str(value).replace("'", "''") + "'"
    # Same nested pipeline and UTF8 OutputEncoding as Cursor desktop 3.24.18.
    command = ('$OutputEncoding = [System.Text.Encoding]::UTF8; Get-Content -LiteralPath '
               + quote(payload) + ' -Raw | & { $input | & ' + quote(sys.executable)
               + ' -I ' + quote(probe) + ' }')
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', command],
                            capture_output=True, text=True, timeout=20, check=True)
    assert not result.stderr
    assert json.loads(result.stdout) == {'hook_event_name': 'preToolUse', 'conversation_id': 'fixture'}
