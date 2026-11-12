"""WorkBuddy hook failures stay observable without leaking host details."""
import io
import json
import sys

import pytest

from security_runtime.workbuddy_hook import reason_code


class _Stdin:
    def __init__(self, data):
        self.buffer = io.BytesIO(data)


def _run(monkeypatch, payload, capsys):
    raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    monkeypatch.setattr(sys, 'stdin', _Stdin(raw))
    from security_runtime.workbuddy_hook import main
    assert main() == 0
    return json.loads(capsys.readouterr().out)


@pytest.mark.parametrize('code', [
    'INVALID_HOST_EVENT', 'INVALID_TURN', 'INVALID_STOP_GUARD',
    'GLOBAL_CONFIGURATION_NOT_READY', 'LEGACY_PROJECT_CONFIGURATION_REQUIRES_REPAIR',
    'UNOWNED_RUNTIME_MCP', 'HOOK_INPUT_TOO_LARGE',
])
def test_stable_codes_are_preserved(code):
    assert reason_code(ValueError(code)) == code


def test_free_text_never_reaches_the_host():
    # A workspace path or session value must not be echoed back to the transcript.
    error = ValueError(r'Host event does not belong to configured workspace C:\Users\someone\secret-repo')
    assert reason_code(error) == 'UNEXPECTED_FAILURE'


def test_os_and_payload_failures_get_their_own_codes():
    assert reason_code(OSError('device unavailable')) == 'HOST_IO_FAILED'
    try:
        json.loads(b'{not-json')
    except json.JSONDecodeError as exc:
        assert reason_code(exc) == 'INVALID_HOST_PAYLOAD'


def test_unreadable_payload_reports_the_payload_code(monkeypatch, capsys):
    output = _run(monkeypatch, b'{not-json', capsys)
    assert 'INVALID_HOST_PAYLOAD' in output['systemMessage']


def test_unsupported_event_reports_the_event_code(monkeypatch, capsys):
    output = _run(monkeypatch, {'hook_event_name': 'Unknown'}, capsys)
    assert 'INVALID_HOST_EVENT' in output['systemMessage']


def test_oversized_input_reports_the_size_code(monkeypatch, capsys):
    output = _run(monkeypatch, b'x' * 100_001, capsys)
    assert 'HOOK_INPUT_TOO_LARGE' in output['systemMessage']


def test_failure_message_still_lets_development_continue(monkeypatch, capsys):
    output = _run(monkeypatch, b'{not-json', capsys)
    assert set(output) == {'systemMessage'}
    assert '正常开发可继续' in output['systemMessage']
