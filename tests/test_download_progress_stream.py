"""Concatenated live Trivy progress parsing and transport; no network."""
import sys

import security_runtime.install_progress as install_progress
from security_runtime.preparation_budget import preparation_budget
from security_runtime.processes import run_process
from security_runtime.toolchain import ToolStatus
from test_preparation_download import database


def _parser():
    parser_type = getattr(install_progress, 'DownloadProgressParser', None)
    assert parser_type is not None, 'Live progress requires a bounded incremental byte parser'
    return parser_type()


def test_concatenated_frames_and_split_chunks_are_emitted_once():
    parser = _parser()
    chunks = [
        b'0.25 Mi',
        b'B / 2.00 MiB [==>] 12.5% ETA1m13s0.',
        b'50 MiB / 2.00 MiB [====>] 25% ETA1m12s0.75 MiB / 2.',
        b'00 MiB [======>] 37.5% ETA1m11s',
    ]
    observed = [count for chunk in chunks for count in parser.feed(chunk)]
    assert observed == [(262144, 2097152), (524288, 2097152), (786432, 2097152)]
    assert parser.feed(b'') == [], 'An already parsed frame must not be emitted twice'
    assert parser.feed(b'garbage after the last frame') == []


def test_invalid_frames_and_large_garbage_never_become_unbounded_or_raw_progress():
    parser = _parser()
    assert parser.feed(b'x' * 1_000_000) == []
    invalid = [
        b'NaN MiB / 10.00 MiB [>] ',
        b'inf MiB / 10.00 MiB [>] ',
        b'-1.00 MiB / 10.00 MiB [>] ',
        b'1e309 MiB / 1e309 MiB [>] ',
        b'20.00 MiB / 10.00 MiB [>] ',
        b'0.00 B / 0.00 B [>] ',
        b'999999999999999999999999999999.00 GiB / 999999999999999999999999999999.00 GiB [>] ',
        b'1.00 TiB / 2.00 TiB [>] ',
        b'1.00 GiB / 10.00 GiB [>] ',
    ]
    for chunk in invalid:
        assert parser.feed(chunk) == [], 'Malformed or out-of-budget counts must stay unknown'
    assert parser.feed(b'\n\xff\xfe1.00 KiB / 2.00 KiB [=>]') == [(1024, 2048)]
    assert parser.feed(b'\n2.00 KiB / 2.00 KiB [==]') == [(2048, 2048)]


def test_stderr_chunk_callback_receives_unterminated_progress_bytes():
    chunks, lines = [], []
    script = "import sys;sys.stderr.buffer.write(b'1.00 KiB / 2.00 KiB [=>]');sys.stderr.flush()"
    result = run_process([sys.executable, '-c', script],
        on_stderr_chunk=chunks.append, on_stderr_line=lines.append)
    assert result.returncode == 0
    assert b''.join(chunks) == b'1.00 KiB / 2.00 KiB [=>]'
    assert all(isinstance(chunk, bytes) for chunk in chunks)
    assert not lines, 'The existing line callback still requires a line terminator'


def test_live_unterminated_progress_keeps_real_child_alive_and_activates_valid_data(database, monkeypatch):
    manager, cache, before, write = database
    from pathlib import Path
    script = (
        "import sys,time\n"
        "for received in range(1,9):\n"
        " sys.stderr.write(f'{received:.2f} KiB / 8.00 KiB [====] {received/8*100:.1f}% ETA1s')\n"
        " sys.stderr.flush()\n"
        " time.sleep(.2)\n"
    )

    def execute(arguments, **options):
        options.pop('env', None)  # Never expose inherited environment in assertion output.
        staging = Path(arguments[arguments.index('--cache-dir') + 1]) / 'db'
        result = run_process([sys.executable, '-c', script], **options)
        if result.returncode == 0:
            assert {path.name: path.read_bytes() for path in (cache / 'db').iterdir()} == before
            write(staging, fresh=True)
        return result

    monkeypatch.setattr('security_runtime.toolchain.run_process', execute)
    events = []
    with preparation_budget(5, idle_seconds=1, progress=events.append):
        status = manager.prepare_trivy_database('trivy.exe', validate_database=lambda _: True)

    assert status == ToolStatus.READY
    assert manager.database_freshness()['status'] == 'FRESH', (
        'Active byte progress without CR/LF must not be killed and fall back to the stale cache')
    numeric_progress = [event for event in events if event['event'] == 'DOWNLOAD_PROGRESS']
    assert len(numeric_progress) >= 2
    assert all(0 <= event['received_bytes'] <= event['total_bytes'] <= 8_000_000_000 for event in numeric_progress)
    assert any(event['event'] == 'DOWNLOAD_COMPLETE' for event in events)
