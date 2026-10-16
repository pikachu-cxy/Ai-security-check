"""Adaptive waits use observed bytes; neither retries nor validation renew the hard cap."""
from copy import deepcopy
import hashlib
import math
from pathlib import Path
import sys
import time
from types import SimpleNamespace

import pytest

from security_runtime.preparation_budget import preparation_budget, bounded_timeout
from security_runtime.processes import run_process, ProcessIdleTimeout, ProcessResult
from security_runtime.toolchain import OfficialReleaseProvider, ToolStatus
from security_runtime.install_readiness import prepare_installation_readiness, validate_readiness_receipt
from test_install_readiness import Manager, manager_cache
from test_preparation_download import database


def observed(budget, received, total=1000, source='ghcr.io'):
    budget.report(dict(event='DOWNLOAD_PROGRESS', component='vulnerability_db',
        received_bytes=received, total_bytes=total, source=source))


@pytest.mark.parametrize('adaptive', [False, True])
def test_remaining_never_exceeds_hard_cap_at_float_boundaries(monkeypatch, adaptive):
    # Adding 60 crosses a float precision boundary: (196.1 + 60) - 196.1 > 60.
    now = [196.1]
    monkeypatch.setattr('security_runtime.preparation_budget.time.monotonic', lambda: now[0])
    with preparation_budget(60, adaptive=adaptive, max_wait_seconds=60) as budget:
        deadline = budget.started + 60
        previous = 60.
        for stamp, expected in [(budget.started, 60.), (budget.started + 1, 59.),
                (math.nextafter(deadline, -math.inf), deadline - math.nextafter(deadline, -math.inf)),
                (deadline, 0.), (math.nextafter(deadline, math.inf), 0.), (deadline + 1, 0.)]:
            now[0] = stamp
            for remaining in (budget.hard_remaining(), budget.remaining()):
                assert 0 <= remaining <= previous <= 60
                assert remaining == pytest.approx(expected)
                assert (remaining > 0) == (stamp < deadline)
            previous = budget.hard_remaining()
            for hard in (False, True):
                if expected > 0:
                    assert bounded_timeout(120, hard=hard) == budget.hard_remaining()
                    assert bounded_timeout(1, hard=hard) <= 1
                else:
                    with pytest.raises(TimeoutError, match='preparation budget exhausted'):
                        bounded_timeout(120, hard=hard)


def test_adaptive_parent_deadline_and_extension_remain_bounded(monkeypatch):
    now = [196.1]
    monkeypatch.setattr('security_runtime.preparation_budget.time.monotonic', lambda: now[0])
    with preparation_budget(5, adaptive=True, max_wait_seconds=60) as budget:
        deadline = budget.started + 5
        for stamp in (budget.started, budget.started + 1, math.nextafter(deadline, -math.inf)):
            now[0] = stamp
            assert 0 < budget.remaining() <= 5
            assert budget.remaining() == pytest.approx(deadline - stamp)
            assert bounded_timeout(120) == budget.remaining() < bounded_timeout(120, hard=True)
        for stamp in (deadline, math.nextafter(deadline, math.inf), deadline + 1):
            now[0] = stamp
            assert budget.remaining() == 0 < budget.hard_remaining()
            observed(budget, 1000)
            assert budget.remaining() == 0  # Late output cannot renew an exhausted parent.
            with pytest.raises(TimeoutError):
                bounded_timeout(120)
    now[0] = 196.1
    with preparation_budget(5, adaptive=True, max_wait_seconds=60) as budget:
        observed(budget, 1000)  # Validation can extend the live parent up to the hard cap.
        assert budget.remaining() == budget.hard_remaining() == 60
        now[0] += 1
        assert 0 < budget.remaining() == budget.hard_remaining() < 60
        now[0] = budget.started + 60
        assert budget.remaining() == budget.hard_remaining() == 0


def test_real_slow_transfer_can_finish_after_initial_wait():
    script = "import sys,time\nfor n in range(1,11):\n time.sleep(.2);sys.stderr.write(str(n)+'\\n');sys.stderr.flush()"
    with preparation_budget(1, adaptive=True, max_wait_seconds=8) as budget:
        result = run_process([sys.executable, '-c', script], timeout=budget.hard_remaining(),
            remaining_callback=budget.remaining,
            on_stderr_line=lambda line: observed(budget, int(line), total=10))
        assert result.returncode == 0 and result.duration_ms > 1000
        assert budget.remaining() > 0


def test_adaptive_wait_without_progress_still_obeys_idle_timeout():
    started = time.monotonic()
    with preparation_budget(1, adaptive=True, max_wait_seconds=8) as budget, pytest.raises(ProcessIdleTimeout):
        run_process([sys.executable, '-c', 'import time;time.sleep(8)'], timeout=budget.hard_remaining(),
            remaining_callback=budget.remaining, idle_timeout=.2, activity_clock=lambda: started)
    assert time.monotonic() - started < 5


def test_fixed_preparation_deadline_is_not_extended_by_byte_progress():
    script = "import sys,time\nfor n in range(1,100):\n time.sleep(.1);sys.stderr.write(str(n)+'\\n');sys.stderr.flush()"
    with preparation_budget(1) as budget, pytest.raises(TimeoutError):
        run_process([sys.executable, '-c', script], timeout=30,
            on_stderr_line=lambda line: observed(budget, int(line), total=100))


def test_continuous_transfer_cannot_exceed_global_max_wait():
    script = "import sys,time\nfor n in range(1,100):\n time.sleep(.1);sys.stderr.write(str(n)+'\\n');sys.stderr.flush()"
    started = time.monotonic()
    with preparation_budget(1, adaptive=True, max_wait_seconds=1) as budget, pytest.raises(TimeoutError):
        run_process([sys.executable, '-c', script], timeout=budget.hard_remaining(),
            remaining_callback=budget.remaining,
            on_stderr_line=lambda line: observed(budget, int(line), total=100))
    assert time.monotonic() - started < 5


def test_stable_eta_extends_initial_deadline_but_not_global_deadline(monkeypatch):
    now = [100.]
    monkeypatch.setattr('security_runtime.preparation_budget.time.monotonic', lambda: now[0])
    with preparation_budget(5, adaptive=True, max_wait_seconds=60) as budget:
        observed(budget, 0)
        for second in range(1, 5):
            now[0] = 100. + second
            observed(budget, 10 * second)
        assert budget.remaining() > 20  # 960 bytes remain at only 10 bytes/second.
        now[0] = 161.
        assert budget.remaining() == 0
        observed(budget, 100)
        assert budget.remaining() == 0, 'Expired waits cannot be resurrected by late output'


def test_source_switch_and_slowdown_share_one_global_cap(monkeypatch):
    now = [10.]
    monkeypatch.setattr('security_runtime.preparation_budget.time.monotonic', lambda: now[0])
    with preparation_budget(2, adaptive=True, max_wait_seconds=10) as budget:
        now[0] = 11.
        observed(budget, 100)
        now[0] = 17.
        budget.report(dict(event='DOWNLOAD_STARTED', component='vulnerability_db', source='mirror.gcr.io',
            attempt=1, max_attempts=1, timeout_seconds=3))
        observed(budget, 1, source='mirror.gcr.io')
        assert budget.hard_remaining() == 3
        now[0] = 20.
        assert budget.remaining() == 0


def test_observed_rate_slowdown_can_extend_existing_wait_within_cap(monkeypatch):
    now = [10.]
    monkeypatch.setattr('security_runtime.preparation_budget.time.monotonic', lambda: now[0])
    with preparation_budget(5, adaptive=True, max_wait_seconds=600) as budget:
        now[0] = 11.
        observed(budget, 1000, total=10000)
        now[0] = 14.
        observed(budget, 4000, total=10000)
        initial_deadline = now[0] + budget.remaining()
        for stamp in range(15, 50):
            now[0] = float(stamp)
            observed(budget, 4000 + (stamp - 14) * 30, total=10000)
        assert initial_deadline < now[0] + budget.remaining() <= 610.


def test_completed_transfer_has_bounded_validation_window(monkeypatch):
    now = [10.]
    monkeypatch.setattr('security_runtime.preparation_budget.time.monotonic', lambda: now[0])
    with preparation_budget(5, adaptive=True, max_wait_seconds=1800) as budget:
        now[0] = 11.
        observed(budget, 100)
        now[0] = 13.
        observed(budget, 1000)
        assert 0 < budget.remaining() <= 120
        now[0] = 132.
        observed(budget, 1000)  # Duplicate 100% frames cannot renew validation.
        assert budget.remaining() <= 1
        now[0] = 134.
        assert budget.remaining() == 0


def test_trivy_native_deadline_uses_hard_cap_parent_uses_adaptive_remaining(database, monkeypatch):
    monkeypatch.setattr('security_runtime.preparation_budget.time.monotonic', lambda: 196.1)
    manager, cache, _, write = database
    seen = []
    def execute(args, **kwargs):
        seen.append(kwargs)
        assert 55 < kwargs['timeout'] <= 60
        assert 55 < float(args[args.index('--timeout') + 1][:-1]) <= 60
        assert callable(kwargs['remaining_callback']) and kwargs['remaining_callback']() <= 5
        kwargs['on_stderr_line']('1.00 MiB / 10.00 MiB [>]')
        write(Path(args[args.index('--cache-dir') + 1]) / 'db', fresh=True)
        return ProcessResult(0, '', '', 1)
    monkeypatch.setattr('security_runtime.toolchain.run_process', execute)
    with preparation_budget(5, adaptive=True, max_wait_seconds=60):
        assert manager.prepare_trivy_database('trivy.exe') == ToolStatus.READY
    assert len(seen) == 1 and manager.database_freshness()['status'] == 'FRESH'


def test_failed_validation_after_complete_transfer_preserves_original_cache(database, monkeypatch):
    manager, cache, before, write = database
    def execute(args, **kwargs):
        kwargs['on_stderr_line']('10.00 MiB / 10.00 MiB [>]')
        write(Path(args[args.index('--cache-dir') + 1]) / 'db', fresh=True)
        return ProcessResult(0, '', '', 1)
    monkeypatch.setattr('security_runtime.toolchain.run_process', execute)
    with preparation_budget(5, adaptive=True, max_wait_seconds=60):
        manager.prepare_trivy_database('trivy.exe', validate_database=lambda _: False)
    assert {p.name: p.read_bytes() for p in (cache / 'db').iterdir()} == before


@pytest.mark.parametrize('tool_id,declared_total', [('gitleaks', True), ('cpython', True), ('gitleaks', False)])
def test_release_components_continue_only_while_actual_chunks_arrive(tmp_path, monkeypatch, tool_id, declared_total):
    payload = b'abcd' * 5
    class Response:
        url = 'https://github.com/official/releases/asset'
        headers = {'Content-Length': str(len(payload))} if declared_total else {}
        def __init__(self): self.chunks = iter([b'abcd'] * 5 + [b''])
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, _):
            time.sleep(.3)
            return next(self.chunks)
    monkeypatch.setattr('security_runtime.toolchain.urllib.request.urlopen', lambda *a, **k: Response())
    manifest = SimpleNamespace(download_url=Response.url, sha256=hashlib.sha256(payload).hexdigest(),
        tool_id=tool_id, version='1')
    started = time.monotonic()
    with preparation_budget(1, adaptive=True, max_wait_seconds=8):
        OfficialReleaseProvider()._download(manifest, tmp_path / 'asset')
    assert time.monotonic() - started > 1 and (tmp_path / 'asset').read_bytes() == payload


def test_receipt_reports_initial_and_longest_wait_and_rejects_invalid_policy():
    receipt = prepare_installation_readiness(manager=Manager(), timeout_seconds=5,
        adaptive=True, max_wait_seconds=60)
    assert receipt['preparation']['adaptive'] is True
    assert receipt['preparation']['budget_seconds'] == 5
    assert receipt['preparation']['max_wait_seconds'] == 60
    assert validate_readiness_receipt(receipt)
    for value in (4, 1801, True):
        invalid = deepcopy(receipt)
        invalid['preparation']['max_wait_seconds'] = value
        assert not validate_readiness_receipt(invalid)
    invalid = deepcopy(receipt)
    invalid['preparation'].pop('adaptive')
    assert not validate_readiness_receipt(invalid)


@pytest.mark.parametrize('options', [dict(adaptive='yes'), dict(adaptive=True, max_wait_seconds=4),
    dict(adaptive=True, max_wait_seconds=1801)])
def test_budget_policy_validation(options):
    with pytest.raises(ValueError), preparation_budget(5, **options):
        pass
