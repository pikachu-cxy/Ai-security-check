"""Cross-process locks must not silently discard an observed edit check."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import subprocess
import sys
import threading

import pytest

from security_runtime.codex_event_adapter import classify_bash_command
from security_runtime.codex_mcp_hook import handle_codex_hook, codex_hook_output
from security_runtime.global_mcp import GlobalWorkspaces
from security_runtime.hook_runtime import HookCoordinator
from security_runtime.hook_state import HookStateStore
from test_codex_mcp_hook import binding
from test_hook_runtime import FakeRuntime, repo, row


@contextmanager
def foreign_lock(directory, root):
    code = ('from pathlib import Path\nimport sys\n'
            'from security_runtime.hook_state import HookStateStore\n'
            'with HookStateStore(Path(sys.argv[1])).lock(Path(sys.argv[2])) as locked:\n'
            ' print(locked, flush=True)\n sys.stdin.readline()\n')
    child = subprocess.Popen([sys.executable, '-c', code, str(directory), str(root)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == 'True'
        yield child
    finally:
        if child.poll() is None:
            child.communicate('\n', timeout=5)
        assert child.returncode == 0


def sample(repo, tmp_path, wait):
    runtime = FakeRuntime()
    core = HookCoordinator(runtime, HookStateStore(tmp_path/'hooks'), cooldown_ms=0,
                           activity_wait_seconds=wait)
    core.handle('SESSION_START', repo, 'codex', 's')
    runtime.findings = [row(repo)]
    (repo/'A.java').write_text('changed-risk\n')
    return runtime, core


def invoke(root, core, *, tool='apply_patch', command=None):
    return handle_codex_hook('PostToolUse', str(root), 's', tool,
        tool_input={'command': command} if command else None,
        binding=binding(root), coordinator=core)


def test_edit_waits_for_foreign_lock_then_scans_once(repo, tmp_path, monkeypatch):
    runtime, core = sample(repo, tmp_path, 2)
    original = core.store.lock
    blocked = threading.Event()

    @contextmanager
    def observed(root, *, wait_seconds=0):
        with original(root) as available:
            assert not available
        assert wait_seconds == 2
        blocked.set()
        with original(root, wait_seconds=wait_seconds) as locked:
            yield locked

    with foreign_lock(core.store.directory, repo) as child:
        monkeypatch.setattr(core.store, 'lock', observed)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(invoke, repo, core)
            assert blocked.wait(5)
            monkeypatch.setattr(core.store, 'lock', original)
            child.communicate('\n', timeout=5)
            result = future.result(timeout=10)
    assert result['scanner_run'] and result['status'] == 'SCANNED'
    assert result['new_families'] == 1 and len(runtime.calls) == 1
    assert core.store.pending_activity(repo, 'codex', 's') is None


def test_timeout_shows_gap_retains_baseline_and_reconciles_later(repo, tmp_path):
    runtime, core = sample(repo, tmp_path, .05)
    path = core.store.path(repo, 'codex', 's')
    before = path.read_bytes()
    with foreign_lock(core.store.directory, repo):
        result = invoke(repo, core)
        assert result['status'] == 'BUSY' and not result['scanner_run']
        assert not runtime.calls and path.read_bytes() == before
        assert core.store.pending_activity(repo, 'codex', 's') is not None
        output = codex_hook_output(result)
        assert '检查未完成' in output['systemMessage']
        assert '本次没有执行安全扫描' in output['systemMessage']
        assert result['user_feedback']['message'] == output['systemMessage']
        context = output['hookSpecificOutput']['additionalContext']
        assert output['systemMessage'] in context and '必须说明' in context
        assert '修复／忽略' not in context and 'remediation_ref' not in context
        assert output['continue'] is True
    # A later observed activity checks the retained delta, without another edit.
    result = invoke(repo, core)
    assert result['scanner_run'] and result['new_families'] == 1
    assert len(runtime.calls) == 1
    assert core.store.pending_activity(repo, 'codex', 's') is None


def test_get_location_remains_quiet_during_foreign_check(repo, tmp_path):
    runtime, core = sample(repo, tmp_path, 2)
    with foreign_lock(core.store.directory, repo):
        result = invoke(repo, core, tool='Bash', command='Get-Location')
        assert result['status'] == 'NOT_SCANNED' and not result['scanner_run']
        assert codex_hook_output(result) == {}
        assert core.store.pending_activity(repo, 'codex', 's') is None
    assert not runtime.calls


@pytest.mark.parametrize('command', ['Get-Location; Copy-Item a b',
    'Get-Location; [IO.File]::WriteAllText("a", "b")', 'Get-Location | Unknown-Command'])
def test_compound_location_commands_still_require_reconciliation(command):
    assert classify_bash_command({'command': command}) != 'READ_ONLY'


def test_real_global_child_enables_bounded_wait(repo, tmp_path, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path/'state'))
    _, core = GlobalWorkspaces._child(repo, tmp_path/'global', binding(repo))
    assert core.activity_wait_seconds == 10


@pytest.mark.parametrize('budget', [-1, 11, float('nan'), True])
def test_wait_budget_rejects_invalid_values(budget):
    with pytest.raises(ValueError):
        HookCoordinator(activity_wait_seconds=budget)
