"""Real inert Windows subprocesses; no project code or scanner is executed."""
import hashlib
import os
import sys

import pytest

from security_runtime.hook_state import HookStateStore
from security_runtime.processes import run_process
from security_runtime.scan_attempt import ScanAttemptExecution, ScanAttemptStore, source_binding
from security_runtime.scan_input import capture_scan_input, scoped_request


@pytest.mark.skipif(os.name != 'nt', reason='Windows CreateProcess path contract')
def test_deep_global_metadata_uses_short_source_rules_derived_and_artifact_paths(tmp_path):
    root = tmp_path/'project'
    root.mkdir()
    (root/'source.py').write_text('not executed = True\n')
    state = tmp_path/'state'
    digest = hashlib.sha256(str(root).encode()).hexdigest()
    hooks = HookStateStore(state/'global-workspaces'/digest/'hooks')
    store = ScanAttemptStore(hooks, root)
    with hooks.lock(root):
        lease = store.claim('MANUAL', 'inert-windows-probe', source_binding({}))
    execution = ScanAttemptExecution(store, lease)
    rules = tmp_path/'rules'
    rules.mkdir()
    (rules/'probe.yml').write_text('rules: []\n')
    with capture_scan_input(scoped_request(root, ['source.py']), private_parent=store.private_parent,
            on_created=execution.input_created, on_removed=execution.input_removed) as initial:
        with initial.with_rules(rules) as view:
            execution.input_ready(view)
            with view.derive(['source.py']) as derived, view.artifacts() as artifacts:
                config = artifacts/'selected.yml'
                report = artifacts/'findings.json'
                config.write_text('inert-probe')
                script = ('from pathlib import Path; import sys; '
                    'assert Path(sys.argv[1]).read_text()=="inert-probe"; '
                    'Path(sys.argv[2]).write_text("probe-complete"); print("ok")')
                for cwd in (view.execution_root, view.rules_path, derived, artifacts):
                    assert len(str(cwd)) < 248
                    result = run_process([sys.executable, '-c', script, str(config), str(report)], cwd=cwd)
                    assert result.return_code == 0 and result.stdout.strip() == 'ok'
                assert report.read_text() == 'probe-complete'
            view.assert_intact()
    with hooks.lock(root):
        assert store.finish(lease, input_id=execution.input_id)
    assert store.read()['directories'] == [] and not list(store.private_parent.iterdir())
    # The old shape would exceed CreateProcess's cwd budget in this same test.
    assert len(str(store.legacy_private_parent/('runtime-input-'+'0'*32)/'source')) > 260


@pytest.mark.skipif(os.name != 'nt', reason='Windows private-path budget')
def test_overlong_custom_state_fails_before_publishing_active(tmp_path):
    root = tmp_path/'project'
    root.mkdir()
    hooks = HookStateStore(tmp_path/('x'*100)/'custom-private')
    store = ScanAttemptStore(hooks, root)
    with hooks.lock(root):
        with pytest.raises(ValueError, match='SCAN_INPUT_PRIVATE_PATH_BUDGET'):
            store.claim('MANUAL', 'long-custom-state', source_binding({}))
    assert store.read()['lane'] is None
