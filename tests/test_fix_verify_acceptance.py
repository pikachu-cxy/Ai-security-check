"""The native fix gate keeps private scan state outside its source fixture."""
import runpy
from pathlib import Path

from security_runtime.hooks import HookStateStore
from security_runtime.scan_attempt import ScanAttemptStore


def test_fix_verification_fixture_separates_project_and_private_state(tmp_path):
    script = Path(__file__).resolve().parents[1] / 'scripts/fix_verify_acceptance.py'
    root, store = runpy.run_path(str(script))['acceptance_workspace'](tmp_path)
    assert root == tmp_path / 'project' and root.is_dir()
    assert store.path == tmp_path / 'state/scans.db'
    attempts = ScanAttemptStore(HookStateStore(store.path.parent / 'hooks'), root)
    assert not attempts.private_parent.resolve().is_relative_to(root)
