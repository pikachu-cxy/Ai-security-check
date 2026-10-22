"""Generic presentation deduplication survives independent command processes."""
import json
import os
import subprocess
import sys

import pytest

from security_runtime.cursor_gap_notices import claim_gap_notice
from security_runtime.hook_state import HookStateStore


def test_notice_claim_survives_process_and_is_workspace_scoped(tmp_path):
    root = tmp_path/'project'
    root.mkdir()
    state = tmp_path/'state'
    code = ('from pathlib import Path; import sys; '
            'from security_runtime.hook_state import HookStateStore; '
            'from security_runtime.cursor_gap_notices import claim_gap_notice; '
            'print(claim_gap_notice(HookStateStore(Path(sys.argv[1])), Path(sys.argv[2]), "session", "turn"))')
    def run():
        return subprocess.run([sys.executable, '-c', code, str(state), str(root)],
            check=True, capture_output=True, text=True, env=os.environ.copy()).stdout.strip()
    assert run() == 'True'
    assert run() == 'False'
    other = tmp_path/'another-project'
    other.mkdir()
    assert claim_gap_notice(HookStateStore(state), other, 'session', 'turn')


def test_tampered_notice_cannot_suppress_feedback_or_reveal_source(tmp_path):
    root = tmp_path/'project'
    root.mkdir()
    hooks = HookStateStore(tmp_path/'state')
    assert claim_gap_notice(hooks, root, 'private-session', 'private-generation')
    path = hooks.workspace_directory(root)/'cursor-gap-notices.json'
    content = path.read_text()
    assert 'private-session' not in content and 'private-generation' not in content
    value = json.loads(content)
    value['signature'] = '0'*64
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match='Unverified'):
        claim_gap_notice(hooks, root, 'private-session', 'private-generation')
