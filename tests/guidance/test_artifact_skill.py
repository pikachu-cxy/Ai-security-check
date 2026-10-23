"""Release verification checks the complete current managed Skill payload."""
from pathlib import Path
import runpy

import pytest

from security_runtime.review_skill import RETIRED_METHODS, skill_files
from security_runtime.guidance.host_guidance import HOST_INSTRUCTIONS
from security_runtime.guidance.mcp_guidance import MCP_INSTRUCTIONS


artifact_verifier = runpy.run_path(
    str(Path(__file__).resolve().parents[2] / 'scripts' / 'verify_artifact.py')
)
verify_skill_payload = artifact_verifier['verify_skill_payload']
verify_host_instructions = artifact_verifier['verify_host_instructions']


@pytest.fixture
def installed_skill(tmp_path):
    for name, content in skill_files().items():
        destination = tmp_path / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
    return tmp_path


def test_current_managed_skill_passes(installed_skill):
    verify_skill_payload(installed_skill)


def test_current_host_instructions_pass():
    from security_runtime.mcp_server import create_server
    verify_host_instructions(create_server(global_mode=False).instructions)


@pytest.mark.parametrize('instructions', [None, '', 'Do not ask users for Finding UUIDs',
                                          HOST_INSTRUCTIONS, MCP_INSTRUCTIONS + 'changed'])
def test_missing_or_stale_host_instructions_fail(instructions):
    with pytest.raises(ValueError, match='workflow instructions mismatch'):
        verify_host_instructions(instructions)


@pytest.mark.parametrize('name', sorted(skill_files()))
@pytest.mark.parametrize('change', ['missing', 'modified'])
def test_incomplete_or_changed_skill_fails(installed_skill, name, change):
    destination = installed_skill / name
    if change == 'missing':
        destination.unlink()
    else:
        destination.write_bytes(destination.read_bytes() + b'changed')
    with pytest.raises(ValueError, match='canonical content mismatch'):
        verify_skill_payload(installed_skill)


@pytest.mark.parametrize('name', sorted(RETIRED_METHODS))
def test_retired_review_method_fails(installed_skill, name):
    (installed_skill / name).write_bytes(b'obsolete')
    with pytest.raises(ValueError, match='retired method'):
        verify_skill_payload(installed_skill)
