"""The Intel Mac harness allowance must not change Windows or product budgets."""
import pytest

from scripts.release import verify_artifact


@pytest.mark.parametrize('platform,expected', [
    (('macos', 'x64'), 600), (('macos', 'arm64'), 180), (('windows', 'x64'), 180),
])
def test_fix_verification_harness_budget(platform, expected, monkeypatch):
    monkeypatch.setattr(verify_artifact, 'platform_key', lambda: platform)
    assert verify_artifact.fix_verification_timeout() == expected
