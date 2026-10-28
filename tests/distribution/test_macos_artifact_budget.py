"""Multi-scan release acceptance has its own budget, separate from product calls."""
import pytest

from scripts.release import verify_artifact


@pytest.mark.parametrize('platform,expected', [
    (('macos', 'x64'), 3600), (('macos', 'arm64'), 3600), (('windows', 'x64'), 3600),
])
def test_fix_verification_harness_budget(platform, expected, monkeypatch):
    monkeypatch.setattr(verify_artifact, 'platform_key', lambda: platform)
    assert verify_artifact.fix_verification_timeout() == expected
