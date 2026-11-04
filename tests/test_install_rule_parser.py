"""The accelerated parser must preserve bundled rules and reject object tags."""
from pathlib import Path
import pytest
import yaml
from security_runtime.rulepacks import _SAFE_LOADER


def test_all_bundled_rules_have_identical_safe_parse():
    root = Path(__file__).parents[1] / 'src/security_runtime/rules'
    files = sorted(root.rglob('*.yaml')) + sorted(root.rglob('*.yml'))
    assert files
    for path in files:
        content = path.read_bytes()
        assert yaml.load(content, Loader=_SAFE_LOADER) == yaml.safe_load(content), path


def test_python_object_tags_remain_rejected():
    with pytest.raises(yaml.constructor.ConstructorError):
        yaml.load('!!python/object/apply:os.system [echo unsafe]', Loader=_SAFE_LOADER)
