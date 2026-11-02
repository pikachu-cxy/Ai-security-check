"""Exercise real Win32 long paths without running external scanners."""
import hashlib
import os

import pytest

from security_runtime.hook_state import native_io_path
from security_runtime.rulepacks import RulePackManager

pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows filesystem regression')
RULE = b'rules:\n- id: long-path-test\n  languages: [python]\n  message: test\n  severity: WARNING\n  pattern: print(...)\n'


def deep(root):
    path = root / ('a' * 80) / ('b' * 80) / ('c' * 80)
    assert len(str(path)) > 260
    native_io_path(path).mkdir(parents=True)
    return path


def test_rule_resolution_cache_and_custom_composition(tmp_path):
    from security_runtime.scan_preferences import preferences
    from security_runtime.user_config import DEFAULTS
    from copy import deepcopy

    root = deep(tmp_path)
    rule = root / 'rule.yml'
    native_io_path(rule).write_bytes(RULE)
    manager = RulePackManager()
    first = manager.resolve(user_path=root)
    assert first.path == root.resolve()
    assert first.catalog[0].path == 'rule.yml'
    short = tmp_path / 'short'
    short.mkdir()
    (short / 'rule.yml').write_bytes(RULE)
    assert manager.resolve(user_path=short).checksum == first.checksum
    assert manager.resolve(user_path=root).checksum == first.checksum
    assert manager.cache_hit
    native_io_path(rule).write_bytes(RULE.replace(b'print(...)', b'eval(...)'))
    assert manager.resolve(user_path=root).checksum != first.checksum
    assert not manager.cache_hit
    values = deepcopy(DEFAULTS)
    values['rules']['sast'].update(mode='replace', paths=[str(root)])
    with preferences({'values': values}):
        composed = manager.resolve()
        assert [r.rule_id for r in composed.catalog] == ['long-path-test']


def test_deep_rule_inventory_and_metadata(tmp_path):
    from security_runtime.scan_input import _rule_files
    from security_runtime.rule_program import load_program
    from security_runtime.rule_catalog import load_catalog
    from security_runtime.rulepacks import DEFAULT_RULE_PACK

    root = deep(tmp_path)
    native_io_path(root / 'rule.yml').write_bytes(RULE)
    native_io_path(root / 'capabilities.json').write_text('{}')
    assert _rule_files(root, 10) == ('capabilities.json', 'rule.yml')
    # A present invalid manifest must reach semantic validation, not look missing.
    with pytest.raises(ValueError) as error:
        load_program(root, ())
    assert 'missing or unsafe' not in str(error.value)
    native_io_path(root / 'catalog.json').write_text('{}')
    with pytest.raises(ValueError, match='Rule Catalog identity mismatch'):
        load_catalog(root, DEFAULT_RULE_PACK, {})


def test_target_capture_freshness_and_plan_keep_deep_source(tmp_path):
    from security_runtime.target import TargetDetector
    from security_runtime.scan_input import scoped_request, _absent
    from security_runtime.scan_request import ScanInputError
    from security_runtime.scan_freshness import source_revision
    from security_runtime.secret_coverage import digest, text_file
    from security_runtime.scanners import SemgrepAdapter
    from security_runtime.models import ScanContext
    from security_runtime.flow_core import Analysis

    root = tmp_path.resolve()
    file = deep(root) / 'app.py'
    native_io_path(file).write_bytes(b'import fastapi\nprint(1)\n')
    name = file.relative_to(root).as_posix()
    detector = TargetDetector()
    for names in (None, [name]):
        profile = detector.detect(root, names)
        assert profile.files == [name]
        assert profile.frameworks == ['FastAPI']
    assert scoped_request(root, [name]).files == (name,)
    with pytest.raises(ScanInputError, match='SCAN_INPUT_ABSENCE_CHANGED'):
        _absent(root, [name])
    before, count = source_revision(root, b'k' * 32, files=[name])
    assert count == 1
    assert text_file(file)
    assert digest(file) == hashlib.sha256(native_io_path(file).read_bytes()).hexdigest()
    analysis = Analysis(root)
    assert analysis.exists(name)
    assert 'fastapi' in analysis.read(name)
    assert analysis.stable()
    rules = root / 'rules'
    rules.mkdir()
    (rules / 'rule.yml').write_bytes(RULE)
    pack = RulePackManager().resolve(user_path=rules)
    adapter = SemgrepAdapter()
    context = ScanContext(str(root), 'feature', (name,), bound_rule_pack=pack)
    plan = adapter.plan_rules(profile, context)
    assert plan.rules
    native_io_path(file).write_bytes(b'print(2)\n')
    assert not analysis.stable()
    assert source_revision(root, b'k' * 32, files=[name])[0] != before
