"""Unchanged index generation must not produce new editor events."""
import importlib.util
from pathlib import Path


def test_index_generation_preserves_unchanged_files(tmp_path, monkeypatch):
    path = Path(__file__).resolve().parents[1]/'scripts/maintenance/knowledge_index.py'
    spec = importlib.util.spec_from_file_location('knowledge_index_test', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, 'OUTPUT', tmp_path)
    monkeypatch.setattr(module, 'collect', lambda: ([], []))
    monkeypatch.setattr(module, 'render', lambda *a: {'index.json': '{"value":1}\n'})
    monkeypatch.setattr('sys.argv', ['knowledge_index.py'])
    assert module.main() == 0
    target = tmp_path/'index.json'
    before = target.stat().st_mtime_ns
    original = Path.write_text
    def no_rewrite(self, *args, **kwargs):
        if self == target:
            raise AssertionError('unchanged index was rewritten')
        return original(self, *args, **kwargs)
    monkeypatch.setattr(Path, 'write_text', no_rewrite)
    assert module.main() == 0
    assert target.stat().st_mtime_ns == before
    monkeypatch.setattr(Path, 'write_text', original)
    monkeypatch.setattr(module, 'render', lambda *a: {'index.json': '{"value":2}\n'})
    assert module.main() == 0
    assert target.read_text() == '{"value":2}\n'
