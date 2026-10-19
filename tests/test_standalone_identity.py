"""Frozen dataflow retains the source bytes used in its rule identity."""
import ast
from pathlib import Path
import shutil
import sys
from types import ModuleType

from security_runtime import dataflow


def test_frozen_dataflow_source_identity_matches_development(tmp_path, monkeypatch):
    root = Path(__file__).resolve().parents[1]
    hooks = ModuleType('PyInstaller.utils.hooks')
    hooks.collect_data_files = lambda *a, **k: []
    hooks.copy_metadata = lambda *a, **k: []
    for name in ('PyInstaller', 'PyInstaller.utils'):
        monkeypatch.setitem(sys.modules, name, ModuleType(name))
    monkeypatch.setitem(sys.modules, 'PyInstaller.utils.hooks', hooks)
    spec = root / 'distribution/build/security-check.spec'
    # Evaluate data collection only; never run Analysis or require PyInstaller.
    statements = []
    for statement in ast.parse(spec.read_text(encoding='utf-8')).body:
        if isinstance(statement, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == 'a' for target in statement.targets):
            break
        statements.append(statement)
    namespace = {'SPECPATH': str(spec.parent)}
    exec(compile(ast.Module(body=statements, type_ignores=[]), str(spec), 'exec'), namespace)
    expected = dataflow.rule_pack().checksum
    frozen = tmp_path / 'security_runtime'
    frozen.mkdir()
    for source, destination in namespace['datas']:
        if destination == 'security_runtime' and Path(source).suffix == '.py':
            shutil.copy2(source, frozen / Path(source).name)
    monkeypatch.setattr(dataflow, '__file__', str(frozen / 'dataflow.py'))
    assert dataflow.rule_pack().checksum == expected
