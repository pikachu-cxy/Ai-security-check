"""Catch migration omissions in actual subprocess snippets and repository callers."""
from pathlib import Path
import subprocess
import sys

from scripts.maintenance.check_repository_layout import check, runtime_import_errors


def test_repository_references_exist():
    assert check() == []


def test_embedded_python_catches_retired_import_without_executing_it(tmp_path):
    package = tmp_path / 'security_runtime'
    (package / 'tasks').mkdir(parents=True)
    (package / 'tasks/__init__.py').write_text('')
    (package / 'tasks/fix.py').write_text('')
    source = 'check = "from security_runtime import task_fix\\nraise RuntimeError()"'
    errors = runtime_import_errors(source, package, 'verify.py')
    assert len(errors) == 1 and 'embedded@1' in errors[0] and 'security_runtime.task_fix' in errors[0]
    assert runtime_import_errors('check = "from security_runtime.tasks import fix"', package, 'verify.py') == []


def test_rebuild_help_exits_before_the_candidate_workflow(tmp_path):
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run([sys.executable, str(root / 'scripts/rebuild_dependency_fix.py'), '--help'],
                            cwd=tmp_path, capture_output=True, timeout=15)
    assert result.returncode == 0, result.stderr.decode('utf-8', errors='replace')
    assert b'usage:' in result.stdout and b'--help' in result.stdout
