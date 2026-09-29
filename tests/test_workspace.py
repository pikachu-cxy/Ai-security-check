import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from security_runtime.workspace import WorkspaceError, WorkspaceResolver


class WorkspaceTests(unittest.TestCase):
    def test_nested_git_workspace_with_spaces(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "my repo"
            root.mkdir()
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            nested = root / "src" / "service"
            nested.mkdir(parents=True)
            with patch.object(Path, "cwd", return_value=nested):
                self.assertEqual(WorkspaceResolver().resolve().path, root.resolve())
            self.assertEqual(WorkspaceResolver().resolve(str(nested)).path, root.resolve())

    def test_rejects_home_and_drive_root(self):
        resolver = WorkspaceResolver()
        with self.assertRaisesRegex(WorkspaceError, "entire user home"):
            resolver.resolve(Path.home())
        with self.assertRaisesRegex(WorkspaceError, "system drive"):
            resolver.resolve(Path(Path.home().anchor))

    def test_explicit_non_git_only_for_doctor(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaisesRegex(WorkspaceError, "No project detected"):
                WorkspaceResolver().resolve(root)
            workspace = WorkspaceResolver().resolve(root, allow_non_git_explicit=True)
            self.assertEqual(workspace.path, root.resolve())
            self.assertFalse(workspace.is_git)
