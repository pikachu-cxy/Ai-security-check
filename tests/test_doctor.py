import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class DoctorTests(unittest.TestCase):
    def run_doctor(self, cwd: Path, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "security_runtime.cli", "doctor", *args],
            cwd=cwd,
            env=dict(os.environ),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

    def test_default_without_git_does_not_scan_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "large").mkdir()
            result = self.run_doctor(root)
            self.assertEqual(result.returncode, 2)
            self.assertIn("No project detected. Run security-check doctor --path <project-path>", result.stdout)

    def test_default_resolves_parent_git_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            nested = root / "nested"
            nested.mkdir()
            (root / "app.py").write_text("pass")
            result = self.run_doctor(nested)
            self.assertIn("Python", result.stdout)
            self.assertNotIn("No project detected", result.stdout)

    def test_explicit_path_accepts_non_git_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("pass")
            result = self.run_doctor(root, "--path", str(root))
            self.assertIn("Python", result.stdout)
            self.assertNotIn("No project detected", result.stdout)
