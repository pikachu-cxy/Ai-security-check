import subprocess
import tempfile
import unittest
from pathlib import Path

from security_runtime.git import GitService
from security_runtime.runtime import SecurityRuntime
from security_runtime.storage import SQLiteStore


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class GitTests(unittest.TestCase):
    def test_clean_quick_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            git(root, "init", "-b", "main")
            (root / "a.py").write_text("print(1)")
            git(root, "add", "a.py")
            git(root, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-m", "start")
            result = SecurityRuntime(store=SQLiteStore(root / ".security-runtime" / "scan.db")).scan(root)
            self.assertEqual((result.release_status, result.status, result.findings), ("NOT_ASSESSED", "NO_CHANGES", []))

    def test_quick_staged_and_unstaged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            git(root, "init", "-b", "main")
            (root / "a.py").write_text("print(1)")
            git(root, "add", "a.py")
            git(root, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-m", "start")
            (root / "a.py").write_text("print(2)")
            (root / "b.py").write_text("print(3)")
            self.assertEqual(GitService(root).changed_files("quick"), ["a.py", "b.py"])
            self.assertEqual(GitService(root).changed_lines(["a.py", "b.py"], "quick"), {"a.py": {1}, "b.py": {1}})
            self.assertEqual(GitService(root).changed_files("quick", staged=True), [])
            git(root, "add", "b.py")
            self.assertEqual(GitService(root).changed_files("quick", staged=True), ["b.py"])


if __name__ == "__main__":
    unittest.main()
