import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from security_runtime.findings import FindingNormalizer, deduplicate
from security_runtime.models import ScanContext, ScanMode
from security_runtime.planner import ScannerPlanner
from security_runtime.redactor import SecretRedactor
from security_runtime.risk import RiskEngine
from security_runtime.scanners import ScannerRegistry
from security_runtime.target import TargetDetector


class CoreTests(unittest.TestCase):
    def test_detector(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("from fastapi import FastAPI")
            (root / "package.json").write_text("{}")
            profile = TargetDetector().detect(root)
            self.assertEqual(profile.languages, ["Python"])
            self.assertEqual(profile.frameworks, ["FastAPI"])
            self.assertEqual(profile.ecosystems, ["npm"])

    def test_detector_excludes_generated_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in (".git", ".venv", "venv", "node_modules", ".idea", ".vscode", "dist", "build", "target", "__pycache__"):
                directory = root / name
                directory.mkdir()
                (directory / "ignored.py").write_text("pass")
            (root / "app.py").write_text("pass")
            self.assertEqual(TargetDetector().detect(root).files, ["app.py"])

    def test_detector_limits_files_and_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.py").write_text("pass")
            (root / "b.py").write_text("pass")
            with patch("security_runtime.target.MAX_FILES", 1):
                with self.assertRaisesRegex(ValueError, "more than 1 files"):
                    TargetDetector().detect(root)
            (root / "nested").mkdir()
            with patch("security_runtime.target.MAX_DIRECTORIES", 1):
                with self.assertRaisesRegex(ValueError, "more than 1 directories"):
                    TargetDetector().detect(root)
            (root / "nested" / "deeper").mkdir()
            with self.assertRaisesRegex(ValueError, "deeper than 1 levels"):
                TargetDetector(max_depth=1).detect(root)

    def test_detector_skips_binary_and_oversized_app_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_bytes(b"\0fastapi")
            self.assertEqual(TargetDetector().detect(root).frameworks, [])
            (root / "app.py").write_text("from fastapi import FastAPI")
            self.assertEqual(TargetDetector(max_file_size=5).detect(root).frameworks, [])

    def test_detector_extra_exclusions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "generated").mkdir()
            (root / "generated" / "app.py").write_text("pass")
            self.assertEqual(TargetDetector(ignored_dirs={"generated"}).detect(root).files, [])

    def test_planner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("pass")
            profile = TargetDetector().detect(root)
            context = ScanContext(str(root), ScanMode.QUICK, ("app.py",))
            plan, adapters = ScannerPlanner(ScannerRegistry()).plan(profile, context)
            self.assertEqual(plan.scanners, ("semgrep", "gitleaks"))
            self.assertEqual([x.name for x in adapters], ["semgrep", "gitleaks"])

    def test_normalize_dedupe_risk(self):
        with tempfile.TemporaryDirectory() as tmp:
            n = FindingNormalizer(Path(tmp))
            args = dict(category="command-injection", title="CWE-78", description="command", severity="HIGH", confidence="HIGH", file_path="app.py", line=8, evidence="os.system(x)")
            first = n.make(scanner="semgrep", **args)
            second = n.make(scanner="trivy", **args)
            found = deduplicate([first, second])
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0].scanner_sources, ["semgrep", "trivy"])
            self.assertEqual(RiskEngine().assess(found), "BLOCKED")
            self.assertEqual(RiskEngine().assess([], complete=False), "REVIEW")
            self.assertNotIn("CWE", found[0].plain_title)

    def test_redactor(self):
        text = 'token="sk-12345678901234567890" password=verysecret123'
        redacted = SecretRedactor().redact(text)
        self.assertNotIn("verysecret", redacted)
        self.assertNotIn("sk-123", redacted)


if __name__ == "__main__":
    unittest.main()
