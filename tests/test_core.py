import tempfile
import unittest
from pathlib import Path

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
