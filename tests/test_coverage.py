import subprocess
import tempfile
import unittest
from pathlib import Path

from security_runtime.models import RunStatus, ScannerRun
from security_runtime.capabilities import Capability
from security_runtime.runtime import SecurityRuntime
from security_runtime.scanners import ScannerRegistry
from security_runtime.storage import SQLiteStore


class StubScanner:
    def __init__(self, name: str, status: RunStatus):
        self.name = name
        self.scanner_id = name
        self.capabilities = frozenset({Capability.CODE_SAST if name == "semgrep" else Capability.SECRET_SCAN})
        self.filter_changed_lines = False
        self.status = status

    def supports(self, profile, context) -> bool:
        return True

    def scan(self, context, normalizer):
        return [], ScannerRun(self.name, "", self.status, 0, error="not installed" if self.status == RunStatus.UNAVAILABLE else "")


class CoverageTests(unittest.TestCase):
    def test_full_partial_and_minimal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init", "-q", "-b", "main", str(root)], check=True)
            (root / "app.py").write_text("print(1)")
            cases = [
                ((RunStatus.SUCCESS, RunStatus.SUCCESS), "FULL", "COMPLETED", "SAFE"),
                ((RunStatus.SUCCESS, RunStatus.UNAVAILABLE), "PARTIAL", "PARTIAL", "REVIEW"),
                ((RunStatus.UNAVAILABLE, RunStatus.UNAVAILABLE), "MINIMAL", "PARTIAL", "REVIEW"),
            ]
            for statuses, coverage, status, recommendation in cases:
                registry = ScannerRegistry([StubScanner("semgrep", statuses[0]), StubScanner("gitleaks", statuses[1])])
                runtime = SecurityRuntime(registry=registry, store=SQLiteStore(root / ".security-runtime" / "scans.db"))
                result = runtime.scan(root)
                self.assertEqual((result.coverage, result.status, result.release_status), (coverage, status, recommendation))
                self.assertEqual([run.status for run in result.scanner_runs], list(statuses))
