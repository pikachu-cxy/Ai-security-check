"""Install a local test wheel through the Python package engine path."""
import base64
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

from security_runtime.capabilities import Capability
from security_runtime.models import RunStatus, ScannerRun
from security_runtime.runtime import SecurityRuntime
from security_runtime.scanners import ScannerRegistry
from security_runtime.storage import SQLiteStore
from security_runtime.toolchain import ToolManager, ToolStatus
from security_runtime.licensing import LicenseMetadata, LicenseClass, Permission


def make_wheel(path: Path) -> None:
    dist = "fake_engine-0.1.0.dist-info"
    files = {
        "fake_engine/__init__.py": b"",
        "fake_engine/cli.py": b"import json, sys\ndef main():\n    print('0.1.0' if '--version' in sys.argv else json.dumps({'title': 'Fake package finding'}))\n",
        f"{dist}/METADATA": b"Metadata-Version: 2.1\nName: fake-engine\nVersion: 0.1.0\n",
        f"{dist}/WHEEL": b"Wheel-Version: 1.0\nGenerator: ai-security-runtime-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        f"{dist}/entry_points.txt": b"[console_scripts]\nfake-engine = fake_engine.cli:main\n",
        f"{dist}/LICENSE": b"MIT License\nCopyright test authors\n",
    }
    records = []
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as wheel:
        for name, content in files.items():
            wheel.writestr(name, content)
            digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
            records.append(f"{name},sha256={digest},{len(content)}")
        record_name = f"{dist}/RECORD"
        wheel.writestr(record_name, "\n".join([*records, f"{record_name},,"]) + "\n")


class FakePackageScanner:
    name = scanner_id = "fake-package"
    display_name = "Fake Package Scanner"
    capabilities = frozenset({Capability.CODE_SAST})
    filter_changed_lines = False

    def __init__(self, executable: Path):
        self.executable = executable

    def required_engines(self):
        return ("fake-engine",)

    def supports(self, profile, context):
        return bool(context.files)

    def normalize(self, raw, normalizer):
        return [normalizer.make(scanner=self.name, category="code", title=raw["title"],
                description="Fake Python package engine result", severity="MEDIUM", confidence="MEDIUM",
                file_path="app.py", line=1, evidence="test", rule_id="fake-package")]

    def scan(self, context, normalizer):
        proc = subprocess.run([str(self.executable), "scan", context.root], capture_output=True, text=True, check=True, timeout=10)
        findings = self.normalize(json.loads(proc.stdout), normalizer)
        return findings, ScannerRun(self.name, "0.1.0", RunStatus.SUCCESS, 0, len(findings))


class PythonPackageEngineTests(unittest.TestCase):
    def test_install_resolve_invoke_and_consume(self):
        with tempfile.TemporaryDirectory() as tmp:
            # The test owns this freshly-created directory; canonicalize the
            # macOS /var alias before passing it as an explicit managed root.
            base = Path(tmp).resolve()
            wheel = base / "fake_engine-0.1.0-py3-none-any.whl"
            make_wheel(wheel)
            manager = ToolManager(root=base / "managed")
            fake_license = LicenseMetadata("MIT", "MIT", "https://opensource.org/license/mit", True, True,
                Permission.YES, Permission.YES, True, True, False, False, "", False,
                LicenseClass.PERMISSIVE, "Copyright test authors")
            manager.register_python_engine("fake-engine", "0.1.0", str(wheel), no_index=True,
                                           license_metadata=fake_license)
            resolved = manager.ensure("fake-engine", offline=True)
            self.assertEqual(resolved.status, ToolStatus.READY, resolved.detail)
            self.assertTrue(Path(resolved.path).is_absolute())
            self.assertEqual(manager.resolve("fake-engine").status, ToolStatus.READY)

            root = base / "sample"
            root.mkdir()
            subprocess.run(["git", "init", "-q", "-b", "main", str(root)], check=True)
            (root / "app.py").write_text("print('hello')")
            registry = ScannerRegistry([FakePackageScanner(Path(resolved.path))], tool_manager=manager)
            result = SecurityRuntime(registry=registry, store=SQLiteStore(base / "scans.db")).scan(root)
            self.assertEqual(result.findings[0].plain_title, "Fake package finding")
