"""License and first-party rule pack gates, including an offline engine run."""
import os
import io
import tempfile
import unittest
import subprocess
from pathlib import Path
from unittest.mock import patch

from security_runtime.engines import BUILTIN_ENGINES
from security_runtime.findings import FindingNormalizer
from security_runtime.licensing import CODEQL_FUTURE_LICENSE, LicenseMetadata, LicensePolicy
from security_runtime.models import ScanContext, ScanMode, RunStatus
from security_runtime.rulepacks import RulePackManager, can_bundle_rule_pack
from security_runtime.scanners import SemgrepAdapter
from security_runtime.toolchain import ToolManager, ToolStatus, ToolManifest, OfficialReleaseProvider
from security_runtime.cli import main as cli_main


class ComplianceTests(unittest.TestCase):
    def test_all_builtin_engines_have_reviewed_metadata_and_notices(self):
        root = Path(__file__).resolve().parents[1]
        for engine in BUILTIN_ENGINES.values():
            with self.subTest(engine=engine.engine_id):
                self.assertIsInstance(engine.license_metadata, LicenseMetadata)
                self.assertTrue(engine.license_metadata.license_spdx)
                self.assertTrue(engine.license_metadata.license_url.startswith("https://"))
                self.assertTrue((root / "src/security_runtime/licenses" / engine.engine_id / "LICENSE").is_file())
                self.assertTrue(LicensePolicy.can_auto_download(engine.license_metadata))
                self.assertTrue(LicensePolicy.can_bundle(engine.license_metadata))
        self.assertTrue((root / "src/security_runtime/licenses/trivy/NOTICE").is_file())
        self.assertTrue((root / "THIRD_PARTY_NOTICES.md").is_file())
        self.assertFalse(LicensePolicy.can_auto_download(CODEQL_FUTURE_LICENSE))
        self.assertFalse(LicensePolicy.can_bundle(CODEQL_FUTURE_LICENSE))
        self.assertFalse(LicensePolicy.can_auto_download(None))
        self.assertEqual(cli_main(["licenses", "--check-distribution"]), 0)

    def test_local_rules_are_licensed_and_no_production_registry_reference(self):
        root = Path(__file__).resolve().parents[1]
        pack = RulePackManager().resolve()
        self.assertEqual(pack.descriptor.rule_pack_id, "ai-security-core")
        self.assertTrue(can_bundle_rule_pack(pack.descriptor))
        self.assertEqual(pack.descriptor.version, "1.0.0")
        forbidden = ("--config=auto", "--config=p/", "--config=r/", "semgrep.dev/registry", "semgrep-rules")
        for file in (root / "src/security_runtime").rglob("*.py"):
            text = file.read_text(encoding="utf-8")
            self.assertFalse(any(term in text for term in forbidden), str(file))

    def test_restricted_engine_is_not_downloaded(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = ToolManager(root=Path(tmp))
            manager.versions["future-codeql"] = "1.0"
            manager.extra_licenses["future-codeql"] = CODEQL_FUTURE_LICENSE
            with patch.object(manager.provider, "download", side_effect=AssertionError("download attempted")):
                result = manager.ensure("future-codeql")
            self.assertEqual(result.status, ToolStatus.BROKEN)
            self.assertIn("license policy", result.detail)

    def test_release_checksum_failure_removes_untrusted_asset(self):
        class Response(io.BytesIO):
            url = "https://github.com/example/release.zip"

        manifest = ToolManifest("fake", "Fake", "1.0", "windows", "x64",
            "https://github.com/example/release.zip", "0" * 64, "zip", "fake.exe",
            "https://github.com/example", "MIT", BUILTIN_ENGINES["gitleaks"].license_metadata)
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "asset.zip"
            with patch("urllib.request.urlopen", return_value=Response(b"unverified bytes")):
                with self.assertRaisesRegex(ValueError, "SHA256 mismatch"):
                    OfficialReleaseProvider().download(manifest, destination)
            self.assertFalse(destination.exists())

    def test_trivy_db_preparation_does_not_use_docker_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = ToolManager(root=Path(tmp))
            seen = []
            def run(*args, **kwargs):
                seen.append(kwargs["env"]["DOCKER_CONFIG"])
                return subprocess.CompletedProcess(args[0], 1, "", "temporary failure")
            with patch.dict(os.environ, {"SECURITY_RUNTIME_TRIVY_CACHE_DIR": str(Path(tmp) / "cache")}), \
                 patch("security_runtime.toolchain.subprocess.run", side_effect=run), \
                 patch("security_runtime.toolchain.time.sleep"):
                self.assertEqual(manager.prepare_trivy_database(str(Path(tmp) / "trivy.exe"), offline=False), ToolStatus.BROKEN)
            self.assertEqual(len(seen), 2)
            self.assertEqual(seen[0], str(Path(tmp) / "cache" / "docker-config"))

    def test_first_party_rules_scan_offline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("import os\nuser_input = input()\nos.system(user_input)\nresult = eval(user_input)\n", encoding="utf-8")
            adapter = SemgrepAdapter()
            context = ScanContext(str(root), ScanMode.QUICK, ("app.py",))
            offline_env = {"SECURITY_RUNTIME_OFFLINE": "1", "HTTP_PROXY": "http://127.0.0.1:9",
                           "HTTPS_PROXY": "http://127.0.0.1:9", "ALL_PROXY": "http://127.0.0.1:9", "NO_PROXY": ""}
            with patch.dict(os.environ, offline_env), patch("urllib.request.urlopen", side_effect=AssertionError("network attempted")):
                findings, run = adapter.scan(context, FindingNormalizer(root))
            self.assertEqual(run.status, RunStatus.SUCCESS, run.error)
            rule_ids = {finding.technical_details.get("rule_id") for finding in findings}
            self.assertTrue(any("command-injection" in str(rule_id) for rule_id in rule_ids))
            self.assertTrue(any("unsafe-eval" in str(rule_id) for rule_id in rule_ids))
            self.assertTrue(all(f.technical_details.get("rule_pack") == "ai-security-core" for f in findings))
