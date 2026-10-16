"""Static license, notice, provenance and rule-pack gates."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from dataclasses import replace

from security_runtime.engines import BUILTIN_ENGINES
from security_runtime.notices import render_third_party_notices
from security_runtime.licensing import CODEQL_FUTURE_LICENSE, SEMGREP_LICENSE, LicenseAction, LicenseMetadata, LicensePolicy, Permission
from security_runtime.rulepacks import FIRST_PARTY_RULE_PACK, RulePackClass, RulePackManager, can_bundle_rule_pack
from security_runtime.toolchain import ToolManager, ToolStatus
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
        self.assertTrue((root / "LICENSE").is_file())
        self.assertTrue((root / "EULA.md").is_file())
        self.assertTrue((root / "LICENSING.md").is_file())
        self.assertTrue((root / "LICENSES/Apache-2.0.txt").is_file())
        self.assertEqual(FIRST_PARTY_RULE_PACK.license, "Apache-2.0")
        self.assertTrue((root / "THIRD_PARTY_NOTICES.md").is_file())
        self.assertEqual((root / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8"),
                         render_third_party_notices())
        self.assertFalse(LicensePolicy.can_auto_download(CODEQL_FUTURE_LICENSE))
        self.assertFalse(LicensePolicy.can_bundle(CODEQL_FUTURE_LICENSE))
        self.assertFalse(LicensePolicy.can_auto_download(None))
        self.assertEqual(cli_main(["licenses", "--check-distribution"]), 0)

    def test_local_rules_are_licensed_and_no_production_registry_reference(self):
        root = Path(__file__).resolve().parents[1]
        pack = RulePackManager().resolve()
        self.assertEqual(pack.descriptor.rule_pack_id, "ai-security-core")
        self.assertTrue(can_bundle_rule_pack(pack.descriptor))
        self.assertEqual(pack.descriptor.version, "1.3.2")
        forbidden = ("--config=auto", "--config=p/", "--config=r/", "semgrep.dev/registry", "semgrep-rules")
        for file in (root / "src/security_runtime").rglob("*.py"):
            text = file.read_text(encoding="utf-8")
            self.assertFalse(any(term in text for term in forbidden), str(file))

    def test_restricted_engine_is_not_downloaded(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = ToolManager(root=Path(tmp))
            manager.versions["future-codeql"] = "1.0"
            manager.extra_licenses["future-codeql"] = CODEQL_FUTURE_LICENSE
            with patch.object(manager.provider, "download", side_effect=AssertionError("download attempted")) as download:
                result = manager.ensure("future-codeql")
            self.assertEqual(result.status, ToolStatus.BROKEN)
            self.assertEqual(result.diagnostic.error_code, "LICENSE_BLOCKED")
            download.assert_not_called()

    def test_license_actions_keep_lgpl_obligations_and_restricted_gate(self):
        self.assertEqual(LicensePolicy.permission(SEMGREP_LICENSE, LicenseAction.USE), Permission.YES)
        self.assertEqual(LicensePolicy.permission(SEMGREP_LICENSE, LicenseAction.AUTO_DOWNLOAD), Permission.YES)
        self.assertEqual(LicensePolicy.permission(SEMGREP_LICENSE, LicenseAction.REDISTRIBUTE), Permission.WITH_OBLIGATIONS)
        self.assertEqual(LicensePolicy.permission(SEMGREP_LICENSE, LicenseAction.BUNDLE), Permission.WITH_OBLIGATIONS)
        self.assertEqual(LicensePolicy.permission(SEMGREP_LICENSE, LicenseAction.HOSTED_SERVICE), Permission.YES)
        for action in LicenseAction:
            self.assertEqual(LicensePolicy.permission(CODEQL_FUTURE_LICENSE, action), Permission.NO)

    def test_first_party_rule_metadata_cannot_be_empty(self):
        source = Path(__file__).resolve().parents[1] / "src/security_runtime/rules/core/python.yml"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "LICENSE").write_text("MIT", encoding="utf-8")
            rule = root / "python.yml"
            rule.write_text(source.read_text(encoding="utf-8").replace(
                "publisher: AI Security Runtime", "publisher: ''"), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "identity mismatch"):
                RulePackManager._validate(FIRST_PARTY_RULE_PACK, root)

    def test_unknown_or_restricted_rule_pack_cannot_be_bundled(self):
        for pack_class in (RulePackClass.UNKNOWN, RulePackClass.RESTRICTED):
            with self.subTest(pack_class=pack_class):
                self.assertFalse(can_bundle_rule_pack(replace(FIRST_PARTY_RULE_PACK, pack_class=pack_class)))
