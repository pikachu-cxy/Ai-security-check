"""A real entry point, planner, runtime, and stdio MCP extension test."""
import asyncio
import importlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from security_runtime.capabilities import Capability, CapabilityRegistry
from security_runtime.mcp_server import create_server
from security_runtime.mcp_config import resolve_runtime_command
from security_runtime.planner import ScannerPlanner
from security_runtime.models import ScanContext, ScanMode
from security_runtime.runtime import SecurityRuntime
from security_runtime.scanners import ScannerRegistry
from security_runtime.storage import SQLiteStore
from security_runtime.target import TargetDetector


PLUGIN_SOURCE = '''
from security_runtime.capabilities import Capability
from security_runtime.models import ScannerRun, RunStatus
from security_runtime.plugin_api import ScannerPluginMetadata

class FakeScannerPlugin:
    scanner_id = name = "fake-scanner"
    display_name = "Fake Scanner"
    capabilities = frozenset({Capability.CODE_SAST})
    supported_languages = frozenset({"Python"})
    supported_ecosystems = frozenset()
    filter_changed_lines = False
    metadata = ScannerPluginMetadata(scanner_id, display_name, "0.1.0", "0.1.0", capabilities,
                                     supported_languages, supported_ecosystems, ())

    def required_engines(self):
        return ()

    def supports(self, profile, context):
        return "Python" in profile.languages and bool(context.files)

    def normalize(self, raw, normalizer):
        return [normalizer.make(scanner=self.scanner_id, category="code", title="Fake issue",
                description="Test plugin finding", severity="MEDIUM", confidence="MEDIUM",
                file_path=raw["file"], line=1, evidence="test", rule_id="fake-rule")]

    def scan(self, context, normalizer):
        findings = self.normalize({"file": "app.py"}, normalizer)
        return findings, ScannerRun(self.scanner_id, "0.1.0", RunStatus.SUCCESS, 0, len(findings))
'''


class PluginE2ETests(unittest.TestCase):
    def test_entry_point_to_mcp(self):
        from mcp import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            plugin_dir = base / "plugin"
            plugin_dir.mkdir()
            (plugin_dir / "fake_scanner_plugin.py").write_text(PLUGIN_SOURCE, encoding="utf-8")
            metadata_dir = plugin_dir / "ai_security_runtime_fake-0.1.0.dist-info"
            metadata_dir.mkdir()
            (metadata_dir / "METADATA").write_text("Metadata-Version: 2.1\nName: ai-security-runtime-fake\nVersion: 0.1.0\n", encoding="utf-8")
            (metadata_dir / "entry_points.txt").write_text("[ai_security_runtime.scanners]\nfake-scanner = fake_scanner_plugin:FakeScannerPlugin\n", encoding="utf-8")
            root = base / "sample repo"
            root.mkdir()
            subprocess.run(["git", "init", "-q", "-b", "main", str(root)], check=True)
            (root / "app.py").write_text("print('hello')")

            with patch.object(sys, "path", [str(plugin_dir), *sys.path]), patch.dict(os.environ, {"SECURITY_RUNTIME_OFFLINE": "1"}):
                importlib.invalidate_caches()
                registry = ScannerRegistry()
                fake = next(adapter for adapter in registry.adapters if adapter.scanner_id == "fake-scanner")
                self.assertIn(fake, CapabilityRegistry(registry).get_scanners(Capability.CODE_SAST))
                profile = TargetDetector().detect(root)
                _, selected = ScannerPlanner(registry).plan(profile, ScanContext(str(root), ScanMode.QUICK, ("app.py",)))
                self.assertIn(fake, selected)
                registry.adapters = [fake]
                direct = SecurityRuntime(registry=registry, store=SQLiteStore(base / "direct.db")).scan(root)
                self.assertTrue(any("fake-scanner" in finding.scanner_sources for finding in direct.findings))

            async def run_mcp():
                runtime_command = resolve_runtime_command()
                env = dict(os.environ)
                env["PYTHONPATH"] = str(plugin_dir) + os.pathsep + env.get("PYTHONPATH", "")
                env["SECURITY_RUNTIME_OFFLINE"] = "1"
                env["SECURITY_RUNTIME_STATE_DIR"] = str(base / "state")
                params = StdioServerParameters(command=runtime_command.command, args=list(runtime_command.args), cwd=root, env=env)
                async with stdio_client(params) as (read, write):
                    async with ClientSession(read, write) as client:
                        await client.initialize()
                        response = await client.call_tool("scan_diff", {"workspace_path": str(root), "summary": False})
                        self.assertFalse(response.isError, response)
                        payload = response.structuredContent or json.loads(response.content[0].text)
                        payload = payload.get("result", payload)
                        self.assertTrue(any(finding["plain_title"] == "Fake issue" for finding in payload["findings"]))
            asyncio.run(run_mcp())
