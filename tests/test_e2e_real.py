"""Runs the actual scanner executables; no scanner results are mocked."""
import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from security_runtime.runtime import SecurityRuntime
from security_runtime.storage import SQLiteStore


SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "vulnerable-python"


def git(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, check=False)


@unittest.skipUnless(shutil.which("semgrep") and shutil.which("gitleaks") and shutil.which("trivy"), "real scanner binaries required")
class RealDemoTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        git(self.root, "init", "-b", "main")
        (self.root / "README.md").write_text("demo")
        git(self.root, "add", "README.md")
        git(self.root, "-c", "user.name=Demo", "-c", "user.email=demo@example.com", "commit", "-m", "base")
        shutil.copy(SAMPLE / "app.py", self.root / "app.py")
        self.runtime = SecurityRuntime(store=SQLiteStore(self.root / "scan.db"))

    def tearDown(self):
        self.tmp.cleanup()

    def test_scan_fix_verify_and_modes(self):
        quick = self.runtime.scan(self.root, "quick")
        self.assertIn("app.py", quick.target_profile.files)
        self.assertTrue(any(f.category == "command-injection" for f in quick.findings))
        self.assertTrue(any(f.category == "secret" for f in quick.findings))
        self.assertEqual(quick.release_status, "BLOCKED")
        self.assertEqual(next(r for r in quick.scanner_runs if r.scanner == "trivy").status, "NOT_APPLICABLE")
        command = next(f for f in quick.findings if f.category == "command-injection")
        task = self.runtime.generate_fix(command.id)
        self.assertIn("coding_agent_prompt", task)
        self.assertEqual(self.runtime.verify(command.id)["status"], "STILL_PRESENT")
        shutil.copy(SAMPLE / "safe_app.py", self.root / "app.py")
        self.assertEqual(self.runtime.verify(command.id)["status"], "RESOLVED")
        feature = self.runtime.scan(self.root, "feature")
        release = self.runtime.scan(self.root, "release")
        self.assertGreater(quick.duration_ms, 0)
        self.assertGreater(feature.duration_ms, 0)
        self.assertGreater(release.duration_ms, 0)
        self.assertEqual({r.scanner: r.status for r in release.scanner_runs}, {"semgrep": "SUCCESS", "gitleaks": "SUCCESS", "trivy": "SUCCESS"})

    def test_cli_quick_and_release(self):
        cli = shutil.which("security-check")
        self.assertIsNotNone(cli)
        for mode in ("quick", "release"):
            result = subprocess.run([cli, "scan", "--mode", mode, "--path", str(self.root), "--json"], capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 1, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["release_status"], "BLOCKED")
            self.assertTrue(payload["findings"])

    def test_pre_commit_blocks_then_allows(self):
        from security_runtime.hooks import install_pre_commit
        # The hook uses the installed CLI from PATH.
        install_pre_commit(self.root)
        git(self.root, "add", "app.py")
        blocked = git(self.root, "-c", "user.name=Demo", "-c", "user.email=demo@example.com", "commit", "-m", "unsafe")
        self.assertNotEqual(blocked.returncode, 0)
        shutil.copy(SAMPLE / "safe_app.py", self.root / "app.py")
        git(self.root, "add", "app.py")
        allowed = git(self.root, "-c", "user.name=Demo", "-c", "user.email=demo@example.com", "commit", "-m", "safe")
        self.assertEqual(allowed.returncode, 0, allowed.stdout + allowed.stderr)

    def test_mcp_protocol(self):
        from mcp import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client

        async def run():
            command = Path(sys.executable).with_name("security-check.exe")
            self.assertTrue(command.is_file(), f"Installed Windows entry point missing: {command}")
            params = StdioServerParameters(command=str(command), args=["mcp"], cwd=self.root, env=dict(os.environ))
            with tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as stderr:
                async with stdio_client(params, errlog=stderr) as (read, write):
                    async with ClientSession(read, write) as client:
                        initialized = await client.initialize()
                        self.assertIsNotNone(initialized.serverInfo)
                        names = {t.name for t in (await client.list_tools()).tools}
                        self.assertEqual(names, {"scan_diff", "scan_project", "get_findings", "generate_fix", "verify"})
                        result = await asyncio.wait_for(client.call_tool("scan_diff", {"path": "."}), timeout=75)
                        self.assertFalse(result.isError)
                        payload = result.structuredContent or json.loads(result.content[0].text)
                        if "result" in payload:
                            payload = payload["result"]
                        self.assertTrue(payload["findings"])
                        self.assertEqual(Path(payload["workspace"]), self.root)
                        self.assertEqual(payload["coverage"], "FULL")
                        saved = SQLiteStore(SQLiteStore.default_path()).get_scan(payload["scan_id"])
                        self.assertEqual(Path(saved["target_profile"]["path"]), self.root)
                        finding = payload["findings"][0]
                        stored = await client.call_tool("get_findings", {"scan_id": payload["scan_id"]})
                        self.assertFalse(stored.isError)
                        fix = await client.call_tool("generate_fix", {"finding_id": finding["id"]})
                        self.assertFalse(fix.isError)
                        shutil.copy(SAMPLE / "safe_app.py", self.root / "app.py")
                        verified = await client.call_tool("verify", {"finding_id": finding["id"]})
                        detail = verified.structuredContent or json.loads(verified.content[0].text)
                        if "result" in detail:
                            detail = detail["result"]
                        self.assertEqual(detail["status"], "RESOLVED")
                stderr.seek(0)
                self.assertNotIn("IncompleteFieldDefinitionWarning", stderr.read())
        asyncio.run(run())

    def test_mcp_rejects_unsafe_workspace_and_reports_partial_coverage(self):
        from mcp import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client

        async def run():
            command = Path(sys.executable).with_name("security-check.exe")
            git_dir = Path(shutil.which("git")).parent
            semgrep_dir = Path(shutil.which("semgrep")).parent
            system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
            env = dict(os.environ)
            env["PATH"] = os.pathsep.join(map(str, (semgrep_dir, git_dir, system_root / "System32", system_root)))
            env["SECURITY_RUNTIME_GITLEAKS_PATH"] = str(self.root / "missing-gitleaks.exe")
            params = StdioServerParameters(command=str(command), args=["mcp"], cwd=self.root, env=env)
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as client:
                    await client.initialize()
                    for unsafe in (str(Path.home()), str(Path(Path.home().anchor))):
                        rejected = await client.call_tool("scan_diff", {"workspace_path": unsafe})
                        self.assertTrue(rejected.isError)
                        self.assertIn("will not scan", rejected.content[0].text)
                    invalid = await client.call_tool("scan_diff", {"workspace_path": str(self.root / "missing")})
                    self.assertTrue(invalid.isError)
                    result = await client.call_tool("scan_diff", {"workspace_path": str(self.root)})
                    self.assertFalse(result.isError)
                    payload = result.structuredContent or json.loads(result.content[0].text)
                    payload = payload.get("result", payload)
                    self.assertEqual(payload["coverage"], "PARTIAL")
                    runs = {run["scanner"]: run["status"] for run in payload["scanner_runs"]}
                    self.assertEqual(runs["semgrep"], "SUCCESS")
                    self.assertEqual(runs["gitleaks"], "UNAVAILABLE")
                    findings = await client.call_tool("get_findings", {"scan_id": payload["scan_id"]})
                    self.assertFalse(findings.isError)
        asyncio.run(run())

    def test_mcp_stdout_contains_only_protocol_json(self):
        command = Path(sys.executable).with_name("security-check.exe")
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "raw-test", "version": "1"}},
        }
        result = subprocess.run(
            [str(command), "mcp"],
            input=json.dumps(request) + "\n",
            capture_output=True,
            text=True,
            cwd=self.root,
            timeout=15,
            check=False,
        )
        lines = result.stdout.splitlines()
        self.assertEqual(len(lines), 1, result.stdout + result.stderr)
        response = json.loads(lines[0])
        self.assertEqual(response["id"], 1)
        self.assertEqual(response["result"]["serverInfo"]["name"], "AI Security Runtime")
        self.assertNotIn("IncompleteFieldDefinitionWarning", result.stderr)


if __name__ == "__main__":
    unittest.main()
