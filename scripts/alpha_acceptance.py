"""Record reproducible Developer Alpha evidence using actual installed engines.

Creates an isolated Git fixture; does not modify or connect a user's AI client.
Run after preparing tools: python scripts/alpha_acceptance.py --output <json>
"""
from __future__ import annotations

import argparse
import asyncio
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from security_runtime.cli import doctor, main
from security_runtime.integration_state import IntegrationStateStore
from security_runtime.integrations import WorkBuddyIntegration
from security_runtime.mcp_config import server_entry
from security_runtime.runtime import SecurityRuntime
from security_runtime.toolchain import ToolManager


def git(root: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True,
                          text=True, encoding="utf-8").stdout.strip()


def capture(function, *args, **kwargs) -> dict:
    output = io.StringIO()
    with redirect_stdout(output):
        code = function(*args, **kwargs)
    return {"exit_code": code, "stdout": output.getvalue()}


async def mcp(root: Path, name: str, arguments: dict) -> dict:
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    entry = server_entry(root, "generic-mcp")
    params = StdioServerParameters(command=entry["command"], args=entry["args"], cwd=root,
                                  env=dict(os.environ, **entry["env"]))
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as client:
            await client.initialize()
            response = await client.call_tool(name, arguments)
            if response.isError:
                raise RuntimeError(str(response.content))
            result = response.structuredContent or json.loads(response.content[0].text)
            return result.get("result", result)


def run() -> dict:
    evidence = {"fixture": "isolated Git repo, 16-level tracked source and ignored clone cache",
                "client_note": "Generic MCP SDK calls; no real WorkBuddy application connection is asserted"}
    fake_token = "gh" + "p_" + ("A7c9E2g4J6m8" + "P0r3T5v7X9z1" + "B4d6F8h0K2n5")
    with tempfile.TemporaryDirectory(prefix="alpha-acceptance-") as temporary:
        base = Path(temporary)
        root = base / "project"
        root.mkdir()
        root = root.resolve()
        os.environ["SECURITY_RUNTIME_STATE_DIR"] = str(base / "state")
        os.environ["SECURITY_RUNTIME_OFFLINE"] = "1"
        git(root, "init", "-q", "-b", "main")
        git(root, "config", "user.name", "Acceptance Fixture")
        git(root, "config", "user.email", "test@example.invalid")
        (root / "app.py").write_text("value = 1\n", encoding="utf-8")
        (root / ".gitignore").write_text("data/repos/\n", encoding="utf-8")
        git(root, "add", "app.py", ".gitignore")
        git(root, "commit", "-qm", "base")
        engine = SecurityRuntime()
        adapter = WorkBuddyIntegration(IntegrationStateStore())
        installed = adapter.install(root)
        assert installed.status == "NEEDS_RESTART", installed
        evidence["workbuddy_setup"] = {"status": installed.status, "details": installed.details}
        evidence["workbuddy_status_output"] = capture(main, ["integrations", "--path", str(root)])
        evidence["owned_config_git_status"] = git(root, "status", "--porcelain")
        evidence["cli_no_changes"] = capture(main, ["scan", "--path", str(root)])
        evidence["mcp_no_changes"] = asyncio.run(mcp(root, "scan_diff", {}))
        cache = root / "data/repos" / Path(*(["cache"] * 16))
        cache.mkdir(parents=True)
        for index in range(300):
            (cache / f"unrelated{index}.py").write_text("pass\n", encoding="utf-8")
        deep_name = (Path(*(["d"] * 16)) / "deep.py").as_posix()
        deep = root / deep_name
        deep.parent.mkdir(parents=True)
        # This hard-coded synthetic token is solely an acceptance fixture.
        deep.write_text(f"import os\nos.system(input())\nTEST_ONLY_TOKEN = '{fake_token}'\n", encoding="utf-8")
        (root / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
        git(root, "switch", "-qc", "acceptance-feature")
        git(root, "add", deep_name, "requirements.txt")
        staged = engine.scan(root, "quick", staged=True)
        git(root, "reset", "-q", "HEAD", "--", deep_name, "requirements.txt")
        unstaged = engine.scan(root, "quick")
        evidence["stable_fingerprint"] = {"staged": sorted(f.id for f in staged.findings),
                                          "unstaged": sorted(f.id for f in unstaged.findings)}
        assert evidence["stable_fingerprint"]["staged"] == evidence["stable_fingerprint"]["unstaged"]
        assert any(f.category == "secret" for f in unstaged.findings), "Real Gitleaks secret finding missing"
        assert any(f.category == "command-injection" for f in unstaged.findings), "Real Semgrep finding missing"
        evidence["actual_quick_scan"] = unstaged.to_dict()
        evidence["doctor_large"] = capture(doctor, root, verbose=True)
        os.environ["SECURITY_RUNTIME_MAX_FILES"] = "1"
        evidence["doctor_limited"] = capture(doctor, root, verbose=True)
        os.environ.pop("SECURITY_RUNTIME_MAX_FILES")
        feature = engine.scan(root, "feature")
        release = engine.scan(root, "release")
        evidence["feature_large"] = feature.to_dict()
        evidence["release_large"] = release.to_dict()
        evidence["mcp_scan_project_large"] = asyncio.run(mcp(root, "scan_project", {}))
        evidence["verify_before"] = [engine.verify(f.id) for f in unstaged.findings]
        deep.write_text("value = 2\n", encoding="utf-8")
        evidence["verify_after"] = [engine.verify(f.id) for f in unstaged.findings]
        assert all(item["status"] == "STILL_PRESENT" for item in evidence["verify_before"])
        assert all(item["status"] == "RESOLVED" for item in evidence["verify_after"])
        evidence["tool_status"] = {name: {"status": item.status, "version": item.version}
                                   for name, item in ToolManager().statuses().items()}
        evidence["trivy_database"] = ToolManager().database_status()
    return evidence


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Acceptance evidence recorded: {args.output}")
