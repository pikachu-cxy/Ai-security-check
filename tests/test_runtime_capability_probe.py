"""Capability probing before a first installation creates its config directory."""
from contextlib import asynccontextmanager
import json
import os
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest

from security_runtime.codex_integration import REQUIRED_TOOLS, probe_runtime
from security_runtime.guidance.host_guidance import runtime_info
from security_runtime.integration_lifecycle import IntegrationDiagnostic


@pytest.mark.parametrize("existing_home", [False, True])
def test_real_runtime_info_launch_and_mcp_discovery_without_creating_home(
    tmp_path, monkeypatch, existing_home
):
    info = runtime_info()
    info["features"]["global_runtime_integration"] = "v0.1"
    info["integration_scope"] = "GLOBAL"
    home = tmp_path / "fresh-codex-home"
    if existing_home:
        home.mkdir()
    marker = tmp_path / "observed-cwd.json"
    program = tmp_path / "owned-runtime-fixture.py"
    program.write_text(
        "import json, os\nfrom pathlib import Path\n"
        + "Path(os.environ['FIXTURE_CWD_MARKER']).write_text(json.dumps(os.getcwd()))\n"
        + "print(" + repr(json.dumps(info)) + ")\n",
        encoding="utf-8",
    )
    stdio_cwds = []

    @asynccontextmanager
    async def fake_stdio(params, **kwargs):
        stdio_cwds.append(Path(params.cwd))
        assert Path(params.cwd).is_dir()
        assert params.env["SECURITY_RUNTIME_CODEX_HOME"] == str(home)
        yield object(), object()

    class FakeSession:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def initialize(self):
            pass

        async def list_tools(self):
            names = REQUIRED_TOOLS | {"get_findings"}
            return SimpleNamespace(tools=[SimpleNamespace(name=name,
                inputSchema={"properties": {"workspace_path": {}}}) for name in names])

        async def call_tool(self, name, arguments):
            assert name == "get_runtime_info" and arguments == {}
            return SimpleNamespace(structuredContent=info, isError=False)

    monkeypatch.setattr("mcp.ClientSession", FakeSession)
    monkeypatch.setattr("mcp.client.stdio.stdio_client", fake_stdio)
    environment = {**os.environ, "SECURITY_RUNTIME_GLOBAL": "1",
        "SECURITY_RUNTIME_CODEX_HOME": str(home), "FIXTURE_CWD_MARKER": str(marker)}
    result = probe_runtime({"command": sys.executable, "prefix": [str(program)],
        "kind": "SYSTEM_PYTHON"}, home, environment)
    expected_cwd = home if existing_home else Path(sys.executable).absolute().parent
    assert result["status"] == "OK"
    assert Path(json.loads(marker.read_text())) == expected_cwd
    assert stdio_cwds == [expected_cwd]
    assert home.exists() is existing_home
    assert not (home / "config.toml").exists()


def test_existing_file_is_not_reinterpreted_as_missing_home(tmp_path):
    home = tmp_path / "invalid-codex-home"
    home.write_bytes(b"unrelated user file")
    with pytest.raises(IntegrationDiagnostic, match="CAPABILITY_MISMATCH"):
        probe_runtime({"command": sys.executable, "prefix": [], "kind": "SYSTEM_PYTHON"}, home,
            {**os.environ, "SECURITY_RUNTIME_GLOBAL": "1"})
    assert home.read_bytes() == b"unrelated user file"


@pytest.mark.parametrize("global_mode,home_claim", [
    ("0", "exact"), ("1", "other"), ("1", "missing"),
])
def test_missing_project_or_unmatched_global_home_still_fails(tmp_path, global_mode, home_claim):
    home = tmp_path / "missing-workspace"
    environment = {**os.environ, "SECURITY_RUNTIME_GLOBAL": global_mode}
    environment.pop("SECURITY_RUNTIME_CODEX_HOME", None)
    if home_claim != "missing":
        environment["SECURITY_RUNTIME_CODEX_HOME"] = str(home if home_claim == "exact" else tmp_path)
    with pytest.raises(IntegrationDiagnostic, match="CAPABILITY_MISMATCH"):
        probe_runtime({"command": sys.executable, "prefix": [], "kind": "SYSTEM_PYTHON"}, home, environment)
    assert not home.exists()
