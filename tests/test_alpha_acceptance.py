"""Acceptance contracts for truthful results and bounded real-project work."""
import asyncio
import json
import subprocess
from pathlib import Path

import pytest

from security_runtime.capabilities import Capability
from security_runtime.cli import doctor, main, render
from security_runtime.git import GitService
from security_runtime.integration_config import IntegrationConfigStore
from security_runtime.integration_state import IntegrationStateStore
from security_runtime.integrations import WorkBuddyIntegration
from security_runtime.mcp_server import _agent_result
from security_runtime.mcp_verify import verify_mcp_entry
from security_runtime.models import RunStatus, ScannerRun
from security_runtime.runtime import SecurityRuntime
from security_runtime.scanners import ScannerRegistry, _snapshot
from security_runtime.storage import SQLiteStore
from security_runtime.target import TargetDetector, DiscoveryLimitError


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True, encoding="utf-8").stdout.strip()


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    git(root, "config", "user.name", "Acceptance Test")
    git(root, "config", "user.email", "test@example.invalid")
    (root / "app.py").write_text("value = 1\n", encoding="utf-8")
    git(root, "add", "app.py")
    git(root, "commit", "-qm", "base")
    return root


class RecordingScanner:
    name = scanner_id = "gitleaks"
    capabilities = frozenset({Capability.SECRET_SCAN})
    filter_changed_lines = True

    def __init__(self):
        self.calls = []

    def supports(self, profile, context):
        return bool(context.files)

    def scan(self, context, normalizer):
        self.calls.append(context)
        found = []
        for name in context.files:
            if "TEST_ONLY_TOKEN" in (Path(context.root) / name).read_text(encoding="utf-8"):
                found.append(normalizer.make(scanner=self.name, category="secret", title="Test secret",
                    description="Test only", severity="HIGH", confidence="HIGH", file_path=name,
                    line=1, evidence="[REDACTED_SECRET]", rule_id="test-token"))
        return found, ScannerRun(self.name, "test", RunStatus.SUCCESS, 1, len(found))


def runtime(tmp_path):
    scanner = RecordingScanner()
    return SecurityRuntime(ScannerRegistry([scanner]), SQLiteStore(tmp_path / "state.db")), scanner


def test_quick_no_changes_and_summary(repo, tmp_path):
    engine, scanner = runtime(tmp_path)
    result = engine.scan(repo)
    assert scanner.calls == []
    assert (result.status, result.execution_state, result.coverage, result.release_status) == ("NO_CHANGES", "NO_CHANGES", "NONE", "NOT_ASSESSED")
    human = render(result)
    assert "本次没有执行代码安全扫描" in human
    assert "SAFE" not in human and "FULL" not in human and "当前未发现阻止提交" not in human
    agent = _agent_result(result)
    assert agent["recommendation"] == "NOT_ASSESSED"
    assert all(run["status"] == "NOT_APPLICABLE" for run in agent["scanner_runs"])
    # Executed results must also preserve the Runtime's calculated summary.
    (repo / "readme.txt").write_text("test")
    result = engine.scan(repo)
    result.summary = "Runtime-specific explanation"
    assert result.summary in render(result)


def test_owned_mcp_config_ignore_reversible(repo, tmp_path):
    exclude = repo / ".git/info/exclude"
    before = exclude.read_bytes() + b"\n# user-owned rule\n/keep-me\n"
    exclude.write_bytes(before)
    config = IntegrationConfigStore(repo, ".workbuddy/mcp.json")
    config.install({"command": "test-runtime"}, lambda: True)
    assert not (repo / ".gitignore").exists()
    assert git(repo, "status", "--porcelain") == ""
    assert GitService(repo).changed_files("quick") == []
    engine, scanner = runtime(tmp_path)
    assert engine.scan(repo).execution_state == "NO_CHANGES"
    assert not scanner.calls
    config.install({"command": "test-runtime"}, lambda: True)
    config.uninstall()
    assert not config.path.exists()
    assert exclude.read_bytes() == before


def test_existing_user_config_is_not_hidden(repo):
    config = IntegrationConfigStore(repo, ".workbuddy/mcp.json")
    config.path.parent.mkdir()
    original = {"mcpServers": {"user": {"command": "user-owned"}}}
    config.path.write_text(json.dumps(original))
    config.install({"command": "test-runtime"}, lambda: True)
    assert ".workbuddy/mcp.json" in GitService(repo).changed_files("quick")
    config.uninstall()
    assert config.load() == original


def test_tracked_runtime_entry_does_not_become_owned(repo):
    config = IntegrationConfigStore(repo, ".workbuddy/mcp.json")
    config.path.parent.mkdir()
    entry = {"command": "user-registered-runtime"}
    config.path.write_text(json.dumps({"mcpServers": {"ai-security-runtime": entry}}))
    git(repo, "add", ".workbuddy/mcp.json")
    git(repo, "commit", "-qm", "user configuration")
    config.install(entry, lambda: True)
    assert not config._local_exclude()
    config.uninstall()
    assert config.path.is_file()


def make_deep(repo):
    # An ignored cache should never be traversed by any Git-scoped operation.
    (repo / ".gitignore").write_text("data/repos/\n")
    cache = repo / "data/repos" / Path(*(["cache"] * 16))
    cache.mkdir(parents=True)
    (cache / "unrelated.py").write_text("TEST_ONLY_TOKEN")
    name = (Path(*(["d"] * 16)) / "deep.py").as_posix()
    path = repo / name
    path.parent.mkdir(parents=True)
    path.write_text("TEST_ONLY_TOKEN = 'synthetic fixture'\n")
    git(repo, "add", ".gitignore", name)
    return name


def test_deep_git_feature_release_verify_and_fingerprint(repo, tmp_path, monkeypatch):
    name = make_deep(repo)
    with pytest.raises(DiscoveryLimitError):
        TargetDetector().detect(repo)
    assert name in TargetDetector().detect(repo, [name]).files
    git(repo, "switch", "-qc", "feature-test")
    git(repo, "commit", "-qm", "deep tracked source")
    engine, scanner = runtime(tmp_path)
    # Fails if Runtime or verify accidentally calls os.walk.
    monkeypatch.setattr("security_runtime.target.os.walk", lambda *a, **k: pytest.fail("recursive discovery"))
    feature = engine.scan(repo, "feature")
    release = engine.scan(repo, "release")
    assert feature.findings and release.findings
    assert name in feature.target_profile.files and name in release.target_profile.files
    assert not any("data/repos" in f for f in release.target_profile.files)
    finding = feature.findings[0]
    assert finding.id == release.findings[0].id
    assert engine.verify(finding.id)["status"] == "STILL_PRESENT"
    assert scanner.calls[-1].files == (name,)
    (repo / name).write_text("value = 2\n")
    assert engine.verify(finding.id)["status"] == "RESOLVED"


def test_staged_unstaged_fingerprint(repo, tmp_path):
    (repo / "app.py").write_text("TEST_ONLY_TOKEN = 'synthetic fixture'\n")
    git(repo, "add", "app.py")
    engine, _ = runtime(tmp_path)
    staged = engine.scan(repo, staged=True).findings[0]
    git(repo, "reset", "-q", "HEAD", "--", "app.py")
    unstaged = engine.scan(repo).findings[0]
    assert staged.id == unstaged.id and staged.fingerprint == unstaged.fingerprint


def test_doctor_profile_limited(repo, monkeypatch, capsys):
    monkeypatch.setenv("SECURITY_RUNTIME_MAX_FILES", "1")
    (repo / "second.py").write_text("pass")
    assert doctor(repo, json_output=True) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["profile"] == "LIMITED"
    assert report["workspace"]["git"]
    assert "Git-scoped files" in report["profile_warning"]
    assert len(report["runtime"]["scanners"]) == 3


def test_cli_plan_prepares_no_unselected_tools(repo, tmp_path, monkeypatch, capsys):
    from security_runtime.toolchain import ToolManager, ToolStatus, ResolvedTool

    monkeypatch.setenv("SECURITY_RUNTIME_STATE_DIR", str(tmp_path / "state"))
    ensured = []
    def ensure(manager, tool_id, **kwargs):
        ensured.append(tool_id)
        return ResolvedTool(tool_id, "", "", None, ToolStatus.OFFLINE, "missing test engine")
    monkeypatch.setattr(ToolManager, "ensure", ensure)
    monkeypatch.setattr(ToolManager, "prepare_trivy_database", lambda *a: pytest.fail("unplanned Trivy DB preparation"))
    assert main(["scan", "--path", str(repo)]) == 0
    assert ensured == []
    (repo / "secret.txt").write_text("test")
    assert main(["scan", "--path", str(repo)]) == 0
    assert ensured == ["gitleaks"]
    output = capsys.readouterr().out
    assert "UNAVAILABLE" in output


def test_not_applicable_human_output(repo, tmp_path):
    (repo / "secret.txt").write_text("test")
    engine, _ = runtime(tmp_path)
    result = engine.scan(repo)
    output = render(result)
    assert "Executed" in output and "Secret Security" in output
    assert "Not applicable" in output and "Code Security" in output
    assert "SKIPPED" not in output and "FULL" not in output


def test_snapshot_has_only_scoped_files(repo):
    name = make_deep(repo)
    from security_runtime.models import ScanContext, ScanMode
    context = ScanContext(str(repo), ScanMode.RELEASE, (name,))
    with _snapshot(context) as root:
        assert (root / name).exists()
        assert not (root / "app.py").exists()
        assert not (root / "data").exists()


def test_feature_includes_nearby_manifests_without_recursive_discovery(repo, tmp_path, monkeypatch):
    nested = repo / "packages/service"
    nested.mkdir(parents=True)
    (nested / "app.py").write_text("pass\n")
    (nested / "requirements.txt").write_text("requests==2.31.0\n")
    git(repo, "add", "packages/service/requirements.txt")
    git(repo, "commit", "-qm", "manifest")
    engine, scanner = runtime(tmp_path)
    monkeypatch.setattr("security_runtime.target.os.walk", lambda *a, **k: pytest.fail("recursive discovery"))
    result = engine.scan(repo, "feature")
    assert "packages/service/requirements.txt" in result.target_profile.files
    assert scanner.calls[-1].context_files == ("packages/service/requirements.txt",)


def test_local_ignore_failure_rolls_back_config(repo, monkeypatch):
    config = IntegrationConfigStore(repo, ".workbuddy/mcp.json")
    def fail(**kwargs):
        raise OSError("ignore write failed")
    monkeypatch.setattr(config, "_local_exclude", fail)
    with pytest.raises(OSError, match="ignore write"):
        config.install({"command": "test-runtime"}, lambda: True)
    assert not config.path.exists()


def test_explicit_targets_keep_security_limits(repo, tmp_path):
    with pytest.raises(ValueError, match="outside"):
        TargetDetector().detect(repo, ["../outside.py"])
    with pytest.raises(DiscoveryLimitError, match="bytes"):
        TargetDetector(max_file_size=1).detect(repo, ["app.py"])
    with pytest.raises(DiscoveryLimitError, match="files"):
        TargetDetector(max_files=1).detect(repo, ["app.py", "other.py"])


@pytest.mark.parametrize("command", [["scan"], ["setup", "workbuddy"], ["integrations"], ["mcp", "config"]])
def test_command_specific_workspace_error(command, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(command) == 2
    output = capsys.readouterr().err
    assert f"security-check {' '.join(command)} --path <project>" in output
    assert "security-check doctor --path" not in output


def test_help_and_version(capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(["--help"])
    assert exit_info.value.code == 0
    help_text = capsys.readouterr().out
    for text in ("Check Runtime", "Scan code changes", "AI coding tool", "MCP server", "Manage security engines"):
        assert text in help_text
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0


def test_workbuddy_self_test_vs_real_invocation(repo, tmp_path, monkeypatch):
    from security_runtime.mcp_config import server_entry
    monkeypatch.setenv("SECURITY_RUNTIME_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("SECURITY_RUNTIME_OFFLINE", "1")
    state = IntegrationStateStore()
    adapter = WorkBuddyIntegration(state)
    installed = adapter.install(repo)  # actual stdio MCP initialize/list_tools
    assert installed.status == "NEEDS_RESTART"
    assert installed.details["configuration_status"] == "WRITTEN"
    assert installed.details["runtime_self_test"] == "PASSED"
    assert installed.details["last_client_invocation"] == ""
    entry = server_entry(repo, "workbuddy", include_type=False)
    ok, detail = verify_mcp_entry(entry, repo, call_scan_diff=True)
    assert ok, detail
    assert adapter.status(repo).details["last_client_invocation"] == ""
    # A normal host client invocation, distinct from the Runtime verifier.
    async def invoke():
        from mcp import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client
        import os
        params = StdioServerParameters(command=entry["command"], args=entry["args"], cwd=repo, env=dict(os.environ, **entry["env"]))
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as client:
                await client.initialize()
                result = await client.call_tool("scan_diff", {})
                assert not result.isError
                payload = result.structuredContent or json.loads(result.content[0].text)
                payload = payload.get("result", payload)
                assert payload["status"] == "NO_CHANGES"
                assert payload["recommendation"] == "NOT_ASSESSED"
    asyncio.run(invoke())
    connected = adapter.status(repo)
    assert connected.status == "CONNECTED"
    assert connected.details["last_client_invocation"]


def test_native_status_canonical_binding(tmp_path, monkeypatch):
    # Windows tempfile paths can use ADMINI~1 while MCP config stores the full
    # canonical user path. Setup must compare canonical workspace identities.
    import tempfile
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        git(root, "init", "-q", "-b", "main")
        monkeypatch.setattr("security_runtime.integrations.verify_mcp_entry", lambda entry, workspace: (True, "verified"))
        adapter = WorkBuddyIntegration(IntegrationStateStore(tmp_path / "canonical.db"))
        assert adapter.install(root).status == "NEEDS_RESTART"
        assert adapter.status(root.resolve()).status == "NEEDS_RESTART"
