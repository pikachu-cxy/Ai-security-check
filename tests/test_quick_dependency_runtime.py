"""Dependency changes exercise the real planner, Runtime and Hook coordinator.

Providers are local recording fixtures: no security engine, package manager,
target installation, target execution or network access is used by these tests.
"""
import json
import subprocess
from pathlib import Path

import pytest

from security_runtime.capabilities import Capability
from security_runtime.dependency_inputs import is_dependency_input
from security_runtime.global_workspace import source_snapshot
from security_runtime.hook_runtime import HookCoordinator
from security_runtime.hook_state import HookStateStore
from security_runtime.models import RunStatus, ScannerRun
from security_runtime.runtime import SecurityRuntime
from security_runtime.scanners import ScannerRegistry
from security_runtime.storage import SQLiteStore
from security_runtime.verification_policy import offline_scanning, scanner_process_observed
from security_runtime.workspace import WorkspaceError


def git(root, *arguments):
    return subprocess.run(["git", "-C", str(root), *arguments], check=True,
                          capture_output=True, text=True, encoding="utf-8").stdout.strip()


def write(root, relative, content="fixture\n"):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def commit(root, *files):
    git(root, "add", *files)
    git(root, "commit", "-qm", "synthetic fixture")


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    git(root, "config", "user.name", "Dependency Fixture")
    git(root, "config", "user.email", "fixture@example.invalid")
    write(root, "app.py", "value = 1\n")
    commit(root, "app.py")
    return root


class RecordingProvider:
    filter_changed_lines = False
    provider_role = "PRIMARY"

    def __init__(self, name, capability, *, status=RunStatus.SUCCESS,
                 coverage="FULL", error_code="", issue=False, role="PRIMARY"):
        self.name = self.scanner_id = self.engine_id = name
        self.capabilities = frozenset({capability})
        self.status, self.coverage, self.error_code = status, coverage, error_code
        self.issue, self.provider_role = issue, role
        self.calls = []
        self.offline_calls = []

    def supports(self, profile, context):
        if Capability.DEPENDENCY_VULN in self.capabilities:
            return any(is_dependency_input(name) for name in (*context.files, *context.context_files))
        if Capability.CODE_SAST in self.capabilities:
            return bool(profile.languages and context.files)
        return bool(context.files)

    def scan(self, context, normalizer):
        self.calls.append(context)
        self.offline_calls.append(offline_scanning())
        scanner_process_observed()
        inputs = tuple(name for name in (*context.files, *context.context_files)
                       if is_dependency_input(name))
        # Verify that the current scoped inventory is readable, rather than
        # treating a removed path as a successfully scanned dependency input.
        for name in inputs:
            (Path(context.root) / name).read_bytes()
        found = []
        if self.issue and inputs and self.status == RunStatus.SUCCESS:
            found.append(normalizer.dependency(scanner=self.name,
                package="fixture-vulnerable-package", version="1.0", ecosystem="pip",
                manifest=inputs[0], vulnerability_id="CVE-2099-0001", aliases=[],
                severity="HIGH", title="Synthetic vulnerable dependency", description="Fixture only",
                source="Fixture"))
        return found, ScannerRun(self.name, "fixture", self.status, 1, len(found),
            error_code=self.error_code, coverage_contract=self.coverage,
            dependency_inventory={"planned_manifests": len(inputs),
                "confirmed_manifests": len(inputs) if self.status == RunStatus.SUCCESS else 0,
                "complete_dependency_graph_attested": self.coverage == "FULL"})


def runtime(tmp_path, *, dependency_status=RunStatus.SUCCESS, dependency_coverage="FULL",
            dependency_error="", issue=False, fallback=None):
    code = RecordingProvider("fixture-code", Capability.CODE_SAST)
    secret = RecordingProvider("gitleaks", Capability.SECRET_SCAN)
    dependency = RecordingProvider("trivy-vuln", Capability.DEPENDENCY_VULN,
        status=dependency_status, coverage=dependency_coverage,
        error_code=dependency_error, issue=issue)
    registry = ScannerRegistry([code, secret, dependency], fallback_adapters=[fallback] if fallback else [])
    return SecurityRuntime(registry, SQLiteStore(tmp_path / "runtime" / "scans.db")), dependency, code, secret


def dependency_scope(provider):
    context = provider.calls[-1]
    return {name for name in (*context.files, *context.context_files) if is_dependency_input(name)}


def coordinator(tmp_path, engine, root, *, non_git=False):
    return HookCoordinator(engine, HookStateStore(tmp_path / "hooks"), cooldown_ms=0,
        workspace_resolver=lambda value: root,
        snapshot_capture=source_snapshot if non_git else None)


def start(coordinator, root):
    return coordinator.handle("SESSION_START", root, "codex", "fixture-session", _lifecycle=True)


def activity(coordinator, root):
    return coordinator.handle("FILE_CHANGED", root, "codex", "fixture-session", _lifecycle=True)


def test_quick_new_dependency_is_scanned_and_finding_is_retained(repo, tmp_path):
    write(repo, "requirements.txt", "fixture-vulnerable-package==1.0\n")
    engine, dependency, _, _ = runtime(tmp_path, issue=True)
    result = engine.scan(repo, "quick")
    assert len(dependency.calls) == 1 and dependency_scope(dependency) == {"requirements.txt"}
    assert result.capability_results[Capability.DEPENDENCY_VULN] == "EXECUTED"
    assert [finding.category for finding in result.findings] == ["dependency"]
    assert engine.store.get_scan(result.scan_id)["findings"][0]["technical_details"]["package"] == "fixture-vulnerable-package"


@pytest.mark.parametrize("name", ["pnpm-lock.yaml", "yarn.lock", "build.gradle.kts", "poetry.lock", "go.sum"])
def test_quick_modifying_lock_or_manifest_triggers_dependency_provider(repo, tmp_path, name):
    write(repo, "service/" + name)
    commit(repo, "service/" + name)
    write(repo, "service/" + name, "changed inventory\n")
    engine, dependency, _, _ = runtime(tmp_path)
    result = engine.scan(repo, "quick")
    assert len(dependency.calls) == 1
    assert dependency_scope(dependency) == {"service/" + name}
    assert result.capability_results[Capability.DEPENDENCY_VULN] == "EXECUTED"


def test_source_only_edit_does_not_rescan_existing_dependency_inventory(repo, tmp_path):
    write(repo, "requirements.txt", "fixture-package==1.0\n")
    commit(repo, "requirements.txt")
    write(repo, "app.py", "value = 2\n")
    engine, dependency, code, secret = runtime(tmp_path)
    result = engine.scan(repo, "quick")
    assert not dependency.calls and len(code.calls) == len(secret.calls) == 1
    assert result.capability_results[Capability.DEPENDENCY_VULN] == "NOT_APPLICABLE"


def test_deleted_lockfile_rechecks_remaining_local_manifest(repo, tmp_path):
    write(repo, "service/package.json", '{"dependencies":{"fixture-package":"1.0"}}\n')
    lock = write(repo, "service/package-lock.json", '{}\n')
    commit(repo, "service/package.json", "service/package-lock.json")
    lock.unlink()
    engine, dependency, _, _ = runtime(tmp_path)
    result = engine.scan(repo, "quick")
    assert len(dependency.calls) == 1
    assert dependency_scope(dependency) == {"service/package.json"}
    assert "service/package-lock.json" in dependency.calls[-1].dependency_changes
    assert result.capability_results[Capability.DEPENDENCY_VULN] == "EXECUTED"


def test_removed_entire_inventory_is_unknown_not_full_dependency_coverage(repo, tmp_path):
    manifest = write(repo, "requirements.txt", "fixture-package==1.0\n")
    commit(repo, "requirements.txt")
    manifest.unlink()
    engine, dependency, _, _ = runtime(tmp_path)
    result = engine.scan(repo, "quick")
    assert not dependency.calls  # no existing manifest to fabricate an inventory from
    assert result.capability_results[Capability.DEPENDENCY_VULN] not in {"EXECUTED", "NOT_APPLICABLE"}
    assert result.coverage != "FULL" and result.execution_state != "NO_CHANGES"


def test_renaming_manifest_to_unrecognized_file_does_not_claim_dependencies_safe(repo, tmp_path):
    manifest = write(repo, "requirements.txt", "fixture-package==1.0\n")
    commit(repo, "requirements.txt")
    manifest.rename(repo / "notes.txt")
    engine, dependency, _, _ = runtime(tmp_path)
    result = engine.scan(repo, "quick")
    assert not dependency.calls
    assert result.capability_results[Capability.DEPENDENCY_VULN] == "UNAVAILABLE"
    assert result.status == "PARTIAL" and result.coverage != "FULL"
    missing = next(run for run in result.scanner_runs if run.error_code == "DEPENDENCY_SCOPE_UNAVAILABLE")
    assert missing.status == RunStatus.UNAVAILABLE and missing.coverage_contract == "NONE"
    assert not result.findings  # no fabricated finding or claimed remediation


def test_nested_change_checks_related_ancestor_manifest_without_unrelated_scope(repo, tmp_path):
    write(repo, "package.json", '{}\n')
    write(repo, "service/package.json", '{}\n')
    write(repo, "unrelated/requirements.txt", "do-not-read==1.0\n")
    commit(repo, "package.json", "service/package.json", "unrelated/requirements.txt")
    write(repo, "service/package-lock.json", '{}\n')
    engine, dependency, _, _ = runtime(tmp_path)
    engine.scan(repo, "quick")
    assert dependency_scope(dependency) == {"package.json", "service/package.json", "service/package-lock.json"}


def test_missing_offline_dependency_data_keeps_completed_code_and_secrets(repo, tmp_path):
    write(repo, "requirements.txt", "fixture-package==1.0\n")
    write(repo, "app.py", "value = 2\n")
    engine, dependency, code, secret = runtime(tmp_path,
        dependency_status=RunStatus.UNAVAILABLE, dependency_error="OFFLINE_MODE", dependency_coverage="NONE")
    result = engine.scan(repo, "quick")
    assert len(dependency.calls) == len(code.calls) == len(secret.calls) == 1
    assert result.capability_results[Capability.CODE_SAST] == "EXECUTED"
    assert result.capability_results[Capability.SECRET_SCAN] == "EXECUTED"
    assert result.capability_results[Capability.DEPENDENCY_VULN] == "UNAVAILABLE"
    assert result.coverage == result.status == "PARTIAL"


def test_quick_dependency_failure_uses_only_eligible_local_fallback(repo, tmp_path):
    write(repo, "package-lock.json", '{}\n')
    fallback = RecordingProvider("osv-scanner", Capability.DEPENDENCY_VULN, role="FALLBACK")
    engine, dependency, _, _ = runtime(tmp_path, dependency_status=RunStatus.UNAVAILABLE,
        dependency_error="OFFLINE_MODE", dependency_coverage="NONE", fallback=fallback)
    result = engine.scan(repo, "quick")
    assert len(dependency.calls) == len(fallback.calls) == 1
    detail = result.capability_details[Capability.DEPENDENCY_VULN]
    assert detail["active_provider"] == "osv-scanner" and detail["primary_status"] == "UNAVAILABLE"
    assert result.capability_results[Capability.DEPENDENCY_VULN] == "EXECUTED"


def test_hook_added_dependency_finding_has_no_sast_family_or_resolution_proof(repo, tmp_path):
    engine, dependency, _, _ = runtime(tmp_path, issue=True)
    hooks = coordinator(tmp_path, engine, repo)
    assert start(hooks, repo)["status"] == "BASELINE_ESTABLISHED"
    write(repo, "requirements.txt", "fixture-vulnerable-package==1.0\n")
    result = activity(hooks, repo)
    assert len(dependency.calls) == 1 and dependency.offline_calls == [True]
    stored = engine.store.get_scan(result["scan_id"])
    dependency_ids = [finding["id"] for finding in stored["findings"] if finding["category"] == "dependency"]
    assert result["current_dependency_finding_ids"] == dependency_ids and dependency_ids
    assert not result["delta"]["families"]
    assert result["delta"]["new"] == result["delta"]["resolved"] == 0
    state = json.loads(hooks.store.path(repo, "codex", "fixture-session").read_bytes())
    assert not state["families"]


def test_hook_unchanged_dependency_does_not_repeat_on_source_edit(repo, tmp_path):
    write(repo, "requirements.txt", "fixture-package==1.0\n")
    commit(repo, "requirements.txt")
    engine, dependency, _, _ = runtime(tmp_path)
    hooks = coordinator(tmp_path, engine, repo)
    start(hooks, repo)
    write(repo, "requirements.txt", "fixture-package==2.0\n")
    assert activity(hooks, repo)["capabilities"][Capability.DEPENDENCY_VULN] == "EXECUTED"
    write(repo, "app.py", "value = 2\n")
    second = activity(hooks, repo)
    assert len(dependency.calls) == 1
    assert second["capabilities"][Capability.DEPENDENCY_VULN] == "NOT_APPLICABLE"


def test_partial_dependency_check_does_not_advance_hook_comparison_point(repo, tmp_path):
    engine, dependency, _, _ = runtime(tmp_path, dependency_status=RunStatus.UNAVAILABLE,
        dependency_error="OFFLINE_MODE", dependency_coverage="NONE")
    hooks = coordinator(tmp_path, engine, repo)
    start(hooks, repo)
    state_path = hooks.store.path(repo, "codex", "fixture-session")
    original = state_path.read_bytes()
    write(repo, "requirements.txt", "fixture-package==1.0\n")
    result = activity(hooks, repo)
    assert result["status"] == result["coverage"] == "PARTIAL"
    assert state_path.read_bytes() == original
    assert hooks.store.pending_activity(repo, "codex", "fixture-session") is not None
    retry = activity(hooks, repo)
    assert len(dependency.calls) == 2 and retry["status"] == "PARTIAL"


def test_dependency_finding_from_moving_source_is_not_current_hook_evidence(repo, tmp_path):
    engine, dependency, _, _ = runtime(tmp_path, issue=True)
    hooks = coordinator(tmp_path, engine, repo)
    start(hooks, repo)
    state_path = hooks.store.path(repo, "codex", "fixture-session")
    original = state_path.read_bytes()
    write(repo, "requirements.txt", "fixture-vulnerable-package==1.0\n")
    scan = dependency.scan
    def mutate_during_check(context, normalizer):
        found, run = scan(context, normalizer)
        write(repo, "app.py", "value = 999\n")
        return found, run
    dependency.scan = mutate_during_check
    result = activity(hooks, repo)
    assert result["status"] == "PARTIAL" and result["coverage"] == "UNKNOWN"
    assert not result.get("current_dependency_finding_ids")
    assert state_path.read_bytes() == original


def test_hook_removing_all_dependency_inputs_keeps_unknown_without_old_finding_ids(repo, tmp_path):
    engine, dependency, _, _ = runtime(tmp_path, issue=True)
    hooks = coordinator(tmp_path, engine, repo)
    start(hooks, repo)
    manifest = write(repo, "requirements.txt", "fixture-vulnerable-package==1.0\n")
    # Stage an addition, process it, then remove it before it ever reaches
    # HEAD. The final recheck name disappears from index AND Git dirty paths.
    git(repo, "add", "requirements.txt")
    first = activity(hooks, repo)
    assert first["current_dependency_finding_ids"] and len(dependency.calls) == 1
    manifest.unlink()
    git(repo, "add", "-u", "requirements.txt")
    assert "requirements.txt" not in git(repo, "ls-files").splitlines()
    assert "requirements.txt" not in git(repo, "diff", "--name-only", "HEAD").splitlines()
    removed = activity(hooks, repo)
    assert len(dependency.calls) == 1
    assert removed["capabilities"].get(Capability.DEPENDENCY_VULN) == "UNAVAILABLE", removed
    assert not removed.get("current_dependency_finding_ids")
    assert removed["scan_id"] != first["scan_id"]
    assert removed["delta"]["resolved"] == 0
    assert removed["status"] == "PARTIAL" and removed["scan_attempt"]["input_id"]


@pytest.mark.parametrize("exception", [RuntimeError, type("PrivateProviderFailure", (Exception,), {})])
def test_unexpected_provider_exception_keeps_stage_and_type_without_private_text(repo, tmp_path, exception):
    write(repo, "requirements.txt", "fixture-package==1.0\n")
    engine, dependency, _, _ = runtime(tmp_path)
    marker = "PRIVATE_EXCEPTION_CREDENTIAL_DO_NOT_ECHO"
    def fail(context, normalizer):
        raise exception(marker)
    dependency.scan = fail
    result = engine.scan(repo, "quick")
    run = next(item for item in result.scanner_runs if item.scanner == "trivy-vuln")
    assert run.status == RunStatus.FAILED and run.error_code == "SCANNER_FAILED"
    assert run.scanner_diagnostics["failure"] == {"stage": "PROVIDER_EXECUTION",
        "exception_type": "RuntimeError" if exception is RuntimeError else "OtherException"}
    assert result.capability_results[Capability.DEPENDENCY_VULN] == "FAILED"
    assert marker not in json.dumps(result.to_dict())
    assert marker not in json.dumps(engine.store.get_scan(result.scan_id))
    assert "PrivateProviderFailure" not in json.dumps(result.to_dict())


def test_non_git_first_hook_checks_dependency_input_but_cli_quick_still_requires_git(tmp_path):
    root = tmp_path / "source-project"
    root.mkdir()
    write(root, "app.py", "value = 1\n")
    write(root, "requirements.txt", "fixture-package==1.0\n")
    engine, dependency, _, _ = runtime(tmp_path)
    with pytest.raises(WorkspaceError, match="require Git"):
        engine.scan(root, "quick")
    assert not dependency.calls
    hooks = coordinator(tmp_path, engine, root, non_git=True)
    first = activity(hooks, root)
    assert len(dependency.calls) == 1 and dependency.offline_calls == [True]
    assert first["capabilities"][Capability.DEPENDENCY_VULN] == "EXECUTED"


def test_non_git_hook_source_edit_does_not_rescan_unchanged_manifest(tmp_path):
    root = tmp_path / "source-project"
    root.mkdir()
    write(root, "app.py", "value = 1\n")
    write(root, "requirements.txt", "fixture-package==1.0\n")
    engine, dependency, _, _ = runtime(tmp_path)
    hooks = coordinator(tmp_path, engine, root, non_git=True)
    first = activity(hooks, root)
    assert first["capabilities"][Capability.DEPENDENCY_VULN] == "EXECUTED"
    write(root, "app.py", "value = 2\n")
    activity(hooks, root)
    assert len(dependency.calls) == 1
