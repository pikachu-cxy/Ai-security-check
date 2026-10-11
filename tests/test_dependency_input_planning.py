"""Incremental dependency scope must follow manifests, including removals."""
import pytest

from security_runtime.capabilities import Capability, requested_capabilities
from security_runtime.dependency_inputs import DEPENDENCIES, is_dependency_input
from security_runtime.models import ScanMode, TargetProfile
from security_runtime.target import DEPENDENCIES as DISCOVERY_DEPENDENCIES, TargetDetector


@pytest.mark.parametrize("mode", [ScanMode.QUICK, ScanMode.FEATURE])
@pytest.mark.parametrize("name", [
    "requirements.txt", "pyproject.toml", "poetry.lock", "Pipfile.lock",
    "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
    "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile",
    "buildscript-gradle.lockfile", "go.mod", "go.sum",
])
def test_new_changed_or_removed_dependency_input_requests_check(mode, name):
    # Removed files need no current ecosystem/profile entry to trigger a check.
    profile = TargetProfile("project")
    wanted = requested_capabilities(profile, mode, ("services/api/" + name,))
    assert Capability.DEPENDENCY_VULN in wanted


@pytest.mark.parametrize("mode", [ScanMode.QUICK, ScanMode.FEATURE])
@pytest.mark.parametrize("files", [(), ("src/app.py",), ("README.md",), ("Dockerfile",), ("config.yaml",)])
def test_existing_manifest_does_not_trigger_dependency_scan_for_source_only_edit(mode, files):
    profile = TargetProfile("project", languages=["Python"], ecosystems=["pip"],
                            files=["src/app.py", "requirements.txt"])
    assert Capability.DEPENDENCY_VULN not in requested_capabilities(profile, mode, files)


def test_release_requests_dependencies_for_existing_inventory():
    profile = TargetProfile("project", ecosystems=["pip"], files=["requirements.txt"])
    assert Capability.DEPENDENCY_VULN in requested_capabilities(profile, ScanMode.RELEASE, ("requirements.txt",))


def test_discovery_and_planning_share_lockfile_identity(tmp_path):
    inputs = ["service/pnpm-lock.yaml", "service/build.gradle.kts", "service/poetry.lock", "service/go.sum"]
    for relative in inputs:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture\n", encoding="utf-8")
    profile = TargetDetector().detect(tmp_path, inputs)
    assert set(profile.ecosystems) == {"pnpm", "gradle", "pip", "go"}
    assert set(profile.files) == set(inputs)
    assert Capability.DEPENDENCY_VULN in requested_capabilities(profile, ScanMode.QUICK, tuple(inputs))
    assert DISCOVERY_DEPENDENCIES is DEPENDENCIES


def test_windows_nested_paths_are_recognized_without_broad_lock_matching():
    assert is_dependency_input(r"services\web\package-lock.json")
    assert is_dependency_input(r"services\web\Pipfile.lock")
    assert not is_dependency_input("service/random.lock")
    assert not is_dependency_input("service/package-lock.json.backup")
    assert not is_dependency_input("service/requirements.txt:alternate")
