import pytest

from security_runtime.explicit_scan import run_explicit_scan
from security_runtime.hooks import GitHookManager, codex_commit_only


@pytest.mark.parametrize("options", [{"mode": "release"}, {"staged": True}])
def test_deferred_explicit_scan_rejects_before_workspace_or_runtime(options):
    with pytest.raises(ValueError, match="后续规划"):
        run_explicit_scan(None, "/missing-workspace", **options)


@pytest.mark.parametrize("action", ["install", "repair"])
def test_deferred_hook_rejects_before_read_or_write(action):
    manager = object.__new__(GitHookManager)
    with pytest.raises(ValueError, match="后续规划"):
        manager.execute(action)
    assert codex_commit_only("/missing-workspace") is False


def test_project_submission_rejected_before_job_creation():
    from security_runtime.scan_jobs import ScanJobs
    jobs = object.__new__(ScanJobs)
    with pytest.raises(ValueError, match="后续规划"):
        jobs.submit("test-project-key", mode="project")


def test_project_scan_rejected_before_cache_reuse():
    from security_runtime.workspace_application import WorkspaceApplication
    application = object.__new__(WorkspaceApplication)
    with pytest.raises(ValueError, match="后续规划"):
        application.scan_project("/missing-workspace")
