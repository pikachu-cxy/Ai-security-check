"""Exercise the archive verifier's doctor contract against the real CLI."""
import os
import json
import subprocess
import sys
from pathlib import Path

from scripts import verify_artifact


def test_verifier_skill_install_cannot_reuse_inherited_real_paths(tmp_path):
    root = tmp_path / 'acceptance'
    root.mkdir()
    real = tmp_path / 'unrelated-profile'
    real.mkdir()
    sentinel = real / 'preserve.txt'
    sentinel.write_bytes(b'unrelated user content')
    inherited = dict(os.environ, CODEX_HOME=str(real),
        SECURITY_RUNTIME_CODEX_HOME=str(real), SECURITY_RUNTIME_SKILLS_DIR=str(real / 'skills'),
        SECURITY_RUNTIME_STATE_DIR=str(real / 'state'), SECURITY_RUNTIME_GLOBAL='1',
        SECURITY_RUNTIME_TRIAL_ROOT=str(real))
    env = verify_artifact.verification_environment(root, root / 'data', full=False, inherited=inherited)
    response = subprocess.run([sys.executable, '-m', 'security_runtime.cli', 'review-skill',
        'install', '--json'], env=env, cwd=root, capture_output=True, text=True, encoding='utf-8')
    assert response.returncode == 0, response.stderr
    assert Path(json.loads(response.stdout)['path']).is_relative_to(root)
    assert (root / 'global-skills/ai-security-review/SKILL.md').is_file()
    assert sentinel.read_bytes() == b'unrelated user content'
    assert list(real.iterdir()) == [sentinel]
    assert 'SECURITY_RUNTIME_GLOBAL' not in env and 'SECURITY_RUNTIME_TRIAL_ROOT' not in env


def test_verifier_separates_global_and_project_doctors(tmp_path, monkeypatch):
    root = tmp_path / "outside-project"
    root.mkdir()
    project = root / "project"
    subprocess.run(["git", "init", "-q", str(project)], check=True)
    env = dict(os.environ, CODEX_HOME=str(root / "isolated-codex-home"),
               SECURITY_RUNTIME_DATA_DIR=str(root / "managed"),
               SECURITY_RUNTIME_STATE_DIR=str(root / "state"), SECURITY_RUNTIME_OFFLINE="1")
    Path(env["CODEX_HOME"]).mkdir()
    for name in ("SECURITY_RUNTIME_GLOBAL", "SECURITY_RUNTIME_WORKSPACE", "SECURITY_RUNTIME_CODEX_HOME"):
        env.pop(name, None)
    actual_run = subprocess.run

    def cli_run(command, **kwargs):
        # The packaged gate uses the native executable; this unit regression
        # uses real CLI routing with an installed-delivery/capability fixture.
        # The native archive gate independently exercises the actual MCP probe;
        # an editable checkout is deliberately rejected by the global DEV guard.
        entry = ("from security_runtime import global_integration as g; "
                 "from security_runtime import codex_integration as c; "
                 "from security_runtime.host_guidance import runtime_info; "
                 "from security_runtime.codex_integration import current_runtime; "
                 "g.installed_runtime = current_runtime; "
                 "c.probe_runtime = lambda *a: c.check_capabilities(runtime_info(), c.REQUIRED_TOOLS); "
                 "from security_runtime.cli import main; raise SystemExit(main())")
        return actual_run([sys.executable, "-c", entry, *command[1:]], **kwargs)

    monkeypatch.setattr(verify_artifact.subprocess, "run", cli_run)
    report = verify_artifact.verify_doctors(Path(sys.executable), root, project, env)
    assert report["default_global"] == "NOT_INSTALLED"
    assert report["missing_project"] == "NO_PROJECT"
    assert report["explicit_project"] in {"ready", "limited"}
    assert not list((root / "isolated-codex-home").iterdir())
