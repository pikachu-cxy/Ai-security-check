"""Install the built wheel in a clean venv and exercise its release contract."""
from __future__ import annotations

import os
import subprocess
import tempfile
import venv
from pathlib import Path
from security_runtime._version import __version__


def run(*command: str, cwd: Path) -> None:
    subprocess.run(command, cwd=cwd, check=True, timeout=300)


def main() -> None:
    repository = Path(__file__).resolve().parents[1]
    wheels = list((repository / "dist").glob(f"ai_security_runtime-{__version__}-*.whl"))
    if len(wheels) != 1:
        raise ValueError("Expected exactly one built wheel")
    with tempfile.TemporaryDirectory(prefix="ai-security-wheel-") as temporary:
        root = Path(temporary)
        environment = root / "venv"
        venv.EnvBuilder(with_pip=True).create(environment)
        scripts = environment / ("Scripts" if os.name == "nt" else "bin")
        python = scripts / ("python.exe" if os.name == "nt" else "python")
        cli = scripts / ("security-check.exe" if os.name == "nt" else "security-check")
        run(str(python), "-m", "pip", "install", str(wheels[0]), cwd=root)
        run(str(cli), "--help", cwd=root)
        run(str(cli), "--version", cwd=root)
        run(str(cli), "licenses", "--check-distribution", cwd=root)
        check = """
from pathlib import Path
import security_runtime
from security_runtime.rulepacks import RulePackManager
package = Path(security_runtime.__file__).resolve().parent
assert package.is_relative_to(Path(__import__('sys').prefix).resolve()), package
pack = RulePackManager().resolve()
assert pack.path.samefile(package / 'rules'), (pack.path, package)
assert pack.descriptor.rule_pack_id == 'ai-security-core'
from security_runtime import task_fix, equivalence, verification, verification_policy
from security_runtime import hook_runtime, hook_state, hook_adapters
for module in (hook_runtime, hook_state, hook_adapters):
    assert Path(module.__file__).resolve().is_relative_to(package)
from security_runtime.host_guidance import runtime_info, REQUIRED_GUIDANCE_TOOLS
from security_runtime.mcp_server import create_server
assert runtime_info()['features']['task_fix_verify'] == 'v0.1'
assert runtime_info()['capability_contract'] == 'developer-guidance-v0.3'
assert REQUIRED_GUIDANCE_TOOLS <= {t.name for t in create_server()._tool_manager.list_tools()}
for engine in ('semgrep', 'gitleaks', 'trivy'):
    assert (package / 'licenses' / engine / 'LICENSE').is_file()
    assert (package / 'licenses' / engine / 'NOTICE').is_file()
assert (package / 'python_downloads.json').is_file()
from security_runtime.review_skill import ReviewSkillManager, skill_files
assert 'references/runtime-workflow.md' in skill_files()
skill = ReviewSkillManager(Path.cwd()/'synthetic-home/.agents/skills',Path.cwd()/'skill-state')
assert skill.status()['status']=='NOT_INSTALLED'
assert skill.execute('install')['status']=='INSTALLED'
assert skill.execute('repair')['changed'] is False
assert skill.execute('remove')['status']=='REMOVED'
share = Path(__import__('sys').prefix) / 'share' / 'ai-security-runtime'
assert (share / 'THIRD_PARTY_NOTICES.md').is_file()
assert (share / 'SOURCE_OFFER.md').is_file()
for name in ('LICENSE', 'EULA.md', 'LICENSING.md', 'LICENSES/Apache-2.0.txt'):
    assert (share / name).is_file()
print('Installed wheel integrity OK')
"""
        run(str(python), "-c", check, cwd=root)
        project = root / 'hook-project'
        project.mkdir()
        run('git', 'init', str(project), cwd=root)
        env = dict(os.environ, SECURITY_RUNTIME_STATE_DIR=str(root/'hook-state'), SECURITY_RUNTIME_OFFLINE='1')
        import json
        result = json.loads(subprocess.check_output([str(cli),'hook','session-start','--path',str(project),'--host','codex','--json'],
            env=env,cwd=root,text=True,encoding='utf-8',timeout=30))
        assert result['status']=='BASELINE_ESTABLISHED' and not result['execution']['scanner_run']
        result = json.loads(subprocess.check_output([str(cli),'hook','agent-stop','--path',str(project),'--host','codex','--json'],
            env=env,cwd=root,text=True,encoding='utf-8',timeout=30))
        assert result['status']=='REUSED_LAST_RESULT' and not result['execution']['scanner_run']
        run(str(cli),'hooks','install','codex','--path',str(project),'--json',cwd=root)
        run(str(cli),'hooks','remove','codex','--path',str(project),'--json',cwd=root)


if __name__ == "__main__":
    main()
