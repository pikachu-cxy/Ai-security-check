"""Install the built wheel in a clean venv and exercise its release contract."""
from __future__ import annotations

import os
import argparse
import subprocess
import tempfile
import venv
from pathlib import Path
from security_runtime._version import __version__


def run(*command: str, cwd: Path) -> None:
    subprocess.run(command, cwd=cwd, check=True, timeout=300)


def main(wheel: Path | None = None, *, offline=False) -> None:
    repository = Path(__file__).resolve().parents[1]
    wheels = [wheel.resolve()] if wheel else list((repository / "dist").glob(f"ai_security_runtime-{__version__}-*.whl"))
    if len(wheels) != 1:
        raise ValueError("Expected exactly one built wheel")
    with tempfile.TemporaryDirectory(prefix="ai-security-wheel-") as temporary:
        # Windows may return an 8.3 TEMP alias; keep the whole synthetic home
        # and interpreter under one canonical long-path identity.
        root = Path(temporary).resolve()
        environment = root / "venv"
        venv.EnvBuilder(with_pip=True, system_site_packages=offline).create(environment)
        os.environ['SECURITY_RUNTIME_STATE_DIR'] = str(root/'isolated-state')
        os.environ['SECURITY_RUNTIME_OFFLINE'] = '1'
        scripts = environment / ("Scripts" if os.name == "nt" else "bin")
        python = scripts / ("python.exe" if os.name == "nt" else "python")
        cli = scripts / ("security-check.exe" if os.name == "nt" else "security-check")
        flags = ['--no-index', '--no-deps'] if offline else []
        run(str(python), "-m", "pip", "install", *flags, str(wheels[0]), cwd=root)
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
assert pack.descriptor.version == '1.3.2'
assert len(pack.catalog) == 56
assert not any(c.auto_fix_eligible for c in pack.program.capabilities)
from security_runtime.rule_coverage import plan_rules
assert len(plan_rules(pack, ['app.py']).rules) == 16
for target in ('app.js', 'view.jsx', 'app.ts', 'view.tsx'):
    plan = plan_rules(pack, [target])
    assert plan.files == (target,) and len(plan.rules) == 6, target
assert any(rule.rule_id == 'ai-security.java.spring-named-jdbc' for rule in pack.catalog)
from security_runtime import task_fix, equivalence, verification, verification_policy
from security_runtime import hook_runtime, hook_state, hook_adapters
for module in (hook_runtime, hook_state, hook_adapters):
    assert Path(module.__file__).resolve().is_relative_to(package)
from security_runtime.host_guidance import runtime_info, REQUIRED_GUIDANCE_TOOLS, HOST_INSTRUCTIONS, RUNTIME_WORKFLOW
from security_runtime.mcp_server import create_server
from security_runtime.professional_guidance import get_professional_guidance
guide = get_professional_guidance()
assert guide['status'] == 'READY' and guide['source'] == 'BUNDLED'
assert guide['delivery']['remote_fetch_implemented'] is False
assert not any(guide['execution'].values())
assert runtime_info()['features']['task_fix_verify'] == 'v0.1'
assert runtime_info()['capability_contract'] == 'developer-guidance-v0.3'
assert runtime_info()['remediation']['user_consent_required'] is True
assert runtime_info()['remediation']['automatic_fix_without_user_consent'] is False
assert 'is analysis, not repair' in RUNTIME_WORKFLOW
assert '沉默和计划均不授权' in HOST_INSTRUCTIONS
from security_runtime.remediation_policy import RemediationConfig, RemediationPolicy, RULE
policy = RemediationConfig(Path.cwd()/'isolated-policy.json')
assert policy.read() == 'ask_before_fix'
policy.write('smart_auto')
assert policy.read() == 'ask_before_fix'
for mode in ('smart_auto', 'ask_before_fix'):
    assert RemediationPolicy().decide(rule=RULE, priority='ACTIONABLE', coverage=True,
        deterministic=True, mode=mode).action == 'CONFIRM_REQUIRED'
assert REQUIRED_GUIDANCE_TOOLS <= {t.name for t in create_server()._tool_manager.list_tools()}
for engine in ('semgrep', 'gitleaks', 'trivy'):
    assert (package / 'licenses' / engine / 'LICENSE').is_file()
    assert (package / 'licenses' / engine / 'NOTICE').is_file()
assert (package / 'python_downloads.json').is_file()
from security_runtime.review_skill import ReviewSkillManager, skill_files
assert 'references/runtime-workflow.md' in skill_files()
assert 'references/deep-audit.md' in skill_files()
assert '沉默和计划均不授权' in skill_files()['SKILL.md'].decode('utf-8')
from security_runtime.compatibility import requirements, storage_contracts, TASK_REVIEW_TOOLS
from security_runtime.guidance_catalog import TOPICS, get_runtime_guidance, manifest as guidance_manifest
from security_runtime.task_security import method
from security_runtime.build_identity import STATE_SCHEMA
assert STATE_SCHEMA == 'runtime-state-v1'
assert {'task-risk-authority-v2', 'closure-authority-v2', 'persistence-effect-v1',
        'private-authority-writer-fence-v1', 'closeout-persistence-v1'} <= set(storage_contracts())
assert TASK_REVIEW_TOOLS <= {t.name for t in create_server()._tool_manager.list_tools()}
assert 'task-review-plan-v3' in runtime_info()['features']['task_security_review_protocol']
assert runtime_info()['guidance_catalog'] == guidance_manifest()
files = skill_files()
assert 'references/quick-task-review-v3.md' in files
assert not {'references/quick-task-review.md', 'references/quick-task-review-v2.md'} & files.keys()
for topic in TOPICS:
    guidance = get_runtime_guidance(topic)
    assert guidance['status'] == 'READY' and not any(guidance['execution'].values())
    assert guidance['content'].encode('utf-8') == files[guidance['local_reference']]
    assert (package/'skills/ai-security-review'/guidance['local_reference']).read_bytes() == files[guidance['local_reference']]
task_guide = get_runtime_guidance('task-review')
assert (task_guide['version'],task_guide['sha256']) == (method(3)['version'],method(3)['sha256'])
assert (package/'skills/ai-security-review/references/deep-audit.md').is_file()
skill = ReviewSkillManager(Path.cwd()/'synthetic-home/.agents/skills',Path.cwd()/'skill-state')
assert skill.status()['status']=='NOT_INSTALLED'
assert skill.status()['compatibility_requirements'] == requirements()
assert skill.status()['requirements_scope'] == 'DECLARATION_NOT_HOST_TOOL_DISCOVERY'
assert skill.execute('install')['status']=='INSTALLED'
for topic in TOPICS:
    guidance = get_runtime_guidance(topic)
    assert (skill.root/guidance['local_reference']).read_bytes() == files[guidance['local_reference']]
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
        from security_runtime.trial import isolated_environment
        import json
        env = isolated_environment(root)
        completed = subprocess.run([str(cli), 'install', 'codex', '--json'],
            env=env, cwd=root, timeout=120, capture_output=True, check=False)
        install = json.loads(completed.stdout)
        if completed.returncode:
            diagnostic_env = dict(env, SECURITY_RUNTIME_GLOBAL='1', SECURITY_RUNTIME_WORKSPACE='',
                SECURITY_RUNTIME_INTEGRATION='codex', SECURITY_RUNTIME_MCP_SELF_TEST='1')
            diagnostic = subprocess.run([str(python), '-I', '-m', 'security_runtime.cli', 'runtime-info', '--json'],
                env=diagnostic_env, cwd=root, timeout=60, capture_output=True, check=False)
            data = json.loads(diagnostic.stdout) if diagnostic.returncode == 0 else {}
            print('Isolated runtime-info diagnostic: ' + json.dumps({'exit_code':diagnostic.returncode,
                'stdout_bytes':len(diagnostic.stdout), 'version':data.get('version'),
                'scope':data.get('integration_scope'), 'global_feature':data.get('features', {}).get('global_runtime_integration')}))
            mcp_check = """
import asyncio, json, os, sys, tempfile
from datetime import timedelta
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from security_runtime.codex_integration import check_capabilities, REQUIRED_TOOLS
async def check():
    stage = 'INITIALIZE'
    try:
        with tempfile.TemporaryFile(mode='w+', encoding='utf-8') as errors:
            params = StdioServerParameters(command=sys.executable, args=['-I','-m','security_runtime.cli','mcp'], env=dict(os.environ), cwd=os.getcwd())
            async with stdio_client(params, errlog=errors) as (reader, writer):
                async with ClientSession(reader, writer, read_timeout_seconds=timedelta(seconds=30)) as session:
                    await session.initialize()
                    stage = 'LIST_TOOLS'
                    listed = (await session.list_tools()).tools
                    stage = 'RUNTIME_INFO'
                    response = await session.call_tool('get_runtime_info', {})
                    info = response.structuredContent or json.loads(response.content[0].text)
                    info = info.get('result', info)
                    result = check_capabilities(info, {t.name for t in listed})
                    print(json.dumps({'stage':stage, 'capabilities':result['status'], 'global':info.get('integration_scope'), 'tool_count':len(listed),
                        'findings_has_workspace_claim':any(t.name == 'get_findings' and 'workspace_path' in t.inputSchema.get('properties', {}) for t in listed)}))
    except Exception as exc:
        def kinds(value):
            return [type(value).__name__, *[name for child in getattr(value, 'exceptions', ()) for name in kinds(child)]]
        print(json.dumps({'stage':stage,'exception_classes':kinds(exc)}))
asyncio.run(asyncio.wait_for(check(), timeout=60))
"""
            subprocess.run([str(python), '-I', '-c', mcp_check], env=diagnostic_env,
                cwd=root, timeout=70, check=True)
        assert completed.returncode == 0, install.get('diagnostics')
        assert install['installation']['local_files_ready'] is True
        assert install['skill']['status'] == 'INSTALLED'
        assert (root / 'skills/ai-security-review/references/deep-audit.md').is_file()
        assert install['installation']['risk_fix_authorized'] is False
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
    parser = argparse.ArgumentParser()
    parser.add_argument('--wheel', type=Path)
    parser.add_argument('--offline', action='store_true', help='Isolated installation using existing local dependencies; never download')
    args = parser.parse_args()
    main(args.wheel, offline=args.offline)
