"""Extract a release archive and exercise the installed executable."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from pathlib import Path

from security_runtime._version import __version__
from security_runtime.toolchain import platform_key

REQUIRED_TOOLS = {"scan_diff", "scan_project", "get_findings", "generate_fix", "verify", "prepare_triage", "submit_triage", "get_triage", "get_security_summary", "prepare_task_triage", "get_runtime_info", "prepare_task_fix", "verify_task_fix"}
PLUGIN_PROBE = '''
from security_runtime.capabilities import Capability
from security_runtime.models import ScannerRun, RunStatus
from security_runtime.plugin_api import ScannerPluginMetadata
class Probe:
    scanner_id = name = "distribution-probe"
    display_name = "Distribution plugin probe"
    capabilities = frozenset({Capability.SECRET_SCAN})
    supported_languages = frozenset()
    supported_ecosystems = frozenset()
    filter_changed_lines = False
    metadata = ScannerPluginMetadata(scanner_id, display_name, "1.0.0", "1.0.0", capabilities, supported_languages, supported_ecosystems, ())
    def required_engines(self): return ()
    def supports(self, profile, context): return True
    def normalize(self, raw, normalizer): return []
    def scan(self, context, normalizer):
        return [], ScannerRun(self.scanner_id, "1.0.0", RunStatus.SUCCESS, 0, 0)
'''


async def verify_mcp(executable: Path, root: Path, project: Path, env: dict[str, str]) -> list[str]:
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    environment = dict(env, SECURITY_RUNTIME_WORKSPACE=str(project), SECURITY_RUNTIME_OFFLINE="1")
    params = StdioServerParameters(command=str(executable), args=["mcp"], cwd=root, env=environment)
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stderr:
        async with stdio_client(params, errlog=stderr) as (read, write):
            async with ClientSession(read, write) as client:
                initialized=await asyncio.wait_for(client.initialize(), timeout=30)
                if 'Do not ask users for Finding UUIDs' not in (initialized.instructions or ''):
                    raise ValueError('Standalone host workflow instructions missing')
                names = {tool.name for tool in (await client.list_tools()).tools}
                if not REQUIRED_TOOLS.issubset(names):
                    raise ValueError("Standalone MCP tools incomplete")
                runtime=await client.call_tool('get_runtime_info',{})
                if runtime.isError:raise ValueError('Standalone runtime capability discovery failed')
                runtime_data=runtime.structuredContent or json.loads(runtime.content[0].text)
                runtime_data=runtime_data.get('result',runtime_data)
                if runtime_data['features']['task_triage']!='v0.1':raise ValueError('Standalone task capability missing')
                if runtime_data['features']['task_fix_verify']!='v0.1':raise ValueError('Standalone task fix capability missing')
                summary_before=await client.call_tool('get_security_summary',{})
                if summary_before.isError: raise ValueError('Standalone security summary failed')
                response = await asyncio.wait_for(client.call_tool("scan_diff", {}), timeout=120)
                if response.isError:
                    raise ValueError("Standalone MCP scan_diff failed")
                payload = response.structuredContent or json.loads(response.content[0].text)
                payload = payload.get("result", payload)
                if payload.get('target_selection', {}).get('excluded_count') != 1:
                    raise ValueError('Standalone MCP did not retain binary document exclusion evidence')
                if not Path(payload["workspace"]).samefile(project):
                    raise ValueError("Standalone MCP workspace binding is incorrect")
                task_summary=await client.call_tool('get_security_summary',{'scan_id':payload['scan_id'],'details':True})
                if task_summary.isError: raise ValueError('Standalone task summary failed')
                tasks=task_summary.structuredContent or json.loads(task_summary.content[0].text)
                tasks=tasks.get('result',tasks)['tasks']
                prepared=await client.call_tool('prepare_task_triage',tasks[0]['continuation']['arguments']) if tasks else await client.call_tool('prepare_triage',{'scan_id':payload['scan_id']})
                if prepared.isError: raise ValueError('Standalone prepare_triage failed')
                data=prepared.structuredContent or json.loads(prepared.content[0].text)
                data=data.get('result',data)
                if data['packets']:
                    packet=data['packets'][0]
                    if packet['category']=='code' and packet['local_evidence']['evidence_status']!='EXACT':
                        raise ValueError('Fresh standalone SAST triage evidence is not original EXACT')
                    # Explicit mock host analysis, real frozen Runtime validation.
                    value={'finding_id':packet['finding_id'],'context_hash':packet['context_hash'],
                        'verdict':'NEEDS_REVIEW','confidence':'LOW','exploitability':'UNKNOWN',
                        'reason':'Synthetic standalone host analysis; context remains unknown.','attack_path':'',
                        'evidence_refs':[{'file':packet['file'],'start_line':packet['line']['start'],'end_line':packet['line']['end'],'claim':'Scanner candidate'}],
                        'preconditions_met':[],'preconditions_unknown':['Reachability'],'recommended_action':'Review'}
                    accepted=await client.call_tool('submit_triage',{'scan_id':payload['scan_id'],'results':[value],'triage_session':data['triage_session'],'compact':True})
                    if accepted.isError: raise ValueError('Standalone submit_triage failed')
                    ack=accepted.structuredContent or json.loads(accepted.content[0].text)
                    ack=ack.get('result',ack)
                    if ack['accepted']!=1 or 'view' in ack: raise ValueError('Standalone compact triage contract failed')
                listed=await client.call_tool('get_findings',{'scan_id':payload['scan_id'],'view':'summary','limit':5})
                if listed.isError: raise ValueError('Standalone paged findings failed')
                listing=listed.structuredContent or json.loads(listed.content[0].text)
                listing=listing.get('result',listing)
                if listing['items']:
                    detail=await client.call_tool('get_findings',{'scan_id':payload['scan_id'],
                        'finding_id':listing['items'][0]['id'],'view':'page','limit':1,'include_evidence':True})
                    if detail.isError: raise ValueError('Standalone local evidence detail failed')
                view=await client.call_tool('get_triage',{'scan_id':payload['scan_id']})
                if view.isError: raise ValueError('Standalone triage view failed')
                summary=await client.call_tool('get_security_summary',{'scan_id':payload['scan_id'],'details':True})
                if summary.isError: raise ValueError('Standalone detailed security summary failed')
                summary_data=summary.structuredContent or json.loads(summary.content[0].text)
                summary_data=summary_data.get('result',summary_data)
                if summary_data['scan_id']!=payload['scan_id'] or summary_data['automatic_execution']:
                    raise ValueError('Standalone summary identity/action contract failed')
                for task in summary_data['tasks'][:1]:
                    prepared_fix = await client.call_tool('prepare_task_fix', task['fix_handoff']['arguments'])
                    if prepared_fix.isError: raise ValueError('Standalone prepare_task_fix failed')
                    fix = prepared_fix.structuredContent or json.loads(prepared_fix.content[0].text)
                    fix = fix.get('result', fix)
                    if fix['execution']['patch_applied'] or not fix['fix_constraints']:
                        raise ValueError('Standalone fix constraints/execution contract failed')
                    checked = await client.call_tool('verify_task_fix', fix['verification_plan']['arguments'])
                    if checked.isError: raise ValueError('Standalone verify_task_fix failed')
                    checked_data = checked.structuredContent or json.loads(checked.content[0].text)
                    checked_data = checked_data.get('result', checked_data)
                    if checked_data['status'] not in {'STILL_PRESENT','INCONCLUSIVE','NOT_VERIFIED'}:
                        raise ValueError('Standalone unchanged source falsely resolved')
                # Even a smoke with no candidates exercises fail-closed entry
                # points, without initializing state or choosing another task.
                if not summary_data['tasks']:
                    for name in ('prepare_task_fix','verify_task_fix'):
                        bad = await client.call_tool(name, {'task_ref':'T01'})
                        if bad.isError: raise ValueError('Standalone invalid fix reference protocol failed')
                        bad_data = bad.structuredContent or json.loads(bad.content[0].text)
                        if bad_data.get('result', bad_data)['status'] != 'REFRESH_REQUIRED':
                            raise ValueError('Standalone task number retargeted')
        stderr.seek(0)
        if "IncompleteFieldDefinitionWarning" in stderr.read():
            raise ValueError("Standalone MCP Settings warning returned")
    return sorted(names)


def extract(archive: Path, root: Path) -> None:
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as package:
            for member in package.infolist():
                target = (root / member.filename).resolve()
                if not target.is_relative_to(root.resolve()):
                    raise ValueError("Archive escapes extraction directory")
            package.extractall(root)
    else:
        with tarfile.open(archive, "r:gz") as package:
            from security_runtime.delivery import bundle_link_name
            seen, total = set(), 0
            for member in package.getmembers():
                from pathlib import PurePosixPath
                name = PurePosixPath(member.name)
                if (name.is_absolute() or '..' in name.parts or name.as_posix() != member.name
                        or name.parts[0] != 'security-check' or member.name in seen
                        or any(c in member.name for c in ('\\', ':', '\x00'))
                        or not (member.isfile() or member.isdir() or member.issym())):
                    raise ValueError("Unsafe archive member")
                seen.add(member.name)
                total += member.size
                if len(seen) > 20_000 or total > 2_000_000_000:
                    raise ValueError('Archive exceeds package limits')
                if member.issym():
                    bundle_link_name('/'.join(name.parts[1:]), member.linkname)
            # Python's data filter also checks actual parent/link containment at IO.
            package.extractall(root, filter='data')
    from security_runtime.delivery import package_metadata
    package_metadata(root / 'security-check')


def run(command: list[str], *, cwd: Path, env: dict[str, str], timeout: int = 60) -> subprocess.CompletedProcess:
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True, encoding="utf-8", timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{command[1:]} failed ({result.returncode}): {result.stderr[-1000:]} {result.stdout[-1000:]}")
    return result


def verify_sample_scan(payload, *, dependency=False):
    """Engine execution and declared inventory are separate from graph completeness."""
    expected = {'semgrep': 'SUCCESS', 'gitleaks': 'SUCCESS',
                'trivy-vuln': 'SUCCESS' if dependency else 'NOT_APPLICABLE',
                'trivy-misconfig': 'NOT_APPLICABLE'}
    runs = {item['scanner']: item for item in payload['scanner_runs']}
    if 'native-js-function' in runs:
        expected['native-js-function'] = 'NOT_APPLICABLE'
    if {name: item['status'] for name, item in runs.items()} != expected:
        raise ValueError('Sample scan has unexpected engine execution: ' + json.dumps(payload['scanner_runs']))
    if payload.get('coverage') != ('PARTIAL' if dependency else 'FULL'):
        raise ValueError('Sample scan has unexpected declared scope: ' + str(payload.get('coverage')))
    if dependency:
        run = runs['trivy-vuln']
        inventory = run.get('dependency_inventory', {})
        coordinates = inventory.get('package_coordinates', [])
        if (run.get('coverage_contract') != 'PARTIAL' or not run.get('coverage_notes')
                or inventory.get('vulnerability_db_freshness') != 'FRESH'
                or inventory.get('complete_dependency_graph_attested') is not False
                or inventory.get('inventory_truncated') is not False
                or not any(p.get('manifest') == 'requirements.txt' and p.get('package') == 'requests'
                           and p.get('version') == '2.31.0' and p.get('ecosystem') == 'pip'
                           for p in coordinates)):
            raise ValueError('Declared dependency inventory or fresh vulnerability data not verified')


def verification_environment(root: Path, data: Path, *, full: bool, inherited=None) -> dict[str, str]:
    """Keep configuration, Skill and state in the disposable acceptance root."""
    inherited = os.environ if inherited is None else inherited
    env = {key: value for key, value in inherited.items()
           if not key.upper().startswith(('SECURITY_RUNTIME_', 'SEMGREP_', 'GITLEAKS_', 'TRIVY_', 'OSV_'))
           and key.upper() not in {'CODEX_HOME', 'PYTHONPATH', 'PYTHONHOME'}}
    env.update(SECURITY_RUNTIME_DATA_DIR=str(data), SECURITY_RUNTIME_STATE_DIR=str(root / 'state'),
               CODEX_HOME=str(root / 'codex-home'), SECURITY_RUNTIME_CODEX_HOME=str(root / 'codex-home'),
               SECURITY_RUNTIME_SKILLS_DIR=str(root / 'global-skills'),
               SECURITY_RUNTIME_PLUGIN_DIR=str(root / 'plugins'), SECURITY_RUNTIME_OFFLINE='0' if full else '1')
    return env


def verify_global_ownership(executable: Path, root: Path, env: dict[str, str]) -> dict:
    home = root / 'global-ownership-home'
    home.mkdir()
    path = home / 'config.toml'
    original = (b'# preserve synthetic sibling bytes\nmodel="fixture"\n'
                b'[marketplaces.fixture]\nsource="synthetic"\n'
                b'[mcp_servers.sibling]\ncommand="synthetic"\n'
                b'[hooks.state.fixture]\nenabled=true\ntrusted_hash="synthetic"\n')
    path.write_bytes(original)
    environment = {**env, 'CODEX_HOME': str(home), 'SECURITY_RUNTIME_CODEX_HOME': str(home),
                   'SECURITY_RUNTIME_SKILLS_DIR': str(home / 'skills')}
    def cli(action):
        return json.loads(run([str(executable), action, '--json'], cwd=root, env=environment).stdout)
    installed = cli('setup')
    if installed['overall'] != 'CONFIGURED' or installed['mcp']['ownership_state'] != 'OWNED_AND_CURRENT':
        raise ValueError('Global semantic ownership install failed')
    canonical = path.read_bytes()
    if b'AI Security Runtime managed Codex' in canonical:
        raise ValueError('Global install still relies on marker blocks')
    # Reproduce real missing-END dogfood in the frozen binary, signed entry intact.
    path.write_bytes(b'# BEGIN AI Security Runtime managed Codex v0.2\n' + canonical)
    if cli('status')['overall'] != 'CONFIGURED':
        raise ValueError('Global ownership depends on END marker')
    if cli('repair')['overall'] != 'CONFIGURED' or path.read_bytes() != canonical:
        raise ValueError('Global marker migration failed or sibling bytes changed')
    owned_files = [path, home / 'hooks.json', home / 'skills/ai-security-review/SKILL.md']
    before_repeat = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in owned_files if p.is_file()}
    repeated = cli('repair')
    # The public repair route now returns a transaction receipt. Check its
    # behavior, not the older adapter-only ALREADY_CONFIGURED operation label.
    if (repeated['overall'] != 'CONFIGURED' or
            before_repeat != {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in before_repeat}):
        raise ValueError('Global repair is not idempotent')
    parsed = tomllib.loads(canonical.decode())
    path.write_bytes(canonical.replace(b'enabled = true', b'enabled = false', 1))
    refused = subprocess.run([str(executable), 'status', '--json'], cwd=root, env=environment,
                             capture_output=True, text=True, encoding='utf-8', timeout=60)
    if refused.returncode == 0 or 'MCP_CONFIGURATION_CONFLICT' not in refused.stdout:
        raise ValueError('Global semantic tamper was not rejected')
    path.write_bytes(canonical)
    if cli('uninstall')['overall'] != 'NOT_INSTALLED' or path.read_bytes() != original:
        raise ValueError('Global removal changed unrelated configuration')
    if 'ai_security_runtime' not in parsed['mcp_servers']:
        raise ValueError('Global MCP entry missing')
    return {'install': 'PASS', 'missing_end': 'PASS', 'repair': 'PASS',
            'tamper_rejection': 'PASS', 'sibling_bytes': 'PRESERVED', 'uninstall': 'PASS'}


def verify_doctors(executable: Path, root: Path, project: Path, env: dict[str, str]) -> dict:
    default = run([str(executable), "doctor"], cwd=root, env=env)
    if "Global Codex" not in default.stdout:
        raise ValueError("Standalone default doctor did not report Global Codex")
    global_report = json.loads(run([str(executable), "doctor", "--json"], cwd=root, env=env).stdout)
    if (global_report.get("scope") != "GLOBAL" or global_report.get("integration") != "codex"
            or global_report.get("overall") != "NOT_INSTALLED"):
        raise ValueError("Standalone global doctor did not report the isolated unconfigured home")
    no_project = subprocess.run([str(executable), "doctor", "--project"], cwd=root, env=env,
                                capture_output=True, text=True, encoding="utf-8", timeout=30)
    if no_project.returncode != 2 or "No project detected" not in no_project.stdout + no_project.stderr:
        raise ValueError("Standalone project doctor did not report the missing project")
    explicit = json.loads(run([str(executable), "doctor", "--path", str(project), "--json"],
                              cwd=root, env=env).stdout)
    workspace = explicit.get("workspace") or {}
    if not workspace.get("git") or not Path(workspace.get("path", "")).samefile(project):
        raise ValueError("Standalone explicit project doctor reported the wrong workspace")
    return {"default_global": global_report["overall"], "missing_project": "NO_PROJECT",
            "explicit_project": explicit["status"]}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("--full", action="store_true", help="Prepare real managed engines and run a real sample scan")
    parser.add_argument("--osv-fallback", action="store_true", help="Also exercise actual offline OSV CLI/MCP fallback using a synthetic inventory")
    parser.add_argument('--fix-verify', action='store_true', help='Also exercise actual offline synthetic Java task fix/verify via native MCP')
    parser.add_argument('--hooks', action='store_true', help='Also exercise offline native Hook CLI with actual local engines')
    parser.add_argument('--remediation', action='store_true', help='Also exercise report, explicit user choice and MCP repair/verification with simulated host edits')
    parser.add_argument('--codex-integration', action='store_true', help='Exercise disposable owned Codex lifecycle and fresh MCP readiness without warmup')
    parser.add_argument("--data-dir", type=Path, help="Retain managed engine cache between local verification attempts")
    args = parser.parse_args()
    if args.osv_fallback and not args.full:
        parser.error('--osv-fallback requires --full')
    if args.fix_verify and not args.full:
        parser.error('--fix-verify requires --full for local managed Semgrep availability')
    if args.hooks and not args.full:
        parser.error('--hooks requires --full for local managed engines')
    if args.remediation and not args.full:
        parser.error('--remediation requires --full for local managed engines')
    if args.codex_integration and not args.full:
        parser.error('--codex-integration requires --full for local managed engines')
    with tempfile.TemporaryDirectory(prefix="ai-security-release-") as temporary:
        root = Path(temporary).resolve()
        extract(args.archive, root)
        bundle = root / "security-check"
        executable = bundle / ("security-check.exe" if os.name == "nt" else "security-check")
        for name in ("LICENSE", "EULA.md", "LICENSING.md", "LICENSES/Apache-2.0.txt", "THIRD_PARTY_NOTICES.md", "SOURCE_OFFER.md", "version.json"):
            if not (bundle / name).is_file():
                raise ValueError(f"Artifact missing {name}")
        metadata = json.loads((bundle / "version.json").read_text(encoding="utf-8"))
        if metadata["version"] != __version__:
            raise ValueError("Version metadata mismatch")
        if any("semgrep-rules" in part.lower() or part == ".git" for path in bundle.rglob("*") for part in path.parts):
            raise ValueError("Forbidden content in artifact")
        data = args.data_dir.resolve() if args.data_dir else root / "user-data"
        osv_preexisting = (data/'tools'/'osv-scanner').exists()
        env = verification_environment(root, data, full=args.full)
        # Default doctor and setup must never inspect the real config or Skill.
        Path(env["CODEX_HOME"]).mkdir()
        git = shutil.which("git")
        if git is None:
            raise ValueError("Git is required by the artifact verification sample")
        system = Path(os.environ.get("SystemRoot", "C:/Windows"))
        # The Windows root can contain the developer's py launcher. Native
        # verification must not accidentally inherit that fallback runtime.
        platform_paths = [system / "System32"] if os.name == "nt" else [Path("/usr/bin"), Path("/bin")]
        env["PATH"] = os.pathsep.join(map(str, [bundle, Path(git).parent, *platform_paths]))
        if os.name == "nt" and any(shutil.which(name, path=env["PATH"]) for name in ("python", "python3", "py")):
            raise ValueError("Developer Python must not be available on standalone verification PATH")
        version = run([str(executable), "--version"], cwd=root, env=env).stdout.strip()
        if version != f"AI Security Runtime {__version__}":
            raise ValueError(f"Unexpected version: {version}")
        run([str(executable), "--help"], cwd=root, env=env)
        skills = root / 'isolated-skills'
        installed = json.loads(run([str(executable),'review-skill','install','--skills-dir',str(skills),'--json'],cwd=root,env=env).stdout)
        if installed['status']!='INSTALLED': raise ValueError('Standalone companion Skill install failed')
        skill_root = skills / 'ai-security-review'
        workflow = (skill_root/'references/runtime-workflow.md').read_text(encoding='utf-8')
        from security_runtime.host_guidance import HOST_INSTRUCTIONS
        if HOST_INSTRUCTIONS not in workflow: raise ValueError('Standalone Skill canonical workflow mismatch')
        custom = skill_root/'user-notes.txt'
        custom.write_bytes(b'preserve user notes\r\n')
        for action in ('status','upgrade','repair','remove'):
            run([str(executable),'review-skill',action,'--skills-dir',str(skills),'--json'],cwd=root,env=env)
        if custom.read_bytes()!=b'preserve user notes\r\n': raise ValueError('Standalone Skill erased user content')
        project = root / "project"
        project.mkdir()
        run(["git", "init", "-q", str(project)], cwd=root, env=env)
        with zipfile.ZipFile(project / 'large-document.docx', 'w', compression=zipfile.ZIP_STORED) as document:
            document.writestr('word/document.xml', b'x' * 1_100_000)
        oversized = root / 'oversized-project'
        oversized.mkdir()
        (oversized / 'large.py').write_bytes(b'x' * 1_000_001)
        rejected = subprocess.run([str(executable), 'scan', '--mode', 'release', '--path', str(oversized), '--json', '--no-progress'],
                                  cwd=root, env=env, capture_output=True, text=True, encoding='utf-8', timeout=60)
        rejection = json.loads(rejected.stdout)
        if (rejected.returncode != 2 or rejection.get('reason_code') != 'TARGET_FILE_SIZE_LIMIT_EXCEEDED'
                or rejection.get('scanner_run') is not False or rejection.get('coverage') != 'UNKNOWN'):
            raise ValueError('Standalone oversized source did not fail closed with typed diagnostic')
        doctors = verify_doctors(executable, root, project, env)
        global_ownership = verify_global_ownership(executable, root, env)
        run([str(executable), "licenses", "--check-distribution"], cwd=root, env=env)
        if args.full:
            for tool in ("semgrep", "gitleaks", "trivy"):
                print(f"Preparing managed {tool}", flush=True)
                run([str(executable), "tools", "install", tool], cwd=project, env=env, timeout=1200)
                parent = data / ("engines" if tool == "semgrep" else "tools") / tool
                if not list(parent.glob("*/metadata.json")):
                    raise ValueError(f"{tool} was not installed as a managed engine")
            reuse_paths = [path for parent in (data / "python", data / "engines" / "semgrep")
                           for path in parent.rglob("*") if path.name in {"metadata.json", "install.json"}]
            before_reuse = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in reuse_paths}
            run([str(executable), "tools", "install", "semgrep"], cwd=project,
                env=dict(env, SECURITY_RUNTIME_OFFLINE="1"), timeout=60)
            if not before_reuse or any((path.read_bytes(), path.stat().st_mtime_ns) != saved
                                       for path, saved in before_reuse.items()):
                raise ValueError("Standalone second Semgrep preparation did not reuse managed installation")
            (project / "app.py").write_text("import os\nos.system(input())\n", encoding="utf-8")
            result = subprocess.run([str(executable), "scan", "--mode", "quick", "--path", str(project), "--json"],
                                    cwd=project, env=env, capture_output=True, text=True, encoding="utf-8", timeout=1200)
            if result.returncode not in (0, 1):
                raise RuntimeError(f"Sample scan failed: {result.stderr[-1000:]}")
            payload = json.loads(result.stdout)
            if not any("command-injection" in str(item.get("technical_details", {}).get("rule_id", ""))
                       for item in payload.get("findings", [])):
                raise ValueError("First-party scanner finding missing")
            verify_sample_scan(payload)
            # Dependency manifests are a distinct release check, not a source-only QUICK.
            (project / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
            release_scan = subprocess.run([str(executable), "scan", "--mode", "release", "--path", str(project), "--json"],
                                          cwd=project, env=env, capture_output=True, text=True, encoding="utf-8", timeout=1200)
            if release_scan.returncode not in (0, 1):
                raise RuntimeError(f"Release sample scan failed: {release_scan.stderr[-1000:]}")
            release_payload = json.loads(release_scan.stdout)
            verify_sample_scan(release_payload, dependency=True)
            all_engines = release_payload["scanner_runs"]
            if any(item["status"] not in {"SUCCESS", "NOT_APPLICABLE"} for item in all_engines):
                raise ValueError("Full sample scan has unavailable or failed engines: " + json.dumps(all_engines))
            if not osv_preexisting and (data/'tools'/'osv-scanner').exists():
                raise ValueError('Healthy primary scanner preparation/scan unexpectedly downloaded OSV')
            if args.osv_fallback:
                # An explicit acceptance operation, after proving a healthy
                # normal scan did not prepare the optional engine.
                run([str(executable),'tools','install','osv-scanner'],cwd=project,env=env,timeout=180)
                script=Path(__file__).with_name('osv_fallback_acceptance.py').resolve()
                evidence=args.archive.resolve().with_name(args.archive.name+'.osv-fallback.json')
                run([sys.executable,str(script),'--executable',str(executable),'--output',str(evidence)],cwd=root,env=env,timeout=120)
            plugin = Path(env["SECURITY_RUNTIME_PLUGIN_DIR"])
            plugin.mkdir(parents=True, exist_ok=True)
            (plugin / "distribution_probe.py").write_text(PLUGIN_PROBE, encoding="utf-8")
            plugin_metadata = plugin / "distribution_probe-1.0.0.dist-info"
            plugin_metadata.mkdir(exist_ok=True)
            (plugin_metadata / "METADATA").write_text("Metadata-Version: 2.1\nName: distribution-probe\nVersion: 1.0.0\n", encoding="utf-8")
            (plugin_metadata / "entry_points.txt").write_text("[ai_security_runtime.scanners]\ndistribution-probe = distribution_probe:Probe\n", encoding="utf-8")
            plugin_result = subprocess.run([str(executable), "scan", "--mode", "quick", "--path", str(project), "--json"],
                                           cwd=root, env=env, capture_output=True, text=True, encoding="utf-8", timeout=1200)
            if plugin_result.returncode not in (0, 1) or not any(
                    item["scanner"] == "distribution-probe" and item["status"] == "SUCCESS"
                    for item in json.loads(plugin_result.stdout)["scanner_runs"]):
                raise ValueError("Standalone external entry-point plugin discovery failed")
        mcp_tools = asyncio.run(verify_mcp(executable, root, project, env))
        if args.fix_verify:
            script = Path(__file__).with_name('fix_verify_acceptance.py').resolve()
            evidence = args.archive.resolve().with_name(args.archive.name + '.fix-verify.json')
            run([sys.executable, str(script), '--executable', str(executable), '--output', str(evidence)],
                cwd=root, env=dict(env, SECURITY_RUNTIME_OFFLINE='1'), timeout=180)
        if args.remediation:
            script = Path(__file__).with_name('remediation_acceptance.py').resolve()
            evidence = args.archive.resolve().with_name(args.archive.name + '.remediation.json')
            run([sys.executable, str(script), '--runtime', str(executable), '--output', str(evidence)],
                cwd=root, env=dict(env, SECURITY_RUNTIME_OFFLINE='1'), timeout=180)
            restart_evidence = args.archive.resolve().with_name(args.archive.name + '.confirmation-restart.json')
            run([sys.executable, str(script), '--runtime', str(executable), '--cross-turn-only',
                 '--output', str(restart_evidence)],
                cwd=root, env=dict(env, SECURITY_RUNTIME_OFFLINE='1'), timeout=180)
            # Existing artifact gate only: no new CI workflow/enterprise policy.
            # Unsupported isolation yields explicit Pending, never functional PASS.
            functional_script = Path(__file__).with_name('functional_acceptance.py').resolve()
            functional_evidence = args.archive.resolve().with_name(args.archive.name + '.functional.json')
            run([sys.executable,str(functional_script),'--runtime',str(executable),'--output',str(functional_evidence)],
                cwd=root,env=dict(env,SECURITY_RUNTIME_OFFLINE='1'),timeout=480)
        if args.hooks:
            script = Path(__file__).with_name('hook_acceptance.py').resolve()
            evidence = args.archive.resolve().with_name(args.archive.name + '.hooks.json')
            run([sys.executable, str(script), '--executable', str(executable), '--output', str(evidence)],
                cwd=root, env=dict(env, SECURITY_RUNTIME_OFFLINE='1'), timeout=180)
        if args.codex_integration:
            script = Path(__file__).with_name('codex_integration_acceptance.py').resolve()
            evidence = args.archive.resolve().with_name(args.archive.name + '.codex-integration.json')
            run([sys.executable, str(script), '--runtime', str(executable), '--output', str(evidence)],
                cwd=root, env=dict(env, SECURITY_RUNTIME_OFFLINE='1'), timeout=480)
        record = {"version": __version__, "source_commit": metadata["source_commit"], "platform": "-".join(platform_key()),
                  "archive_sha256": hashlib.sha256(args.archive.read_bytes()).hexdigest(),
                  "smoke": True, "managed_engines": args.full, "mcp_tools": mcp_tools,
                  "plugin_discovery": args.full, "release_scanner_runs": all_engines if args.full else []}
        record['osv_offline_fallback']=args.osv_fallback
        record['fix_verify_offline_synthetic'] = args.fix_verify
        record['hooks_offline_synthetic'] = args.hooks
        record['remediation_offline_synthetic'] = args.remediation
        record['codex_integration_offline_synthetic'] = args.codex_integration
        record['doctor_contract'] = doctors
        record['global_semantic_ownership'] = global_ownership
        record['managed_semgrep_reuse'] = args.full
        record['large_binary_document_exclusion'] = True
        record['oversized_source_typed_failure'] = True
        record['scan_coverage'] = {'quick': payload['coverage'], 'release': release_payload['coverage']} if args.full else {}
        args.archive.with_name(args.archive.name + ".verification.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        print(f"Artifact verified: {args.archive.name}; full={args.full}")


if __name__ == "__main__":
    main()
