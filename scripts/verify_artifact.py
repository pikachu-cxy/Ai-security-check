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
                    # Explicit mock host analysis, real frozen Runtime validation.
                    value={'finding_id':packet['finding_id'],'context_hash':packet['context_hash'],
                        'verdict':'NEEDS_REVIEW','confidence':'LOW','exploitability':'UNKNOWN',
                        'reason':'Synthetic standalone host analysis; context remains unknown.','attack_path':'',
                        'evidence_refs':[{'file':packet['file'],'start_line':packet['line']['start'],'end_line':packet['line']['end'],'claim':'Scanner candidate'}],
                        'preconditions_met':[],'preconditions_unknown':['Reachability'],'recommended_action':'Review'}
                    accepted=await client.call_tool('submit_triage',{'scan_id':payload['scan_id'],'results':[value],'triage_session':data['triage_session']})
                    if accepted.isError: raise ValueError('Standalone submit_triage failed')
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
            for member in package.getmembers():
                target = (root / member.name).resolve()
                if not target.is_relative_to(root.resolve()) or member.issym() or member.islnk():
                    raise ValueError("Unsafe archive member")
            package.extractall(root)


def run(command: list[str], *, cwd: Path, env: dict[str, str], timeout: int = 60) -> subprocess.CompletedProcess:
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True, encoding="utf-8", timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{command[1:]} failed ({result.returncode}): {result.stderr[-1000:]} {result.stdout[-1000:]}")
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("--full", action="store_true", help="Prepare real managed engines and run a real sample scan")
    parser.add_argument("--osv-fallback", action="store_true", help="Also exercise actual offline OSV CLI/MCP fallback using a synthetic inventory")
    parser.add_argument('--fix-verify', action='store_true', help='Also exercise actual offline synthetic Java task fix/verify via native MCP')
    parser.add_argument("--data-dir", type=Path, help="Retain managed engine cache between local verification attempts")
    args = parser.parse_args()
    if args.osv_fallback and not args.full:
        parser.error('--osv-fallback requires --full')
    if args.fix_verify and not args.full:
        parser.error('--fix-verify requires --full for local managed Semgrep availability')
    with tempfile.TemporaryDirectory(prefix="ai-security-release-") as temporary:
        root = Path(temporary)
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
        env = dict(os.environ, SECURITY_RUNTIME_DATA_DIR=str(data), SECURITY_RUNTIME_STATE_DIR=str(root / "state"))
        for name in ("SECURITY_RUNTIME_SEMGREP_PATH", "SECURITY_RUNTIME_GITLEAKS_PATH", "SECURITY_RUNTIME_TRIVY_PATH", "SECURITY_RUNTIME_OSV_SCANNER_PATH",
                     "SECURITY_RUNTIME_CONFIG", "SECURITY_RUNTIME_WORKSPACE", "SECURITY_RUNTIME_PLUGIN_DIR",
                     "SECURITY_RUNTIME_TRIVY_CACHE_DIR", "TRIVY_CACHE_DIR"):
            env.pop(name, None)
        git = shutil.which("git")
        if git is None:
            raise ValueError("Git is required by the artifact verification sample")
        system = Path(os.environ.get("SystemRoot", "C:/Windows"))
        platform_paths = [system / "System32", system] if os.name == "nt" else [Path("/usr/bin"), Path("/bin")]
        env["PATH"] = os.pathsep.join(map(str, [bundle, Path(git).parent, *platform_paths]))
        env["SECURITY_RUNTIME_PLUGIN_DIR"] = str(root / "plugins")
        env["SECURITY_RUNTIME_OFFLINE"] = "0" if args.full else "1"
        version = run([str(executable), "--version"], cwd=root, env=env).stdout.strip()
        if version != f"AI Security Runtime {__version__}":
            raise ValueError(f"Unexpected version: {version}")
        run([str(executable), "--help"], cwd=root, env=env)
        no_project = subprocess.run([str(executable), "doctor"], cwd=root, env=env, capture_output=True, text=True, encoding="utf-8", timeout=30)
        if "No project detected" not in no_project.stdout + no_project.stderr:
            raise ValueError("Standalone doctor did not report the missing project")
        project = root / "project"
        project.mkdir()
        run(["git", "init", "-q", str(project)], cwd=root, env=env)
        run([str(executable), "doctor", "--path", str(project)], cwd=root, env=env)
        run([str(executable), "licenses", "--check-distribution"], cwd=root, env=env)
        if args.full:
            for tool in ("semgrep", "gitleaks", "trivy"):
                print(f"Preparing managed {tool}", flush=True)
                run([str(executable), "tools", "install", tool], cwd=project, env=env, timeout=1200)
                parent = data / ("engines" if tool == "semgrep" else "tools") / tool
                if not list(parent.glob("*/metadata.json")):
                    raise ValueError(f"{tool} was not installed as a managed engine")
            (project / "app.py").write_text("import os\nos.system(input())\n", encoding="utf-8")
            (project / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
            result = subprocess.run([str(executable), "scan", "--mode", "quick", "--path", str(project), "--json"],
                                    cwd=project, env=env, capture_output=True, text=True, encoding="utf-8", timeout=1200)
            if result.returncode not in (0, 1):
                raise RuntimeError(f"Sample scan failed: {result.stderr[-1000:]}")
            payload = json.loads(result.stdout)
            if not any("command-injection" in str(item.get("technical_details", {}).get("rule_id", ""))
                       for item in payload.get("findings", [])):
                raise ValueError("First-party scanner finding missing")
            statuses = {item["scanner"]: item["status"] for item in payload["scanner_runs"]}
            if statuses != {"semgrep": "SUCCESS", "gitleaks": "SUCCESS", "trivy-vuln": "NOT_APPLICABLE", "trivy-misconfig": "NOT_APPLICABLE"}:
                raise ValueError("Quick sample scan violated its scope: " + json.dumps(payload["scanner_runs"]))
            release_scan = subprocess.run([str(executable), "scan", "--mode", "release", "--path", str(project), "--json"],
                                          cwd=project, env=env, capture_output=True, text=True, encoding="utf-8", timeout=1200)
            if release_scan.returncode not in (0, 1):
                raise RuntimeError(f"Release sample scan failed: {release_scan.stderr[-1000:]}")
            all_engines = json.loads(release_scan.stdout)["scanner_runs"]
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
        record = {"version": __version__, "source_commit": metadata["source_commit"], "platform": "-".join(platform_key()),
                  "archive_sha256": hashlib.sha256(args.archive.read_bytes()).hexdigest(),
                  "smoke": True, "managed_engines": args.full, "mcp_tools": mcp_tools,
                  "plugin_discovery": args.full, "release_scanner_runs": all_engines if args.full else []}
        record['osv_offline_fallback']=args.osv_fallback
        record['fix_verify_offline_synthetic'] = args.fix_verify
        args.archive.with_name(args.archive.name + ".verification.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        print(f"Artifact verified: {args.archive.name}; full={args.full}")


if __name__ == "__main__":
    main()
