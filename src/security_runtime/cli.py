from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tomllib
from pathlib import Path

from .capabilities import Capability
from .diagnostics import format_diagnostic, sanitize
from .engines import BUILTIN_ENGINES, ON_DEMAND_ENGINES
from .licensing import LicenseAction, LicensePolicy, Permission
from .git import GitError, GitService
from .logging_utils import configure_logging
from .risk import MESSAGES
from .runtime import SecurityRuntime
from .scanners import ScannerRegistry
from .explicit_scan import ExplicitScanBusy, cancelled_scan
from .progress import ScanCancelled
from .target import TargetDetector, DiscoveryLimitError
from .models import TargetProfile
from .toolchain import ToolManager, ToolStatus, VERSIONS
from .tools_info import installation_help
from .workspace import WorkspaceError, WorkspaceResolver
from .integrations import IntegrationRegistry, IntegrationStatusCode
from .integration_state import DogfoodEvent, IntegrationStateStore
from .mcp_config import copy_to_clipboard, json_config, resolve_runtime_command, toml_config
from ._version import __version__


def doctor(path: Path | None = None, *, json_output: bool = False, verbose: bool = False) -> int:
    report = {"runtime": {"git_available": bool(shutil.which("git")), "scanners": []}, "workspace": None,
              "capabilities": {}, "scanner_plan": {"available": [], "unavailable": []}, "database": "MISSING",
              "status": "unavailable", "message": ""}
    try:
        workspace = WorkspaceResolver().resolve(path, allow_non_git_explicit=True, allow_non_git_source=True)
        report["profile"] = "READY"
        try:
            files = GitService(workspace.path).changed_files("release") if workspace.is_git else None
            profile = TargetDetector().detect(workspace.path, files, select_scan_targets=True)
        except DiscoveryLimitError:
            profile = TargetProfile(str(workspace.path))
            report["profile"] = "LIMITED"
            report["profile_warning"] = ("Project profiling was limited because automatic discovery exceeded configured limits. "
                                         "Scanning can still use Git-scoped files.")
        project = workspace.path.name
        manifest = workspace.path / "pyproject.toml"
        try:
            if manifest.is_file() and manifest.stat().st_size <= 1_000_000:
                project = tomllib.loads(manifest.read_text(encoding="utf-8")).get("project", {}).get("name", project)
        except (OSError, ValueError, tomllib.TOMLDecodeError):
            pass
        report["workspace"] = {"path": str(workspace.path), "git": workspace.is_git, "languages": profile.languages, "frameworks": profile.frameworks, "project": project}
        integrations = IntegrationRegistry()
        integration_statuses = [adapter.status(workspace.path) for adapter in integrations.native()]
        report["integrations"] = {state.integration_id: {"status": state.status,
            "details": state.details} for state in integration_statuses}
        report["integrations"]["generic-mcp"] = {"status": "AVAILABLE", "details": {"scope": "PROJECT"}}
        manager = ToolManager()
        registry = ScannerRegistry(tool_manager=manager)
        resolved = manager.statuses()
        report["database"] = manager.database_status()
        report["trivy_data"] = manager.trivy_data_statuses()
        scanners = []
        for adapter in registry.adapters:
            engine = getattr(adapter, "engine_id", "") or adapter.scanner_id
            if engine not in resolved:
                continue
            tool = resolved[engine]
            scanners.append({"name": adapter.name, "engine": engine, "status": tool.status,
                "available": tool.status == ToolStatus.READY, "version": tool.version,
                "source": tool.source, "path": tool.path, "install": installation_help(engine)})
        report["optional_providers"] = [{"name": name, "role": "FALLBACK", "status": "ON_DEMAND",
            "engine_status": tool.status, "version": tool.version, "path": tool.path,
            "available": tool.status == ToolStatus.READY} for name,tool in resolved.items() if name in ON_DEMAND_ENGINES]
        report["runtime"]["scanners"] = scanners
        report["scanner_plan"]["available"] = [item["name"] for item in scanners if item["available"]]
        report["scanner_plan"]["unavailable"] = [item["name"] for item in scanners if not item["available"]]
        labels = {Capability.CODE_SAST: "Code Security", Capability.SECRET_SCAN: "Secret Security",
                  Capability.DEPENDENCY_VULN: "Dependency Security", Capability.IAC_MISCONFIG: "IaC Security"}
        for capability, label in labels.items():
            supporting = [adapter for adapter in registry.adapters if capability in adapter.capabilities]
            ready = any(item["available"] and (item["name"] != "trivy-vuln" or report["database"] == ToolStatus.READY)
                        for item in scanners if any(adapter.name == item["name"] for adapter in supporting))
            report["capabilities"][label] = "READY" if ready else "MISSING"
        report["status"] = "ready" if all(value == "READY" for value in report["capabilities"].values()) else "limited"
        report["message"] = "Local prerequisites checked. READY does not guarantee a project scan succeeds; remote repositories may fail."
        if not workspace.is_git:
            report["message"] += " Source directory supports release scans; quick/feature/staged require Git."
        code = 0
    except (WorkspaceError, ValueError, OSError) as exc:
        report["message"] = str(exc)
        code = 2
    if json_output:
        print(json.dumps(report, ensure_ascii=True))
        return code
    print("AI Security Runtime")
    if report["workspace"]:
        workspace_info = report["workspace"]
        print(f"\nWorkspace\n{workspace_info['path']}")
        print("Workspace: READY")
        print("Git: " + ("READY" if workspace_info["git"] else "MISSING"))
        print("Languages: " + (", ".join(workspace_info["languages"]) or "Unknown"))
        print(f"Profile: {report['profile']}")
        if report.get("profile_warning"):
            print("Warning: " + report["profile_warning"])
        print("\nSecurity capabilities")
        for label, state in report["capabilities"].items():
            print(f"{label:<22} {state}")
        print("\nIntegrations")
        for name, state in report["integrations"].items():
            print(f"{name.title():<14} {state['status']}")
            if verbose:
                for key, value in state["details"].items():
                    print(f"  {key}: {value or '-'}")
        if verbose:
            print(f"\nRuntime\nGit: {'READY' if report['runtime']['git_available'] else 'MISSING'}")
            for item in report["runtime"]["scanners"]:
                descriptor = BUILTIN_ENGINES.get(item["engine"])
                print(f"\n{item['name'].title()}\nStatus: {item['status']}\nVersion: {item['version'] or (descriptor.version if descriptor else '')}")
                print(f"Source: {item['source'] or 'NONE'}\nPath: {item['path'] or '-'}")
                if item["engine"] == "trivy":
                    print(f"Database: {report['database']}")
                    for name, state in report["trivy_data"].items():
                        print(f"{name}: {state}")
                    if report["database"] == ToolStatus.READY:
                        metadata = manager.trivy_cache_dir() / "db" / "metadata.json"
                        try:
                            updated = json.loads(metadata.read_text(encoding="utf-8")).get("UpdatedAt", "")
                        except (OSError, ValueError):
                            updated = ""
                        print(f"Updated: {updated or '-'}")
                if not item["available"]:
                    print(f"Install: {item['install']}")
    if verbose:
        for item in report.get("optional_providers", []):
            print(f"\n{item['name']}: ON_DEMAND / FALLBACK; engine: {item['engine_status']}")
    print("\n" + report["message"])
    return code


def render(result, *, verbose=False) -> str:
    from .human import render_scan
    return render_scan(result, verbose=verbose)


def main(argv: list[str] | None = None, *, installation_progress=None) -> int:
    # Windows redirected streams may otherwise use cp1252/cp936. MCP JSON and
    # CLI status symbols are UTF-8 on every delivery format.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(prog="security-check")
    parser.add_argument("--version", action="version", version=f"AI Security Runtime {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    # Optional observer: removing it must not remove any product commands.
    try:
        from .context_cost_cli import register as register_context_usage
        register_context_usage(sub)
    except Exception:
        pass
    info_parser=sub.add_parser('runtime-info',help='Read version/capabilities and host reconnect guidance without scanning')
    info_parser.add_argument('--json',action='store_true')
    skill_parser=sub.add_parser('review-skill',help='Install/status/upgrade/repair/remove the companion user Security Review Skill')
    skill_parser.add_argument('action',choices=['install','status','upgrade','repair','remove'])
    skill_parser.add_argument('--skills-dir',type=Path,help='Explicit user Skill directory, for isolated profiles')
    skill_parser.add_argument('--json',action='store_true')
    upgrade_parser = sub.add_parser('upgrade', help='Read-only diagnosis/plan, explicit bounded apply and CAS recovery')
    upgrade_parser.add_argument('action', choices=['diagnose', 'plan', 'apply', 'recover'])
    upgrade_parser.add_argument('--path', type=Path)
    upgrade_parser.add_argument('--skills-dir', type=Path)
    upgrade_parser.add_argument('--plan', type=Path)
    upgrade_parser.add_argument('--output', type=Path)
    upgrade_parser.add_argument('--approve-user-managed', action='store_true')
    upgrade_parser.add_argument('--dev', action='store_true')
    upgrade_parser.add_argument('--probe', action='store_true', help='Probe only the current product launcher, not unknown config commands')
    upgrade_parser.add_argument('--json', action='store_true')
    trial_parser = sub.add_parser('trial', help='Create/status/run an explicit isolated local trial profile')
    trial_parser.add_argument('action', choices=['create', 'status', 'run'])
    trial_parser.add_argument('--root', required=True, type=Path)
    trial_parser.add_argument('--executable', type=Path)
    trial_parser.add_argument('--json', action='store_true')
    delivery_parser = sub.add_parser('delivery', help='Activate/status/rollback a verified frozen package behind a stable launcher')
    delivery_parser.add_argument('action', choices=['activate', 'status', 'rollback', 'cleanup', 'make-update'])
    delivery_parser.add_argument('--root', type=Path)
    delivery_parser.add_argument('--bundle', type=Path)
    delivery_parser.add_argument('--base', type=Path)
    delivery_parser.add_argument('--output', type=Path)
    delivery_parser.add_argument('--json', action='store_true')
    remediation_parser = sub.add_parser('remediation', help='User-level consent/reporting preferences; fixes require explicit approval')
    remediation_parser.add_argument('action', choices=['status', 'configure'])
    remediation_parser.add_argument('--mode', choices=['smart_auto', 'ask_before_fix', 'report_only'],
                                    help='smart_auto is a legacy alias for ask_before_fix; no mode grants unconfirmed edits')
    summary_parser=sub.add_parser('summary',help='Read developer tasks for this workspace; never scans or invokes AI')
    summary_parser.add_argument('--path')
    summary_parser.add_argument('--scan')
    summary_parser.add_argument('--details',action='store_true',help='Show every task, identity and accepted AI review')
    summary_parser.add_argument('--json',action='store_true')
    ai_parser=sub.add_parser('ai',help='Configure user BYOK; AI is disabled during scan')
    ai_sub=ai_parser.add_subparsers(dest='ai_action',required=True)
    ai_config=ai_sub.add_parser('configure')
    ai_config.add_argument('--provider',choices=['openai-compatible'],default='openai-compatible')
    ai_config.add_argument('--base-url',required=True)
    ai_config.add_argument('--model',required=True)
    ai_config.add_argument('--api-key-env',default='SECURITY_RUNTIME_AI_KEY')
    triage_parser=sub.add_parser('triage',help='Validate stored candidates; keeps raw findings')
    triage_select=triage_parser.add_mutually_exclusive_group(required=True)
    triage_select.add_argument('--latest',action='store_true')
    triage_select.add_argument('--scan')
    triage_parser.add_argument('--path')
    triage_parser.add_argument('--provider',choices=['configured'])
    triage_parser.add_argument('--allow-external-code-context',action='store_true',help='Authorize bounded original code context, including embedded credentials, to configured external LLM')
    triage_parser.add_argument('--category',choices=['code','secret','dependency'],action='append')
    triage_parser.add_argument('--severity',choices=['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'],action='append')
    triage_parser.add_argument('--limit',type=int,default=20)
    triage_parser.add_argument('--json',action='store_true')
    triage_parser.add_argument('--raw',action='store_true')
    triage_parser.add_argument('--prepare',action='store_true',help='Export agent-native evidence and schema as JSON')
    triage_parser.add_argument('--no-progress',action='store_true')
    doctor_parser = sub.add_parser("doctor", help="Check Runtime and project readiness")
    doctor_parser.add_argument("--path")
    doctor_parser.add_argument("--json", action="store_true")
    doctor_parser.add_argument("--verbose", action="store_true")
    doctor_parser.add_argument('--global', dest='global_scope', action='store_true', help='Check global Codex integration, including when --path is supplied')
    doctor_parser.add_argument('--project', action='store_true', help='Use the legacy scanner/project doctor')
    scan_parser = sub.add_parser("scan", help="Scan code changes or the project")
    scan_parser.add_argument("--path")
    scan_parser.add_argument("--mode", choices=["quick", "feature", "release"], default="quick")
    scan_parser.add_argument("--json", action="store_true")
    scan_parser.add_argument("--no-progress", action="store_true", help="不显示进度，仍输出正式结果和错误")
    scan_parser.add_argument("--verbose", action="store_true", help="显示本次不适用的检查")
    scan_parser.add_argument("--staged", action="store_true", help=argparse.SUPPRESS)
    scan_parser.add_argument("--rules", help="Local user-provided Semgrep rule directory")
    scan_parser.add_argument('--gate', choices=['strict', 'report'], help='Git gate: 0 allowed, 1 policy blocked, 2 incomplete (strict)')
    mcp_parser = sub.add_parser("mcp", help="Run or configure the MCP server")
    mcp_sub = mcp_parser.add_subparsers(dest="mcp_action")
    config_parser = mcp_sub.add_parser("config")
    config_parser.add_argument("--path")
    config_format = config_parser.add_mutually_exclusive_group()
    config_format.add_argument("--json", action="store_true")
    config_format.add_argument("--toml", action="store_true")
    config_parser.add_argument("--copy", action="store_true")
    config_parser.add_argument("--help-client", action="store_true")
    install_parser = sub.add_parser('install', help='Install personal Runtime, host global connection and professional Skill together')
    install_parser.add_argument('integration', nargs='?', choices=['codex', 'cursor'], default='codex')
    install_parser.add_argument('--bundle', type=Path, help='Explicit local standalone bundle; portable EXE defaults to its own bundle')
    install_parser.add_argument('--update', type=Path, help='Local verified delta ZIP matching the active base build')
    install_parser.add_argument('--root', type=Path, help='Stable personal program directory; defaults to user local application data')
    install_parser.add_argument('--path', help='Optional project conflict check; never a project installation')
    install_parser.add_argument('--dev', action='store_true', help='Explicit source-development opt-in; not a user installation')
    install_parser.add_argument('--offline', action='store_true', help='Verify existing components and data without downloading')
    install_parser.add_argument('--json', action='store_true')
    background_parser = sub.add_parser('preparation', help='View automatic background preparation or retry it without reinstalling')
    background_parser.add_argument('action', choices=['status', 'watch', 'retry'], default='status', nargs='?')
    background_parser.add_argument('--json', action='store_true')
    worker_parser = sub.add_parser('preparation-worker', help=argparse.SUPPRESS)
    worker_parser.add_argument('--job', required=True)
    worker_parser.add_argument('--ticket', required=True)
    task_worker = sub.add_parser('task-closeout-worker', help=argparse.SUPPRESS)
    task_worker.add_argument('--workspace', required=True)
    task_worker.add_argument('--hooks', required=True)
    task_worker.add_argument('--ticket', required=True)
    scan_worker = sub.add_parser('scan-job-worker', help=argparse.SUPPRESS)
    scan_worker.add_argument('--workspace', required=True)
    scan_worker.add_argument('--hooks', required=True)
    scan_worker.add_argument('--job-ref', required=True)
    scan_worker.add_argument('--ticket', required=True)
    epoch_worker = sub.add_parser('product-epoch-worker', help=argparse.SUPPRESS)
    epoch_worker.add_argument('--workspace', required=True)
    epoch_worker.add_argument('--hooks', required=True)
    epoch_worker.add_argument('--ticket', required=True)
    dispatcher = sub.add_parser('task-closeout-dispatcher', help=argparse.SUPPRESS)
    dispatcher.add_argument('--once', action='store_true')
    startup = sub.add_parser('task-dispatcher-startup', help='Manage automatic recovery at user login')
    startup.add_argument('action', choices=['status', 'install', 'remove'], default='status', nargs='?')
    for preparation_command in ('prepare-scanners', 'prepare-installation'):
        preparation_parser = sub.add_parser(preparation_command,
            help='Prepare scanners and public vulnerability data independently of installation' if preparation_command == 'prepare-scanners' else argparse.SUPPRESS)
        preparation_parser.add_argument('--json', action='store_true')
        preparation_parser.add_argument('--offline', action='store_true')
        preparation_parser.add_argument('--status', action='store_true', help='Read-only check of existing tools and data; no downloads')
        preparation_parser.add_argument('--timeout', type=int, default=300, help='Initial wait in seconds; observed transfer progress may extend it (1-1800)')
        preparation_parser.add_argument('--max-wait', type=int, default=1800, help='Absolute shared preparation ceiling in seconds; at least --timeout (1-1800)')
        preparation_parser.add_argument('--fixed-timeout', action='store_true', help='Keep --timeout as a fixed deadline without automatic continuation')
        preparation_parser.add_argument('--retries', type=int, choices=(0, 1), default=0, help='Explicit extra download attempts; all attempts share the budget')
        preparation_parser.add_argument('--idle-timeout', type=int, default=30, help='Stop database download after this many seconds without byte progress (1-300)')
    setup_parser = sub.add_parser("setup", help="Configure Codex globally and install its companion Skill together")
    setup_parser.add_argument("integration", nargs="?", choices=["codex", "cursor", "workbuddy"])
    setup_parser.add_argument("--path")
    setup_parser.add_argument('--json', action='store_true')
    setup_parser.add_argument("--verbose", action="store_true")
    setup_parser.add_argument('--scope', choices=['global', 'project'], help='Default Codex setup is global, including --path; project scope is explicit legacy/development opt-in')
    setup_parser.add_argument('--dev', action='store_true', help='Explicitly acknowledge a DEV launcher; does not install source paths')
    cursor_hook_parser = sub.add_parser('cursor-hook', help=argparse.SUPPRESS)
    cursor_hook_parser.add_argument('--automatic', action='store_true', help=argparse.SUPPRESS)
    for action in ('status', 'repair', 'uninstall'):
        global_parser = sub.add_parser(action, help='Manage the owned user-level Codex installation')
        global_parser.add_argument('--path', help='Inspect or migrate this workspace only')
        global_parser.add_argument('--json', action='store_true')
        global_parser.add_argument('--dev', action='store_true')
        if action == 'repair':
            global_parser.add_argument('--approve-user-managed', action='store_true',
                help='Explicitly approve backup/removal of the diagnosed same-name MCP subtree; never approve unknown Hooks or invalid ownership')
    lifecycle_parser = sub.add_parser('integration', help='Manage owned project Codex connection and readiness')
    lifecycle_parser.add_argument('action', choices=['status', 'repair', 'remove'])
    lifecycle_parser.add_argument('integration', choices=['codex', 'cursor'])
    lifecycle_parser.add_argument('--scope', choices=['global', 'project'], default='project')
    lifecycle_parser.add_argument('--path')
    lifecycle_parser.add_argument('--json', action='store_true')
    integrations_parser = sub.add_parser("integrations", help="Inspect AI coding integrations")
    integrations_parser.add_argument("--path")
    integrations_parser.add_argument("--verbose", action="store_true")
    integrations_sub = integrations_parser.add_subparsers(dest="integrations_action")
    repair_parser = integrations_sub.add_parser("repair")
    repair_parser.add_argument("--path")
    remove_parser = integrations_sub.add_parser("remove")
    remove_parser.add_argument("integration", choices=["cursor", "workbuddy"])
    remove_parser.add_argument("--path")
    stats_parser = sub.add_parser("stats")
    stats_parser.add_argument("--days", type=int, default=7)
    license_parser = sub.add_parser("licenses")
    license_parser.add_argument("--check-distribution", action="store_true")
    hooks_parser = sub.add_parser("hooks", help="Manage AI host lifecycle Hooks and diagnostics")
    hooks_parser.add_argument("action", choices=["install", "status", "repair", "remove", "generate-mcp-poc", "recent", "repair-diagnostics"])
    hooks_parser.add_argument("hook", nargs="?", choices=["pre-commit", "codex", "cursor", "kiro", "workbuddy", "codebuddy", "qoder"],
        metavar="{codex,cursor,kiro,workbuddy,codebuddy,qoder}")
    hooks_parser.add_argument("--path")
    hooks_parser.add_argument("--json", action="store_true")
    hooks_parser.add_argument('--gate', choices=['strict', 'report'], default='strict')
    hooks_parser.add_argument("--limit", type=int, default=16, help="Recent diagnostics count (1–32)")
    hooks_parser.add_argument("--unbound", action="store_true", help="Explicitly query unattributed Hook diagnostics")
    hook_parser = sub.add_parser('hook', help='Advisory local lifecycle quick check')
    hook_parser.add_argument('event', choices=['session-start','file-changed','agent-stop','host-event'])
    hook_parser.add_argument('--path')
    hook_parser.add_argument('--host', choices=['codex','cursor','kiro','workbuddy','codebuddy','qoder','generic'], default='generic')
    hook_parser.add_argument('--session-id')
    hook_parser.add_argument('--json',action='store_true')
    hook_parser.add_argument('--stdin',action='store_true')
    hook_parser.add_argument('--adapter-id',choices=['ai-security-runtime-hook-v1'],help=argparse.SUPPRESS)
    tools_parser = sub.add_parser("tools", help="Manage security engines")
    tools_sub = tools_parser.add_subparsers(dest="tools_action", required=True)
    tool_status_parser = tools_sub.add_parser("status")
    tool_status_parser.add_argument('--json', action='store_true')
    repair_component_parser = tools_sub.add_parser('repair', help='Back up and rebuild confirmed corrupt Semgrep settings; no download or scan')
    repair_component_parser.add_argument('tool', choices=['semgrep'])
    repair_component_parser.add_argument('--json', action='store_true')
    install_parser = tools_sub.add_parser("install")
    install_parser.add_argument("tool", nargs="?", choices=tuple(VERSIONS))
    install_parser.add_argument("--all", action="store_true")
    install_parser.add_argument('--reinstall', action='store_true', help='Explicitly replace one broken managed/system component; never repair user settings by downloading')
    trial_arguments = []
    parsed_argv = list(sys.argv[1:] if argv is None else argv)
    if parsed_argv[:1] == ['trial'] and '--' in parsed_argv:
        split = parsed_argv.index('--')
        trial_arguments = parsed_argv[split + 1:]
        parsed_argv = parsed_argv[:split]
    args = parser.parse_args(parsed_argv)
    if args.command == 'cursor-hook':
        from .cursor_hook import main as cursor_hook_main
        return cursor_hook_main(automatic=args.automatic)
    if ((args.command == 'setup' and args.integration == 'cursor' and args.scope == 'global')
            or (args.command == 'integration' and args.integration == 'cursor' and args.scope == 'global')):
        from .cursor_connector import CursorConnectorInstallation, setup_personal_cursor, cursor_reason
        try:
            integration = CursorConnectorInstallation(allow_dev=getattr(args, 'dev', False))
            data = (setup_personal_cursor(integration, args.path) if args.command == 'setup'
                    else integration.execute(args.action, args.path))
        except (ValueError, OSError, KeyError, TypeError) as exc:
            data = dict(integration='cursor', scope='GLOBAL', overall='BROKEN',
                        diagnostics=[cursor_reason(exc)])
        print(json.dumps(data, ensure_ascii=True) if args.json else 'AI Security Runtime / Cursor\n'+data['overall'])
        return 0 if data['overall'] in {'CONFIGURED', 'REMOVED'} else 2
    try:
        configure_logging(mcp=args.command == "mcp")
        if args.command == 'context-usage':
            from .context_cost_cli import execute as execute_context_usage
            return execute_context_usage(args)
        if args.command == 'preparation-worker':
            from .background_preparation import run_worker
            return run_worker(args.job, args.ticket)
        if args.command == 'task-closeout-worker':
            from .task_closeout_worker import run_worker
            return run_worker(args.workspace, args.hooks, args.ticket)
        if args.command == 'scan-job-worker':
            from .scan_jobs import run_worker
            return run_worker(args.workspace, args.hooks, args.job_ref, args.ticket)
        if args.command == 'product-epoch-worker':
            from .product_epoch_worker import run_worker
            return run_worker(args.workspace, args.hooks, args.ticket)
        if args.command == 'task-closeout-dispatcher':
            from .task_dispatcher import run
            return run(once=args.once)
        if args.command == 'task-dispatcher-startup':
            from .task_dispatcher import autostart
            print(json.dumps(autostart(args.action)))
            return 0
        if args.command == 'preparation':
            from .background_preparation import read_preparation_status, start_background_preparation, watch_preparation, preparation_message
            data = (start_background_preparation() if args.action == 'retry' else
                    watch_preparation() if args.action == 'watch' else read_preparation_status())
            print(json.dumps(data, ensure_ascii=True) if args.json else preparation_message(data))
            return 0 if data.get('ready') or data['status'] in {'QUEUED', 'PREPARING', 'RESUMING'} else 2
        if args.command in {'prepare-installation', 'prepare-scanners'}:
            from .install_readiness import prepare_installation_readiness
            from .install_progress import child_preparation_progress, InstallationProgress
            if not 1 <= args.timeout <= args.max_wait <= 1800 or not 1 <= args.idle_timeout <= 300:
                parser.error('Preparation timeout and max wait must be 1-1800, max wait at least timeout, and idle timeout 1-300 seconds')
            offline = args.offline or args.status or os.getenv('SECURITY_RUNTIME_OFFLINE') == '1'
            adaptive = args.command == 'prepare-scanners' and not args.fixed_timeout and not offline
            kwargs = dict(offline=offline, timeout_seconds=args.timeout, retries=args.retries, idle_seconds=args.idle_timeout,
                adaptive=adaptive, max_wait_seconds=args.max_wait if adaptive else args.timeout)
            if args.status:
                # A read-only query must not say it is downloading/updating.
                data = prepare_installation_readiness(**kwargs)
            elif os.getenv('SECURITY_RUNTIME_INSTALL_PROGRESS') == '1':
                data = prepare_installation_readiness(progress=child_preparation_progress, **kwargs)
            else:
                with InstallationProgress(preparation=True, adaptive=adaptive,
                        initial_seconds=args.timeout, max_wait_seconds=args.max_wait if adaptive else args.timeout) as progress:
                    data = prepare_installation_readiness(progress=progress, **kwargs)
                    progress.finish(data['ready'])
            if args.command == 'prepare-installation' and isinstance(data.get('preparation'), dict):
                # Old installed parents require the exact legacy receipt fields.
                # Public prepare-scanners retains the richer source trail.
                base = {'budget_seconds', 'elapsed_ms', 'max_attempts', 'attempts', 'error_code', 'source'}
                data['preparation'] = {key: value for key, value in data['preparation'].items() if key in base}
            if args.command == 'prepare-installation':
                # Preserve the legacy private child receipt for old installers.
                for component in data['tools'].values():
                    component.pop('diagnostic', None)
                data['failures'] = [dict(stage=item['stage'], component=item['component'],
                    exception_type=item.get('exception_type', 'OtherException')) for item in data['failures']]
            else:
                from .component_health import component_feedback
                health = component_feedback(data['tools'])
                # Keep the receipt shape stable for scripts. One-time notices
                # use stderr, while JSON contains current diagnostic state.
                if health['notify']:
                    print(health['message'], file=sys.stderr)
            print(json.dumps(data, ensure_ascii=True) if args.json else data['message'])
            return 0 if data['ready'] else 2
        if args.command == 'install':
            from .install_progress import InstallationProgress
            with installation_progress or InstallationProgress() as progress:
                from .personal_install import install_personal_codex
                from .integration_lifecycle import IntegrationDiagnostic
                try:
                    host_kwargs = {'_host': 'cursor'} if args.integration == 'cursor' else {}
                    data = install_personal_codex(bundle=args.bundle, root=args.root,
                        workspace=str(Path(args.path).absolute()) if args.path else None,
                        allow_dev=args.dev, progress=progress, update=args.update, offline=args.offline, **host_kwargs)
                except (ValueError, OSError, TypeError, RecursionError) as exc:
                    code = exc.code if isinstance(exc, IntegrationDiagnostic) else 'INSTALL_PATH_OR_STATE_INVALID'
                    data = {'integration':args.integration, 'scope':'GLOBAL', 'overall':'BROKEN', 'diagnostics':[code],
                        'installation':{'contract':'personal-install-v1', 'status':'NOT_READY',
                            'local_files_ready':False, 'scan_ready':False, 'risk_fix_authorized':False, 'restart_required':False,
                            'message':'安装未完成。请检查诊断中的包、安装目录或现有配置问题；未授权覆盖用户内容，也不能视为可扫描。'}}
                ready = data['installation'].get('local_files_ready') is True
                progress.finish(ready, scan_ready=data['installation'].get('scan_ready') is True)
            print(json.dumps(data, ensure_ascii=True) if args.json else data['installation']['message'])
            return 0 if ready else 2
        if args.command == 'delivery':
            if args.action == 'make-update':
                from .delta_delivery import make_update
                if args.base is None or args.bundle is None or args.output is None:
                    raise ValueError('DELTA_BASE_BUNDLE_OUTPUT_REQUIRED')
                print(json.dumps(make_update(args.base, args.bundle, args.output), ensure_ascii=True))
                return 0
            from .delivery import StableDelivery
            if args.root is None:
                raise ValueError('DELIVERY_ROOT_REQUIRED')
            delivery = StableDelivery(args.root)
            if args.action == 'activate':
                if args.bundle is None:
                    raise ValueError('DELIVERY_BUNDLE_REQUIRED')
                data = delivery.activate(args.bundle)
            else:
                data = delivery.rollback() if args.action == 'rollback' else delivery.cleanup() if args.action == 'cleanup' else delivery.status()
            print(json.dumps(data, ensure_ascii=True))
            return 0
        if args.command == 'trial':
            from .trial import TrialProfile
            trial = TrialProfile(args.root)
            if args.action == 'run':
                return trial.run(trial_arguments, executable=args.executable)
            print(json.dumps(trial.create() if args.action == 'create' else trial.status(), ensure_ascii=True))
            return 0
        if args.command == 'upgrade':
            from .upgrade import InstallationUpgrade
            from .global_integration import GlobalCodexIntegration
            from .review_skill import ReviewSkillManager
            from .hook_state import atomic_bytes, no_links
            manager = InstallationUpgrade(GlobalCodexIntegration(allow_dev=args.dev), ReviewSkillManager(args.skills_dir))
            if args.action == 'diagnose':
                data = manager.diagnose(args.path, probe=args.probe)
            elif args.action == 'plan':
                data = manager.plan(args.path)
                if args.output:
                    no_links(args.output)
                    if args.output.exists():
                        raise ValueError('UPGRADE_PLAN_OUTPUT_EXISTS')
                    atomic_bytes(args.output, json.dumps(data, ensure_ascii=True).encode())
            elif args.action == 'recover':
                data = manager.recover()
            else:
                if args.plan is None:
                    raise ValueError('UPGRADE_PLAN_REQUIRED')
                no_links(args.plan)
                if args.plan.stat().st_size > 1_000_000:
                    raise ValueError('UPGRADE_PLAN_INVALID')
                data = manager.apply(json.loads(args.plan.read_bytes()), approve_user_managed=args.approve_user_managed)
            print(json.dumps(data, ensure_ascii=True) if args.json else json.dumps(data, ensure_ascii=False, indent=2))
            return 0 if not data.get('blocked') else 2
        if args.command == 'hooks' and args.action == 'repair-diagnostics':
            if args.hook is not None or args.path is not None or args.unbound:
                raise ValueError('Diagnostic repair uses the fixed user diagnostic store')
            from .recent_hooks import RecentHookStore
            try:
                result = RecentHookStore().repair()
            except (OSError, ValueError, __import__('sqlite3').DatabaseError):
                result = dict(status='UNAVAILABLE', reason_code='HOOK_DIAGNOSTIC_RECOVERY_UNAVAILABLE',
                              diagnostic_only=True, security_proof=False)
                print(json.dumps(result, ensure_ascii=True) if args.json else 'Hook diagnostic recovery unavailable; original history retained.')
                return 2
            print(json.dumps(result, ensure_ascii=True) if args.json else json.dumps(result, ensure_ascii=False, indent=2))
            return 0
        if args.command == 'hooks' and args.action == 'recent':
            from .recent_hooks import RecentHookStore
            from .global_workspace import resolve_workspace
            try:
                if args.hook is not None or (args.unbound and args.path is not None):
                    raise ValueError('Invalid recent diagnostic scope')
                root = None if args.unbound else resolve_workspace(str(Path(args.path or Path.cwd()).absolute()))
                result = RecentHookStore().recent(root, limit=args.limit, unbound=args.unbound)
            except Exception:
                result = dict(status='UNAVAILABLE', reason_code='RECENT_HOOK_DIAGNOSTIC_UNAVAILABLE',
                              records=[], diagnostic_only=True, security_proof=False)
                print(json.dumps(result, ensure_ascii=True) if args.json else 'Recent Hook diagnostics unavailable; no state changed.')
                return 2
            if args.json:
                print(json.dumps(result, ensure_ascii=True))
            else:
                print('Recent Hook diagnostics: ' + result['status'] + ' (diagnostic only)')
                for row in result['records']:
                    print(f"{row['timestamp']} {row['event']} {row['last_stage']} claims={row.get('host_claim_status')} scanner={row.get('scanner_run')} id={row['diagnostic_id']}")
                print(result['note'])
            return 0
        if args.command == 'hook':
            try:
                from .hook_runtime import HookCoordinator
                if args.event == 'host-event':
                    if not args.stdin:
                        raise ValueError('Host event requires JSON stdin')
                    from .hook_adapters import run_host_event
                    data = sys.stdin.buffer.read(100_001)
                    if len(data)>100_000:
                        raise ValueError('Host payload budget exceeded')
                    output = run_host_event(json.loads(data),args.path,args.host)
                else:
                    if args.stdin:
                        raise ValueError('Use host-event for lifecycle payloads')
                    event = args.event.upper().replace('-','_')
                    output = HookCoordinator(task_audit_mode=True).handle(event,args.path,args.host,args.session_id)
                print(json.dumps(output,ensure_ascii=True) if args.json or args.event=='host-event' else
                      f"{output['status']} · coverage {output['coverage']} · new families {output['delta']['new']} · added occurrences {output['delta']['additional_occurrences']}\n{output['next_step']}")
                return 0  # Findings and scanner limitations are advisory.
            except Exception:
                # Do not echo untrusted stdin, paths or exception source text.
                print(json.dumps({'status':'FAILED','error_code':'HOOK_RUNTIME_FAILED','systemMessage':'本次安全检查未完成，暂时无法确认改动是否安全。建议检查工具状态后重新检查。'}))
                return 2
        if args.command == 'remediation':
            from .remediation_policy import RemediationConfig
            config = RemediationConfig()
            if args.action == 'configure':
                if args.mode is None:
                    raise ValueError('configure requires --mode')
                config.write(args.mode)
            elif args.mode is not None:
                raise ValueError('status does not accept --mode')
            print(json.dumps({'remediation': {'mode': config.read(), 'user_consent_required': True,
                'automatic_fix_without_user_consent': False}, 'max_auto_fix_attempts': 2}))
            return 0
        if args.command=='review-skill':
            from .review_skill import ReviewSkillManager
            data=ReviewSkillManager(args.skills_dir).execute(args.action)
            print(json.dumps(data,ensure_ascii=True) if args.json else '\n'.join([
                'AI Security Review: '+data['status'],data.get('path',''),data.get('reason','')]))
            return 2 if data['status'] in {'USER_MANAGED','USER_MODIFIED','OWNERSHIP_CONFLICT'} else 0
        if args.command=='runtime-info':
            from .guidance.host_guidance import runtime_info
            info=runtime_info()
            if os.getenv('SECURITY_RUNTIME_GLOBAL') == '1':
                from .global_mcp import global_runtime_info
                info = global_runtime_info()
            # Native stdout is UTF-8, but Windows PowerShell 5.1 can decode a
            # pipeline using its legacy console code page. ASCII escapes keep
            # JSON parseable and preserve Unicode values under either decoder.
            print(json.dumps(info,ensure_ascii=True) if args.json else '\n'.join([
                'AI Security Runtime '+info['version'], 'Capabilities: '+info['capability_contract'],
                *info['connection_recovery']]))
            return 0
        if args.command=='summary':
            from .security_summary import SecuritySummaryService
            from .human import render_security_summary
            bound=os.getenv('SECURITY_RUNTIME_WORKSPACE')
            root=args.path or bound
            if root is None:
                root=WorkspaceResolver().resolve(allow_non_git_source=True).path
            result=SecuritySummaryService().get(root,args.scan,details=args.details,bound_workspace=bound)
            print(json.dumps(result,ensure_ascii=True) if args.json else render_security_summary(result))
            return 0
        if args.command=='ai':
            from .triage_providers import AIConfig
            AIConfig(args.base_url,args.model,args.api_key_env,args.provider).save()
            print('BYOK 配置已保存，仅保存 API key 环境变量名。AI 默认关闭。')
            print('将向外部 LLM Provider 发送限定范围的原文代码上下文（包括其中的凭据），用于安全 Finding 验证。')
            print('使用 triage --provider configured --allow-external-code-context 显式授权。')
            return 0
        if args.command=='triage':
            from .triage import TriageService
            from .triage_providers import AIConfig,OpenAICompatibleProvider
            from .storage import SQLiteStore
            from .human import render_triage
            store=SQLiteStore();service=TriageService(store)
            scan=store.latest_scan(args.path) if args.latest else store.get_scan(args.scan)
            if scan is None: raise ValueError('No stored scan found')
            if args.path and Path(scan['target_profile']['path']).resolve()!=Path(args.path).resolve():
                raise ValueError('Scan does not belong to this workspace')
            selection=dict(categories=args.category,severities=args.severity,limit=args.limit)
            if args.raw:
                if args.provider or args.prepare: raise ValueError('--raw cannot invoke or prepare AI')
                print(json.dumps(scan['findings'],ensure_ascii=True,indent=2))
                return 0
            if args.provider:
                if args.prepare: raise ValueError('Choose BYOK or agent-native prepare')
                if not args.allow_external_code_context:
                    raise ValueError('将向外部 LLM Provider 发送限定范围的原文代码上下文（包括其中的凭据）。必须显式提供 --allow-external-code-context')
                provider=OpenAICompatibleProvider(AIConfig.load(),allow_external_code_context=True)
                if args.no_progress: output=service.run(scan['scan_id'],provider,**selection)
                else:
                    from .cli_progress import CLIProgressRenderer
                    with CLIProgressRenderer() as reporter: output=service.run(scan['scan_id'],provider,progress=reporter,**selection)
                print(json.dumps(output,ensure_ascii=True) if args.json else render_triage(output['view']))
                return 2 if output['failures'] or output['evidence_errors'] else 0
            if args.prepare:
                print(json.dumps(service.prepare(scan['scan_id'],**selection),ensure_ascii=True))
            else:
                view=service.view(scan['scan_id'])
                print(json.dumps(view,ensure_ascii=True) if args.json else render_triage(view))
            return 0
        if args.command == "doctor" and (args.project or (args.path is not None and not args.global_scope)):
            return doctor(Path(args.path) if args.path is not None else None, json_output=args.json, verbose=args.verbose)
        if args.command == "scan":
            registry = ScannerRegistry()
            # Adapters prepare their engines only after Runtime scope/planning.
            from .cli_progress import CLIProgressRenderer
            from .explicit_scan import run_explicit_scan
            runtime = SecurityRuntime(registry=registry)
            if args.no_progress:
                result = run_explicit_scan(runtime, args.path, mode=args.mode, staged=args.staged, rules_path=args.rules)
            else:
                with CLIProgressRenderer() as reporter:
                    result = run_explicit_scan(runtime, args.path, mode=args.mode, staged=args.staged, rules_path=args.rules, progress=reporter)
            try:
                IntegrationStateStore().event(DogfoodEvent("cli", result.target_profile.path, args.mode,
                    result.duration_ms, len(result.findings), result.coverage))
            except OSError:
                pass
            print(json.dumps(result.to_dict(), ensure_ascii=True) if args.json else render(result, verbose=args.verbose))
            if args.gate:
                from .hooks import gate_exit
                code = gate_exit(result, args.gate)
                if result.status not in {'COMPLETED', 'NO_CHANGES'}:
                    print('Git gate: scan incomplete; ' + ('commit blocked (strict).' if code else 'commit allowed without a completed security verdict (report).'), file=sys.stderr)
                return code
            return 0 if result.release_status != "BLOCKED" else 1
        if args.command == "tools":
            manager = ToolManager()
            if args.tools_action == 'repair':
                from .component_health import repair_semgrep_settings
                data = repair_semgrep_settings(manager=manager)
                print(json.dumps(data, ensure_ascii=True) if args.json else data['message'] +
                    ('\n备份：' + data['backup_path'] if data.get('backup_path') else ''))
                return 0 if data['status'] in {'REPAIRED', 'NOT_APPLICABLE'} else 2
            if args.tools_action == "status":
                from .component_health import component_feedback
                from .install_readiness import _component, CORE_TOOLS
                statuses = manager.statuses()
                tools = {name: _component(result, manager.versions[name], name)
                    for name, result in statuses.items() if name in CORE_TOOLS}
                health = component_feedback(tools, root=manager.root)
                if args.json:
                    print(json.dumps(dict(tools=tools, component_health=health,
                        vulnerability_data=manager.trivy_data_statuses()), ensure_ascii=True))
                    return 0
                for tool_id, resolved in statuses.items():
                    if tool_id in ON_DEMAND_ENGINES:
                        print(f"{tool_id.title():<12} ON_DEMAND / FALLBACK ({resolved.status}) {resolved.path}")
                    else:
                        print(f"{tool_id.title():<12} {resolved.status} {resolved.path}")
                    issue = tools.get(tool_id, {}).get('diagnostic')
                    if issue:
                        print(issue['message'] + issue['remediation'])
                        if issue['repair_command']:
                            print('修复命令：' + ' '.join(issue['repair_command']))
                for name, state in manager.trivy_data_statuses().items():
                    print(f"Trivy {name}: {state}")
                if health['notify']:
                    print(health['message'])
                return 0
            if not args.all and args.tool is None:
                parser.error("tools install requires a tool name or --all")
            if args.reinstall and args.all:
                parser.error('tools install --reinstall requires one explicitly selected component')
            names = tuple(name for name in VERSIONS if name not in ON_DEMAND_ENGINES) if args.all else (args.tool,)
            successful = True
            for tool_id in names:
                print(f"Preparing {tool_id}...", file=sys.stderr)
                resolved = manager.ensure(tool_id, **({'reinstall': True} if args.reinstall else {}))
                print(f"{tool_id.title():<12} {resolved.status} {resolved.path} {resolved.detail}")
                if resolved.diagnostic:
                    print(format_diagnostic(resolved.diagnostic, retry=f"security-check tools install {tool_id}"))
                successful &= resolved.status == ToolStatus.READY
            if "trivy" in names and manager.resolve("trivy").status == ToolStatus.READY:
                database = manager.prepare_trivy_database(manager.resolve("trivy").path)
                print(f"Trivy DB     {database}")
                if manager.data_diagnostics.get("vulnerability_db"):
                    print(format_diagnostic(manager.data_diagnostics["vulnerability_db"], retry="security-check tools install trivy"))
                successful &= database == ToolStatus.READY
            return 0 if successful else 2
        if args.command == "licenses":
            notice_roots = (Path(__file__).resolve().parent, Path(__file__).resolve().parents[2],
                            Path(sys.prefix) / "share" / "ai-security-runtime")
            def distributed_file(name: str) -> bool:
                return any((directory / name).is_file() for directory in notice_roots)
            print(f"{'Engine':<12} {'License':<18} Distribution")
            failed = False
            for descriptor in BUILTIN_ENGINES.values():
                metadata = descriptor.license_metadata
                status = LicensePolicy.distribution_status(metadata)
                print(f"{descriptor.display_name:<12} {metadata.license_spdx:<18} {status}")
                if args.check_distribution:
                    # This wheel carries our code and first-party rules. A
                    # runtime dependency or a later managed download is not
                    # an engine binary bundled inside the Runtime wheel.
                    delivery_actions = {"RUNTIME_DEPENDENCY": LicenseAction.USE,
                                        "MANAGED_PYTHON_PACKAGE": LicenseAction.AUTO_DOWNLOAD,
                                        "PINNED_RELEASE": LicenseAction.AUTO_DOWNLOAD}
                    action = delivery_actions.get(descriptor.install_strategy)
                    if action is None or LicensePolicy.permission(metadata, action) == Permission.NO:
                        failed = True
                    license_file = Path(__file__).parent / "licenses" / descriptor.engine_id / "LICENSE"
                    if not license_file.is_file():
                        failed = True
                    if metadata.notice_required and not (license_file.parent / "NOTICE").is_file():
                        failed = True
                    if metadata.source_offer_required and not distributed_file("SOURCE_OFFER.md"):
                        failed = True
            if args.check_distribution:
                from .rulepacks import RulePackManager, can_bundle_rule_pack
                if not all(can_bundle_rule_pack(pack.descriptor) for pack in RulePackManager().discover()):
                    failed = True
                if not distributed_file("THIRD_PARTY_NOTICES.md"):
                    failed = True
            return 2 if failed else 0
        if args.command == "mcp" and args.mcp_action == "config":
            workspace = WorkspaceResolver().resolve(args.path).path
            payload = toml_config(workspace) if args.toml else json_config(workspace)
            if args.copy and copy_to_clipboard(payload):
                print("Configuration copied to clipboard.")
                return 0
            if args.copy:
                print("Clipboard unavailable. Configuration printed below.\n")
            if args.toml or args.json or args.copy:
                print(payload)
            else:
                runtime = resolve_runtime_command()
                print("AI Security Runtime MCP\n")
                print(f"Name: ai-security-runtime\nTransport: stdio\nCommand: {runtime.command}\nArguments: {' '.join(runtime.args)}\nWorkspace: {workspace}")
                print("Environment: SECURITY_RUNTIME_WORKSPACE=" + str(workspace))
                print("\nFor any MCP-compatible coding tool:\n1. Open MCP settings\n2. Add local stdio server\n3. Use the command and arguments above")
            return 0
        global_action = (args.command in {'status', 'repair', 'uninstall'}
            or (args.command == 'integration' and args.integration == 'codex' and args.scope == 'global')
            or (args.command == 'setup' and args.integration in {None, 'codex'}
                and args.scope != 'project')
            or (args.command == 'doctor' and not args.project and (args.path is None or args.global_scope)))
        if global_action:
            from contextlib import nullcontext
            from .install_progress import InstallationProgress
            action = ('uninstall' if args.action == 'remove' else args.action) if args.command == 'integration' else args.command
            reporter = (installation_progress or InstallationProgress()) if action == 'setup' else nullcontext(None)
            with reporter as progress:
                from .global_integration import GlobalCodexIntegration, render_global
                from .global_workspace import resolve_workspace
                from .integration_lifecycle import IntegrationDiagnostic
                from .integration_recovery import configuration_recovery, repair_connection
                adapter = None
                workspace = None
                try:
                    if progress is not None:
                        progress('PREPARE')
                    adapter = GlobalCodexIntegration(allow_dev=getattr(args, 'dev', False))
                    # Local CLI paths may be relative; MCP workspace claims remain strict.
                    workspace = str(Path(args.path).absolute()) if args.path is not None else None
                    if workspace is None:
                        try:
                            resolve_workspace(str(Path.cwd()))
                            workspace = str(Path.cwd())
                        except (ValueError, OSError):
                            workspace = None
                    if action == 'repair':
                        data = repair_connection(adapter, workspace,
                            approve_user_managed=getattr(args, 'approve_user_managed', False))
                    elif action == 'setup':
                        from .personal_install import setup_personal_codex
                        data = setup_personal_codex(adapter, workspace, progress=progress)
                    else:
                        data = adapter.execute(action, workspace)
                    if data['overall'] == 'DEGRADED':
                        data['configuration_recovery'] = configuration_recovery(adapter, workspace,
                            reason=next(iter(data.get('diagnostics', [])), None))
                except (IntegrationDiagnostic, ValueError, OSError, TypeError, RecursionError):
                    # Do not echo arbitrary claims or malformed config contents.
                    exc = sys.exc_info()[1]
                    reason = exc.code if isinstance(exc, IntegrationDiagnostic) else 'GLOBAL_STATE_ACCESS_FAILED' if isinstance(exc, OSError) else 'GLOBAL_CONFIGURATION_REJECTED'
                    data = {'integration': 'codex', 'scope': 'GLOBAL', 'overall': 'BROKEN',
                            'ownership': 'UNKNOWN', 'diagnostics': [reason]}
                    try:
                        if adapter is not None:
                            data['configuration_recovery'] = configuration_recovery(adapter, workspace, reason=reason)
                    except (ValueError, OSError, TypeError, RecursionError):
                        pass  # Never reflect an invalid workspace/configuration claim.
                if progress is not None:
                    progress.finish(data.get('installation', {}).get('local_files_ready') is True)
            print(json.dumps(data, ensure_ascii=True) if args.json else render_global(data))
            return 2 if data['overall'] in {'BROKEN', 'DEGRADED'} else 0
        if args.command == 'integration' or (args.command == 'setup' and args.integration == 'codex'):
            from .integration_lifecycle import IntegrationManager, render_integration
            data = IntegrationManager().execute('setup' if args.command == 'setup' else args.action,
                                                args.integration, args.path)
            print(json.dumps(data, ensure_ascii=True) if args.json else render_integration(data))
            return 2 if data['overall'] == 'BROKEN' else 0
        if args.command == "setup":
            workspace = WorkspaceResolver().resolve(args.path).path
            registry = IntegrationRegistry()
            adapters = [registry.get(args.integration)] if args.integration else [adapter for adapter in registry.native() if adapter.detect()]
            print(f"AI Security Runtime\n\nWorkspace\n✓ {workspace}\n\nDetected AI coding tools")
            if not adapters:
                print("No supported native client detected. Use security-check mcp config for another tool.")
                return 0
            for adapter in adapters:
                print(f"✓ {adapter.display_name}" if adapter.detect() else f"○ {adapter.display_name} not detected")
            for adapter in adapters:
                print(f"\nConnecting {adapter.display_name}...")
                try:
                    state = adapter.install(workspace)
                except ValueError as exc:
                    print(f"{adapter.display_name} configuration could not be updated.\n{exc}\nRun: security-check setup {adapter.integration_id} --verbose")
                    return 2
                print(f"✓ {adapter.display_name} configuration written")
                print(f"Config path: {state.details['config_path']}")
                print("✓ Runtime MCP self-test passed")
                print(f"○ {adapter.display_name} client connection not confirmed yet")
                if state.status == IntegrationStatusCode.NEEDS_RESTART:
                    print(f"Restart {adapter.display_name} to load the project connection.")
                if args.verbose:
                    for key, value in state.details.items():
                        print(f"  {key}: {value or '-'}")
            print("\nCode stays local.")
            return 0
        if args.command == "integrations":
            workspace = WorkspaceResolver().resolve(args.path).path
            registry = IntegrationRegistry()
            if args.integrations_action == "repair":
                for adapter in registry.native():
                    state = adapter.repair(workspace)
                    print(f"{adapter.display_name:<12} {state.status}")
                return 0
            if args.integrations_action == "remove":
                adapter = registry.get(args.integration)
                state = adapter.uninstall(workspace)
                print(f"{adapter.display_name} project connection removed. {state.status}")
                return 0
            print("AI Security Runtime\n\nAI Coding integrations")
            for adapter in registry.native():
                state = adapter.status(workspace)
                print(f"{adapter.display_name:<12} {state.status}")
                for key in ("config_path", "configuration_status", "runtime_self_test", "last_client_invocation"):
                    print(f"  {key}: {state.details.get(key) or '-'}")
                if args.verbose:
                    for key, value in state.details.items():
                        if key in {"config_path", "configuration_status", "runtime_self_test", "last_client_invocation"}:
                            continue
                        print(f"  {key}: {value or '-'}")
            print("\nOther tools\nGeneric MCP  AVAILABLE\nCLI          AVAILABLE")
            return 0
        if args.command == "stats":
            if args.days < 1 or args.days > 365:
                raise ValueError("--days must be between 1 and 365")
            stats = IntegrationStateStore().stats(args.days)
            print(f"Last {stats['days']} days\n")
            print(f"Scans               {stats['scans']}\nIssues found        {stats['issues_found']}\nIssues resolved     {stats['issues_resolved']}\nAverage scan time   {stats['average_scan_ms']} ms")
            print("\nIntegrations")
            for name, count in sorted(stats["integrations"].items()):
                print(f"{name:<18} {count}")
            return 0
        if args.command == "mcp":
            from .mcp_server import serve
            serve()
            return 0
        if args.command == "hooks":
            if args.action == 'generate-mcp-poc':
                if args.hook != 'codex' or args.path is not None:
                    raise ValueError('MCP POC generation supports codex only, without --path; prints JSON without installing')
                from .codex_mcp_hook import codex_mcp_hook_config
                print(json.dumps(codex_mcp_hook_config(), ensure_ascii=True, indent=2))
                return 0
            if args.hook == 'pre-commit':
                from .hooks import GitHookManager
                value = GitHookManager(Path(args.path) if args.path is not None else Path.cwd()).execute(args.action, args.gate)
                print(json.dumps(value, ensure_ascii=True))
                return 0
            from .hook_adapters import HookIntegrationRegistry
            registry = HookIntegrationRegistry()
            if args.action != 'status' and args.hook is None:
                raise ValueError('Select a hook host')
            result = registry.manage(args.action,args.hook,args.path) if args.hook else registry.status(args.path)
            print(json.dumps(result,ensure_ascii=True) if args.json else json.dumps(result,ensure_ascii=False,indent=2))
            return 0
    except ExplicitScanBusy as exc:
        if getattr(args, 'json', False):
            print(json.dumps(exc.to_dict(), ensure_ascii=True))
        else:
            print(f"security-check: SCAN_ATTEMPT_BUSY: {exc}", file=sys.stderr)
        return 2
    except ScanCancelled:
        if getattr(args, 'json', False):
            print(json.dumps(cancelled_scan(), ensure_ascii=True))
        else:
            print(cancelled_scan()['message'], file=sys.stderr, flush=True)
        return 130
    except KeyboardInterrupt:
        message = '扫描能力准备已取消，未确认就绪。' if args.command in {'prepare-installation', 'prepare-scanners'} else '安装已取消，未确认完成。' if args.command in {'install', 'setup'} else '操作已取消。'
        print(message, file=sys.stderr, flush=True)
        return 130
    except DiscoveryLimitError as exc:
        if getattr(args, 'json', False):
            print(json.dumps(exc.to_dict(), ensure_ascii=True))
        else:
            print(f"security-check: {exc.code}: {sanitize(str(exc))}", file=sys.stderr)
        return 2
    except WorkspaceError as exc:
        hint = args.command
        if args.command == "setup" and args.integration:
            hint += " " + args.integration
        elif args.command == "mcp":
            hint += " config"
        message = str(exc).replace("security-check doctor --path <project>", f"security-check {hint} --path <project>")
        print(f"security-check: {message}", file=sys.stderr)
        return 2
    except (GitError, ValueError, OSError, ImportError) as exc:
        print(f"security-check: {sanitize(str(exc))}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
