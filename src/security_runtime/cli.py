from __future__ import annotations

import argparse
import json
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
            profile = TargetDetector().detect(workspace.path, files)
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
        print(json.dumps(report, ensure_ascii=False))
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


def main(argv: list[str] | None = None) -> int:
    # Windows redirected streams may otherwise use cp1252/cp936. MCP JSON and
    # CLI status symbols are UTF-8 on every delivery format.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(prog="security-check")
    parser.add_argument("--version", action="version", version=f"AI Security Runtime {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    info_parser=sub.add_parser('runtime-info',help='Read version/capabilities and host reconnect guidance without scanning')
    info_parser.add_argument('--json',action='store_true')
    remediation_parser = sub.add_parser('remediation', help='User-level automatic remediation preferences')
    remediation_parser.add_argument('action', choices=['status', 'configure'])
    remediation_parser.add_argument('--mode', choices=['smart_auto', 'ask_before_fix', 'report_only'])
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
    triage_parser.add_argument('--allow-external-code-context',action='store_true',help='Authorize bounded redacted code context to configured external LLM')
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
    scan_parser = sub.add_parser("scan", help="Scan code changes or the project")
    scan_parser.add_argument("--path")
    scan_parser.add_argument("--mode", choices=["quick", "feature", "release"], default="quick")
    scan_parser.add_argument("--json", action="store_true")
    scan_parser.add_argument("--no-progress", action="store_true", help="不显示进度，仍输出正式结果和错误")
    scan_parser.add_argument("--verbose", action="store_true", help="显示本次不适用的检查")
    scan_parser.add_argument("--staged", action="store_true", help=argparse.SUPPRESS)
    scan_parser.add_argument("--rules", help="Local user-provided Semgrep rule directory")
    mcp_parser = sub.add_parser("mcp", help="Run or configure the MCP server")
    mcp_sub = mcp_parser.add_subparsers(dest="mcp_action")
    config_parser = mcp_sub.add_parser("config")
    config_parser.add_argument("--path")
    config_format = config_parser.add_mutually_exclusive_group()
    config_format.add_argument("--json", action="store_true")
    config_format.add_argument("--toml", action="store_true")
    config_parser.add_argument("--copy", action="store_true")
    config_parser.add_argument("--help-client", action="store_true")
    setup_parser = sub.add_parser("setup", help="Configure an AI coding tool connection")
    setup_parser.add_argument("integration", nargs="?", choices=["cursor", "workbuddy"])
    setup_parser.add_argument("--path")
    setup_parser.add_argument("--verbose", action="store_true")
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
    hooks_parser = sub.add_parser("hooks")
    hooks_parser.add_argument("action", choices=["install", "status", "repair", "remove", "generate-mcp-poc"])
    hooks_parser.add_argument("hook", nargs="?", choices=["pre-commit", "codex", "cursor", "kiro", "workbuddy", "codebuddy", "qoder"])
    hooks_parser.add_argument("--path")
    hooks_parser.add_argument("--json", action="store_true")
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
    tools_sub.add_parser("status")
    install_parser = tools_sub.add_parser("install")
    install_parser.add_argument("tool", nargs="?", choices=tuple(VERSIONS))
    install_parser.add_argument("--all", action="store_true")
    args = parser.parse_args(argv)
    try:
        configure_logging(mcp=args.command == "mcp")
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
                    output = HookCoordinator().handle(event,args.path,args.host,args.session_id)
                print(json.dumps(output,ensure_ascii=True) if args.json or args.event=='host-event' else
                      f"{output['status']} · coverage {output['coverage']} · new families {output['delta']['new']} · added occurrences {output['delta']['additional_occurrences']}\n{output['next_step']}")
                return 0  # Findings and scanner limitations are advisory.
            except Exception:
                # Do not echo untrusted stdin, paths or exception source text.
                print(json.dumps({'status':'FAILED','error_code':'HOOK_RUNTIME_FAILED','systemMessage':'AI Security Runtime hook could not complete. Retry the local advisory check.'}))
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
            print(json.dumps({'remediation': {'mode': config.read()}, 'max_auto_fix_attempts': 2}))
            return 0
        if args.command=='runtime-info':
            from .host_guidance import runtime_info
            info=runtime_info()
            print(json.dumps(info,ensure_ascii=False) if args.json else '\n'.join([
                'AI Security Runtime '+info['version'], 'Capabilities: '+info['capability_contract'],
                *info['connection_recovery']]))
            return 0
        if args.command=='summary':
            import os
            from .security_summary import SecuritySummaryService
            from .human import render_security_summary
            bound=os.getenv('SECURITY_RUNTIME_WORKSPACE')
            root=args.path or bound
            if root is None:
                root=WorkspaceResolver().resolve(allow_non_git_source=True).path
            result=SecuritySummaryService().get(root,args.scan,details=args.details,bound_workspace=bound)
            print(json.dumps(result,ensure_ascii=False) if args.json else render_security_summary(result))
            return 0
        if args.command=='ai':
            from .triage_providers import AIConfig
            AIConfig(args.base_url,args.model,args.api_key_env,args.provider).save()
            print('BYOK 配置已保存，仅保存 API key 环境变量名。AI 默认关闭。')
            print('将向外部 LLM Provider 发送经过限制和脱敏的代码上下文，用于安全 Finding 验证。')
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
                print(json.dumps(scan['findings'],ensure_ascii=False,indent=2))
                return 0
            if args.provider:
                if args.prepare: raise ValueError('Choose BYOK or agent-native prepare')
                if not args.allow_external_code_context:
                    raise ValueError('将向外部 LLM Provider 发送经过限制和脱敏的代码上下文。必须显式提供 --allow-external-code-context')
                provider=OpenAICompatibleProvider(AIConfig.load(),allow_external_code_context=True)
                if args.no_progress: output=service.run(scan['scan_id'],provider,**selection)
                else:
                    from .cli_progress import CLIProgressRenderer
                    with CLIProgressRenderer() as reporter: output=service.run(scan['scan_id'],provider,progress=reporter,**selection)
                print(json.dumps(output,ensure_ascii=False) if args.json else render_triage(output['view']))
                return 2 if output['failures'] or output['evidence_errors'] else 0
            if args.prepare:
                print(json.dumps(service.prepare(scan['scan_id'],**selection),ensure_ascii=False))
            else:
                view=service.view(scan['scan_id'])
                print(json.dumps(view,ensure_ascii=False) if args.json else render_triage(view))
            return 0
        if args.command == "doctor":
            return doctor(Path(args.path) if args.path is not None else None, json_output=args.json, verbose=args.verbose)
        if args.command == "scan":
            registry = ScannerRegistry()
            # Adapters prepare their engines only after Runtime scope/planning.
            from .cli_progress import CLIProgressRenderer
            if args.no_progress:
                result = SecurityRuntime(registry=registry).scan(args.path, args.mode, staged=args.staged, rules_path=args.rules)
            else:
                with CLIProgressRenderer() as reporter:
                    result = SecurityRuntime(registry=registry).scan(args.path, args.mode, staged=args.staged, rules_path=args.rules, progress=reporter)
            try:
                IntegrationStateStore().event(DogfoodEvent("cli", result.target_profile.path, args.mode,
                    result.duration_ms, len(result.findings), result.coverage))
            except OSError:
                pass
            print(json.dumps(result.to_dict(), ensure_ascii=False) if args.json else render(result, verbose=args.verbose))
            return 0 if result.release_status != "BLOCKED" else 1
        if args.command == "tools":
            manager = ToolManager()
            if args.tools_action == "status":
                for tool_id, resolved in manager.statuses().items():
                    if tool_id in ON_DEMAND_ENGINES:
                        print(f"{tool_id.title():<12} ON_DEMAND / FALLBACK ({resolved.status}) {resolved.path}")
                    else:
                        print(f"{tool_id.title():<12} {resolved.status} {resolved.path}")
                for name, state in manager.trivy_data_statuses().items():
                    print(f"Trivy {name}: {state}")
                return 0
            if not args.all and args.tool is None:
                parser.error("tools install requires a tool name or --all")
            names = tuple(name for name in VERSIONS if name not in ON_DEMAND_ENGINES) if args.all else (args.tool,)
            successful = True
            for tool_id in names:
                print(f"Preparing {tool_id}...", file=sys.stderr)
                resolved = manager.ensure(tool_id)
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
                if args.action != 'install':
                    raise ValueError('Existing pre-commit supports install only')
                from .hooks import install_pre_commit
                print(install_pre_commit(Path(args.path) if args.path is not None else Path.cwd()))
                return 0
            from .hook_adapters import HookIntegrationRegistry
            registry = HookIntegrationRegistry()
            if args.action != 'status' and args.hook is None:
                raise ValueError('Select a hook host')
            result = registry.manage(args.action,args.hook,args.path) if args.hook else registry.status(args.path)
            print(json.dumps(result,ensure_ascii=True) if args.json else json.dumps(result,ensure_ascii=False,indent=2))
            return 0
    except KeyboardInterrupt:
        print("扫描已取消。", file=sys.stderr)
        return 130
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
