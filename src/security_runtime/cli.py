from __future__ import annotations

import argparse
import json
import shutil
import sys
import tomllib
from pathlib import Path

from .capabilities import Capability
from .engines import BUILTIN_ENGINES
from .licensing import LicenseAction, LicensePolicy, Permission
from .git import GitError
from .logging_utils import configure_logging
from .risk import MESSAGES
from .runtime import SecurityRuntime
from .scanners import ScannerRegistry
from .target import TargetDetector
from .toolchain import ToolManager, ToolStatus, VERSIONS
from .tools_info import installation_help
from .workspace import WorkspaceError, WorkspaceResolver
from .integrations import IntegrationRegistry, IntegrationStatusCode
from .integration_state import DogfoodEvent, IntegrationStateStore
from .mcp_config import copy_to_clipboard, json_config, resolve_runtime_command, toml_config


def doctor(path: Path | None = None, *, json_output: bool = False, verbose: bool = False) -> int:
    report = {"runtime": {"git_available": bool(shutil.which("git")), "scanners": []}, "workspace": None,
              "capabilities": {}, "scanner_plan": {"available": [], "unavailable": []}, "database": "MISSING",
              "status": "unavailable", "message": ""}
    try:
        workspace = WorkspaceResolver().resolve(path, allow_non_git_explicit=True)
        profile = TargetDetector().detect(workspace.path)
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
        scanners = [{"name": adapter.name, "status": resolved[adapter.scanner_id].status,
                     "available": resolved[adapter.scanner_id].status == ToolStatus.READY,
                     "version": resolved[adapter.scanner_id].version, "source": resolved[adapter.scanner_id].source,
                     "path": resolved[adapter.scanner_id].path, "install": installation_help(adapter.name)}
                    for adapter in registry.adapters if adapter.scanner_id in resolved]
        report["runtime"]["scanners"] = scanners
        report["scanner_plan"]["available"] = [item["name"] for item in scanners if item["available"]]
        report["scanner_plan"]["unavailable"] = [item["name"] for item in scanners if not item["available"]]
        labels = {Capability.CODE_SAST: "Code Security", Capability.SECRET_SCAN: "Secret Security",
                  Capability.DEPENDENCY_VULN: "Dependency Security", Capability.IAC_MISCONFIG: "IaC Security"}
        for capability, label in labels.items():
            supporting = [adapter for adapter in registry.adapters if capability in adapter.capabilities]
            ready = any(resolved[adapter.scanner_id].status == ToolStatus.READY and
                        (adapter.scanner_id != "trivy" or report["database"] == ToolStatus.READY)
                        for adapter in supporting if adapter.scanner_id in resolved)
            report["capabilities"][label] = "READY" if ready else "MISSING"
        if not workspace.is_git:
            report["status"] = "workspace-only"
            report["message"] = "Workspace detected. A Git repository is required for scans."
        elif not report["runtime"]["git_available"]:
            report["status"] = "unavailable"
            report["message"] = "Git is required for scans."
        else:
            report["status"] = "ready" if all(value == "READY" for value in report["capabilities"].values()) else "limited"
            report["message"] = "Runtime ready." if report["status"] == "ready" else "Runtime ready with limited coverage."
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
        print("Languages: " + (", ".join(workspace_info["languages"]) or "Unknown"))
        print("\nSecurity capabilities")
        for label, state in report["capabilities"].items():
            print(f"{label:<22} {'✓' if state == 'READY' else '○'}")
        print("\nIntegrations")
        for name, state in report["integrations"].items():
            print(f"{name.title():<14} {state['status']}")
            if verbose:
                for key, value in state["details"].items():
                    print(f"  {key}: {value or '-'}")
        if verbose:
            print(f"\nRuntime\nGit: {'READY' if report['runtime']['git_available'] else 'MISSING'}")
            for item in report["runtime"]["scanners"]:
                descriptor = BUILTIN_ENGINES.get(item["name"])
                print(f"\n{item['name'].title()}\nStatus: {item['status']}\nVersion: {item['version'] or (descriptor.version if descriptor else '')}")
                print(f"Source: {item['source'] or 'NONE'}\nPath: {item['path'] or '-'}")
                if item["name"] == "trivy":
                    print(f"Database: {report['database']}")
                    if report["database"] == ToolStatus.READY:
                        metadata = manager.trivy_cache_dir() / "db" / "metadata.json"
                        try:
                            updated = json.loads(metadata.read_text(encoding="utf-8")).get("UpdatedAt", "")
                        except (OSError, ValueError):
                            updated = ""
                        print(f"Updated: {updated or '-'}")
                if not item["available"]:
                    print(f"Install: {item['install']}")
    print("\n" + report["message"])
    return code


def render(result) -> str:
    lines = ["AI Security Check", "", "检查完成。", f"发现 {len(result.findings)} 个需要处理的问题。", ""]
    for f in result.findings:
        lines += [f.severity, f.plain_title, f"位置：{f.file_path}:{f.line_start}", f"为什么危险：{f.impact}", f"建议：{f.fix_advice}", ""]
    lines += ["结果：", MESSAGES[result.release_status], f"Coverage: {result.coverage}", "", f"耗时：{result.duration_ms} ms"]
    for run in result.scanner_runs:
        if run.status != "SUCCESS":
            lines.append(f"{run.scanner}: {run.status} {run.error}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="security-check")
    sub = parser.add_subparsers(dest="command", required=True)
    doctor_parser = sub.add_parser("doctor")
    doctor_parser.add_argument("--path")
    doctor_parser.add_argument("--json", action="store_true")
    doctor_parser.add_argument("--verbose", action="store_true")
    scan_parser = sub.add_parser("scan")
    scan_parser.add_argument("--path")
    scan_parser.add_argument("--mode", choices=["quick", "feature", "release"], default="quick")
    scan_parser.add_argument("--json", action="store_true")
    scan_parser.add_argument("--staged", action="store_true", help=argparse.SUPPRESS)
    scan_parser.add_argument("--rules", help="Local user-provided Semgrep rule directory")
    mcp_parser = sub.add_parser("mcp")
    mcp_sub = mcp_parser.add_subparsers(dest="mcp_action")
    config_parser = mcp_sub.add_parser("config")
    config_parser.add_argument("--path")
    config_format = config_parser.add_mutually_exclusive_group()
    config_format.add_argument("--json", action="store_true")
    config_format.add_argument("--toml", action="store_true")
    config_parser.add_argument("--copy", action="store_true")
    config_parser.add_argument("--help-client", action="store_true")
    setup_parser = sub.add_parser("setup")
    setup_parser.add_argument("integration", nargs="?", choices=["cursor", "workbuddy"])
    setup_parser.add_argument("--path")
    setup_parser.add_argument("--verbose", action="store_true")
    integrations_parser = sub.add_parser("integrations")
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
    hooks_parser.add_argument("action", choices=["install"])
    hooks_parser.add_argument("hook", choices=["pre-commit"])
    hooks_parser.add_argument("--path")
    tools_parser = sub.add_parser("tools")
    tools_sub = tools_parser.add_subparsers(dest="tools_action", required=True)
    tools_sub.add_parser("status")
    install_parser = tools_sub.add_parser("install")
    install_parser.add_argument("tool", nargs="?", choices=tuple(VERSIONS))
    install_parser.add_argument("--all", action="store_true")
    args = parser.parse_args(argv)
    try:
        configure_logging(mcp=args.command == "mcp")
        if args.command == "doctor":
            return doctor(Path(args.path) if args.path is not None else None, json_output=args.json, verbose=args.verbose)
        if args.command == "scan":
            registry = ScannerRegistry()
            if not args.staged:
                print("Preparing security tools...", file=sys.stderr)
                for tool_id in VERSIONS:
                    try:
                        current_status = registry.tool_manager.resolve(tool_id).status
                    except Exception:
                        current_status = ToolStatus.BROKEN
                    if current_status != ToolStatus.READY:
                        print(f"{tool_id.title():<12} preparing...", file=sys.stderr)
                    resolved = registry.tool_manager.ensure(tool_id)
                    print(f"{tool_id.title():<12} {resolved.status}", file=sys.stderr)
                trivy = registry.tool_manager.resolve("trivy")
                if trivy.status == ToolStatus.READY:
                    if registry.tool_manager.database_status() != ToolStatus.READY:
                        print("Preparing vulnerability database...", file=sys.stderr)
                    database = registry.tool_manager.prepare_trivy_database(trivy.path)
                    print(f"Trivy DB     {database}", file=sys.stderr)
            result = SecurityRuntime(registry=registry).scan(args.path, args.mode, staged=args.staged, rules_path=args.rules)
            try:
                IntegrationStateStore().event(DogfoodEvent("cli", result.target_profile.path, args.mode,
                    result.duration_ms, len(result.findings), result.coverage))
            except OSError:
                pass
            print(json.dumps(result.to_dict(), ensure_ascii=False) if args.json else render(result))
            return 0 if result.release_status != "BLOCKED" else 1
        if args.command == "tools":
            manager = ToolManager()
            if args.tools_action == "status":
                for tool_id, resolved in manager.statuses().items():
                    print(f"{tool_id.title():<12} {resolved.status} {resolved.path}")
                print(f"Trivy DB     {manager.database_status()}")
                return 0
            if not args.all and args.tool is None:
                parser.error("tools install requires a tool name or --all")
            names = tuple(VERSIONS) if args.all else (args.tool,)
            successful = True
            for tool_id in names:
                print(f"Preparing {tool_id}...", file=sys.stderr)
                resolved = manager.ensure(tool_id)
                print(f"{tool_id.title():<12} {resolved.status} {resolved.path}")
                successful &= resolved.status == ToolStatus.READY
            if "trivy" in names and manager.resolve("trivy").status == ToolStatus.READY:
                database = manager.prepare_trivy_database(manager.resolve("trivy").path)
                print(f"Trivy DB     {database}")
                successful &= database == ToolStatus.READY
            return 0 if successful else 2
        if args.command == "licenses":
            notice_roots = (Path(__file__).resolve().parents[2], Path(sys.prefix) / "share" / "ai-security-runtime")
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
                print(f"✓ Runtime verified for {adapter.display_name}")
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
                if args.verbose:
                    for key, value in state.details.items():
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
            from .hooks import install_pre_commit
            print(install_pre_commit(Path(args.path) if args.path is not None else Path.cwd()))
            return 0
    except (GitError, ValueError, FileNotFoundError, ImportError) as exc:
        print(f"security-check: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
