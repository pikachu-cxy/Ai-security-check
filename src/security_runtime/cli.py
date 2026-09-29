from __future__ import annotations

import argparse
import json
import shutil
import sys
import tomllib
from pathlib import Path

from .capabilities import Capability
from .engines import BUILTIN_ENGINES
from .licensing import LicensePolicy
from .git import GitError
from .logging_utils import configure_logging
from .risk import MESSAGES
from .runtime import SecurityRuntime
from .scanners import ScannerRegistry
from .target import TargetDetector
from .toolchain import ToolManager, ToolStatus, VERSIONS
from .tools_info import installation_help
from .workspace import WorkspaceError, WorkspaceResolver


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
    sub.add_parser("mcp")
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
                    if not LicensePolicy.can_bundle(metadata):
                        failed = True
                    license_file = Path(__file__).parent / "licenses" / descriptor.engine_id / "LICENSE"
                    if not license_file.is_file():
                        failed = True
                    if descriptor.engine_id == "trivy" and not (license_file.parent / "NOTICE").is_file():
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
