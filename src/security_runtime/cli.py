from __future__ import annotations

import argparse
import json
import shutil
import sys
import tomllib
from pathlib import Path

from .git import GitError
from .logging_utils import configure_logging
from .risk import MESSAGES
from .runtime import SecurityRuntime
from .scanners import ScannerRegistry
from .target import TargetDetector
from .tools_info import installation_help
from .workspace import WorkspaceError, WorkspaceResolver


def doctor(path: Path | None = None, *, json_output: bool = False) -> int:
    registry = ScannerRegistry()
    scanners = [{"name": adapter.name, "available": bool(shutil.which(adapter.executable)), "install": installation_help(adapter.name)} for adapter in registry.adapters]
    report = {"runtime": {"git_available": bool(shutil.which("git")), "scanners": scanners}, "workspace": None, "scanner_plan": {"available": [], "unavailable": []}, "status": "unavailable", "message": ""}
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
        report["scanner_plan"]["available"] = [item["name"] for item in scanners if item["available"]]
        report["scanner_plan"]["unavailable"] = [item["name"] for item in scanners if not item["available"]]
        if not workspace.is_git:
            report["status"] = "workspace-only"
            report["message"] = "Workspace detected. A Git repository is required for scans."
        elif not report["runtime"]["git_available"]:
            report["status"] = "unavailable"
            report["message"] = "Git is required for scans."
        else:
            report["status"] = "ready" if report["scanner_plan"]["available"] else "limited"
            report["message"] = "Runtime ready." if report["status"] == "ready" else "Runtime ready with limited coverage."
        code = 0
    except (WorkspaceError, ValueError, OSError) as exc:
        report["message"] = str(exc)
        code = 2
    if json_output:
        print(json.dumps(report, ensure_ascii=False))
        return code
    print("AI Security Runtime\n\nRuntime")
    print(f"Git          {'✓' if report['runtime']['git_available'] else '✗ not installed'}")
    for item in scanners:
        print(f"{item['name'].title():<12} {'✓' if item['available'] else '✗ not installed'}")
    if report["workspace"]:
        workspace_info = report["workspace"]
        print(f"\nWorkspace\nPath: {workspace_info['path']}\nGit: {'✓' if workspace_info['git'] else '○'}")
        print("Languages: " + (", ".join(workspace_info["languages"]) or "Unknown"))
        print("Project: " + workspace_info["project"])
        print("\nScanner Plan\nAvailable")
        for name in report["scanner_plan"]["available"]:
            print(f"✓ {name.title()}")
        print("Unavailable")
        for item in scanners:
            if not item["available"]:
                print(f"○ {item['name'].title()}\n  not installed\n  Install: {item['install']}")
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
    scan_parser = sub.add_parser("scan")
    scan_parser.add_argument("--path")
    scan_parser.add_argument("--mode", choices=["quick", "feature", "release"], default="quick")
    scan_parser.add_argument("--json", action="store_true")
    scan_parser.add_argument("--staged", action="store_true", help=argparse.SUPPRESS)
    sub.add_parser("mcp")
    hooks_parser = sub.add_parser("hooks")
    hooks_parser.add_argument("action", choices=["install"])
    hooks_parser.add_argument("hook", choices=["pre-commit"])
    hooks_parser.add_argument("--path")
    args = parser.parse_args(argv)
    try:
        configure_logging(mcp=args.command == "mcp")
        if args.command == "doctor":
            return doctor(Path(args.path) if args.path is not None else None, json_output=args.json)
        if args.command == "scan":
            result = SecurityRuntime().scan(args.path, args.mode, staged=args.staged)
            print(json.dumps(result.to_dict(), ensure_ascii=False) if args.json else render(result))
            return 0 if result.release_status != "BLOCKED" else 1
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
