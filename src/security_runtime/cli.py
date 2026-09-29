from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from .git import GitError, GitService
from .logging_utils import configure_logging
from .risk import MESSAGES
from .runtime import SecurityRuntime
from .scanners import ScannerRegistry
from .target import TargetDetector


def doctor(path: Path | None = None) -> int:
    print("AI Security Runtime\n\nEnvironment")
    print(f"Git          {'✓' if shutil.which('git') else '✗ not installed'}")
    registry = ScannerRegistry()
    available = 0
    for adapter in registry.adapters:
        present = bool(shutil.which(adapter.executable))
        available += present
        print(f"{adapter.name.title():<12} {'✓' if present else '✗ not installed'}")
    if path is None:
        try:
            path = GitService(Path.cwd()).top_level()
        except GitError:
            print("\nNo project detected. Run security-check doctor --path <project-path>")
            return 2
    path = path.resolve(strict=True)
    if not path.is_dir():
        raise ValueError("Project path must be a directory")
    profile = TargetDetector().detect(path)
    print("\nProject\n" + (", ".join(profile.languages + profile.frameworks) or "Unknown"))
    print("\nStatus\n" + ("Ready" if available else "No scanners installed"))
    return 0 if available else 2


def render(result) -> str:
    lines = ["AI Security Check", "", "检查完成。", f"发现 {len(result.findings)} 个需要处理的问题。", ""]
    for f in result.findings:
        lines += [f.severity, f.plain_title, f"位置：{f.file_path}:{f.line_start}", f"为什么危险：{f.impact}", f"建议：{f.fix_advice}", ""]
    lines += ["结果：", MESSAGES[result.release_status], "", f"耗时：{result.duration_ms} ms"]
    for run in result.scanner_runs:
        if run.status != "SUCCESS":
            lines.append(f"{run.scanner}: {run.status} {run.error}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    configure_logging()
    parser = argparse.ArgumentParser(prog="security-check")
    sub = parser.add_subparsers(dest="command", required=True)
    doctor_parser = sub.add_parser("doctor")
    doctor_parser.add_argument("--path")
    scan_parser = sub.add_parser("scan")
    scan_parser.add_argument("--path", default=".")
    scan_parser.add_argument("--mode", choices=["quick", "feature", "release"], default="quick")
    scan_parser.add_argument("--json", action="store_true")
    scan_parser.add_argument("--staged", action="store_true", help=argparse.SUPPRESS)
    sub.add_parser("mcp")
    hooks_parser = sub.add_parser("hooks")
    hooks_parser.add_argument("action", choices=["install"])
    hooks_parser.add_argument("hook", choices=["pre-commit"])
    hooks_parser.add_argument("--path", default=".")
    args = parser.parse_args(argv)
    try:
        if args.command == "doctor":
            return doctor(Path(args.path) if args.path is not None else None)
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
            print(install_pre_commit(Path(args.path)))
            return 0
    except (GitError, ValueError, FileNotFoundError, ImportError) as exc:
        print(f"security-check: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
