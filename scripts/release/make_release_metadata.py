"""Create metadata from verified Windows and both Mac architecture artifacts."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from security_runtime._version import __version__

PLATFORMS = ("windows-x64", "macos-arm64", "macos-x64")
REPOSITORY = "pikachu-cxy/Ai-security-check"


def main(*, focused=False, workbuddy=False) -> None:
    release = Path(__file__).resolve().parents[2] / "dist" / "release"
    artifacts = {}
    lines = []
    source_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    for platform in PLATFORMS:
        name = f"ai-security-runtime-v{__version__}-{platform}" + (".zip" if platform.startswith("windows") else ".tar.gz")
        path = release / name
        if not path.is_file():
            raise ValueError(f"Missing verified platform artifact: {name}")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        verification = json.loads(path.with_name(name + ".verification.json").read_text(encoding="utf-8"))
        common = (verification.get("archive_sha256") == digest and verification.get("version") == __version__
                  and verification.get("platform") == platform and verification.get("smoke") is True
                  and verification.get("source_commit") == source_commit)
        full = (verification.get("managed_engines") and verification.get("plugin_discovery")
                and verification.get('dependency_unavailable_without_fallback') is True
                and verification.get('observed_development_without_baseline') is True
                and verification.get('fix_verify_offline_synthetic') is True)
        focused_ok = (verification.get('usage_monitor_disabled') is True
                      and 'start_usage_monitor' not in verification.get('mcp_tools', [])
                      and 'start_risk_dashboard' in verification.get('mcp_tools', []))
        workbuddy_ok = (verification.get('validation_scope') == 'workbuddy-adapter'
                        and verification.get('workbuddy_connector') is True
                        and {'frozen-install', 'settings-preservation', 'native-edit-record',
                             'owner-bound-mcp', 'bounded-stop', 'owned-uninstall'} <= set(verification.get('checked', [])))
        if not common or not (workbuddy_ok if workbuddy else focused_ok if focused else full):
            raise ValueError(f"Incomplete or stale native verification for {platform}")
        artifacts[platform] = {"url": f"https://github.com/{REPOSITORY}/releases/download/v{__version__}/{name}", "sha256": digest}
        lines.append(f"{digest}  {name}")
    (release / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (release / "release-manifest.json").write_text(json.dumps({"version": __version__, "source_commit": source_commit, "validation_scope": "workbuddy-adapter" if workbuddy else "focused-monitor-defaults" if focused else "full", "artifacts": artifacts}, indent=2) + "\n", encoding="utf-8")
    print(release / "release-manifest.json")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--focused", action="store_true")
    parser.add_argument("--workbuddy", action="store_true")
    args = parser.parse_args()
    main(focused=args.focused, workbuddy=args.workbuddy)
