"""Create metadata from verified Windows and both Mac architecture artifacts."""
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from security_runtime._version import __version__

PLATFORMS = ("windows-x64", "macos-arm64", "macos-x64")
REPOSITORY = "pikachu-cxy/Ai-security-check"


def main() -> None:
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
        if (verification.get("archive_sha256") != digest or verification.get("version") != __version__
                or verification.get("platform") != platform or not verification.get("smoke")
                or not verification.get("managed_engines") or not verification.get("plugin_discovery")
                or verification.get('dependency_unavailable_without_fallback') is not True
                or verification.get('observed_development_without_baseline') is not True
                or verification.get('fix_verify_offline_synthetic') is not True
                or verification.get("source_commit") != source_commit):
            raise ValueError(f"Incomplete or stale native verification for {platform}")
        artifacts[platform] = {"url": f"https://github.com/{REPOSITORY}/releases/download/v{__version__}/{name}", "sha256": digest}
        lines.append(f"{digest}  {name}")
    (release / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (release / "release-manifest.json").write_text(json.dumps({"version": __version__, "source_commit": source_commit, "artifacts": artifacts}, indent=2) + "\n", encoding="utf-8")
    print(release / "release-manifest.json")


if __name__ == "__main__":
    main()
