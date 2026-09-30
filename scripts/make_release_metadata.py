"""Create checksum and URL metadata only from all four verified artifacts."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from security_runtime._version import __version__

PLATFORMS = ("windows-x64", "macos-arm64", "macos-x64", "linux-x64")
REPOSITORY = "pikachu-cxy/Ai-security-check"


def main() -> None:
    release = Path(__file__).resolve().parents[1] / "dist" / "release"
    artifacts = {}
    lines = []
    for platform in PLATFORMS:
        name = f"ai-security-runtime-v{__version__}-{platform}" + (".zip" if platform.startswith("windows") else ".tar.gz")
        path = release / name
        if not path.is_file():
            raise ValueError(f"Missing verified platform artifact: {name}")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        verification = json.loads(path.with_name(name + ".verification.json").read_text(encoding="utf-8"))
        if (verification.get("archive_sha256") != digest or verification.get("version") != __version__
                or verification.get("platform") != platform or not verification.get("smoke")
                or not verification.get("managed_engines")):
            raise ValueError(f"Incomplete or stale native verification for {platform}")
        artifacts[platform] = {"url": f"https://github.com/{REPOSITORY}/releases/download/v{__version__}/{name}", "sha256": digest}
        lines.append(f"{digest}  {name}")
    (release / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (release / "release-manifest.json").write_text(json.dumps({"version": __version__, "artifacts": artifacts}, indent=2) + "\n", encoding="utf-8")
    print(release / "release-manifest.json")


if __name__ == "__main__":
    main()
