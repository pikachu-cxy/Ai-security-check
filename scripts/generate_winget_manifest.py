"""Generate portable archive WinGet manifests from verified release metadata."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import yaml

from security_runtime._version import __version__

IDENTIFIER = "PikachuCXY.AISecurityRuntime"


def artifact(data: dict, platform: str) -> tuple[str, str]:
    entry = data["artifacts"][platform]
    url, digest = entry["url"], entry["sha256"]
    if not url.startswith(f"https://github.com/pikachu-cxy/Ai-security-check/releases/download/v{__version__}/"):
        raise ValueError("Unexpected release asset URL")
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("Invalid SHA256")
    return url, digest


def generate(manifest: Path, output: Path) -> None:
    data = json.loads(manifest.read_text(encoding="utf-8"))
    if data["version"] != __version__:
        raise ValueError("Release version mismatch")
    url, digest = artifact(data, "windows-x64")
    common = {"PackageIdentifier": IDENTIFIER, "PackageVersion": __version__}
    version = {**common, "DefaultLocale": "en-US", "ManifestType": "version", "ManifestVersion": "1.10.0"}
    locale = {**common, "PackageLocale": "en-US", "Publisher": "PikachuCXY",
              "PackageName": "AI Security Runtime", "License": "MIT", "Moniker": "security-check",
              "ShortDescription": "Local security runtime for AI coding agents",
              "ManifestType": "defaultLocale", "ManifestVersion": "1.10.0"}
    installer = {**common, "InstallerType": "zip", "NestedInstallerType": "portable",
                 "NestedInstallerFiles": [{"RelativeFilePath": "security-check\\security-check.exe",
                                           "PortableCommandAlias": "security-check"}],
                 "Installers": [{"Architecture": "x64", "InstallerUrl": url, "InstallerSha256": digest.upper()}],
                 "ManifestType": "installer", "ManifestVersion": "1.10.0"}
    output.mkdir(parents=True, exist_ok=True)
    for suffix, payload in (("", version), (".locale.en-US", locale), (".installer", installer)):
        (output / f"{IDENTIFIER}{suffix}.yaml").write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("distribution/winget"))
    arguments = parser.parse_args()
    generate(arguments.manifest, arguments.output)
