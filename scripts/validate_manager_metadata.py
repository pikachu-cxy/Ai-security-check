"""Validate generated WinGet schemas and package-manager checksums offline."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import jsonschema
import yaml

from security_runtime._version import __version__

ROOT = Path(__file__).resolve().parents[1]


def validate(manifest: Path, winget: Path, formula: Path, *, archives: bool = True) -> None:
    data = json.loads(manifest.read_text(encoding="utf-8"))
    if data["version"] != __version__:
        raise ValueError("Release version mismatch")
    payloads = {}
    for path in winget.glob("*.yaml"):
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        kind = payload["ManifestType"]
        schema = json.loads((ROOT / "distribution/winget/schemas" / f"manifest.{kind}.1.10.0.json").read_text(encoding="utf-8"))
        jsonschema.Draft7Validator(schema).validate(payload)
        if payload["PackageIdentifier"] != "PikachuCXY.AISecurityRuntime" or payload["PackageVersion"] != __version__:
            raise ValueError("WinGet identity mismatch")
        if kind in payloads:
            raise ValueError("Duplicate WinGet manifest")
        payloads[kind] = payload
    if set(payloads) != {"version", "defaultLocale", "installer"}:
        raise ValueError("Incomplete WinGet multi-file manifest")
    installer = payloads["installer"]
    windows = data["artifacts"]["windows-x64"]
    if installer["Installers"] != [{"Architecture": "x64", "InstallerUrl": windows["url"], "InstallerSha256": windows["sha256"].upper()}]:
        raise ValueError("WinGet checksum or URL mismatch")
    formula_text = formula.read_text(encoding="utf-8")
    for platform, entry in data["artifacts"].items():
        if archives:
            archive = manifest.parent / entry["url"].rsplit("/", 1)[-1]
            if hashlib.sha256(archive.read_bytes()).hexdigest() != entry["sha256"]:
                raise ValueError(f"Archive checksum mismatch: {platform}")
        if platform != "windows-x64" and (f'url "{entry["url"]}"' not in formula_text or f'sha256 "{entry["sha256"]}"' not in formula_text):
            raise ValueError(f"Homebrew metadata mismatch: {platform}")
    print("Package-manager schemas, versions, URLs and checksums OK")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--winget", type=Path, default=ROOT / "distribution/winget")
    parser.add_argument("--formula", type=Path, default=ROOT / "distribution/homebrew/Formula/ai-security-runtime.rb")
    args = parser.parse_args()
    validate(args.manifest, args.winget, args.formula)
