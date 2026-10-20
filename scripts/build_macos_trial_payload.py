"""Build an immutable, offline wheel payload for the opt-in macOS installer."""
from __future__ import annotations

import argparse
from email.parser import BytesParser
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile


RELEASE_TAG = "macos-trial-v0.3.8.1"
PLATFORMS = {"macos-arm64", "macos-x64"}


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def wheel_requirement(path: Path) -> tuple[str, str]:
    with zipfile.ZipFile(path) as archive:
        metadata = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
        if len(metadata) != 1:
            raise ValueError("Wheel must have exactly one METADATA file")
        value = BytesParser().parsebytes(archive.read(metadata[0]))
    name, version = value["Name"], value["Version"]
    if not name or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name):
        raise ValueError("Invalid distribution name")
    if not version or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+!-]*", version):
        raise ValueError("Invalid distribution version")
    normalized = re.sub(r"[-_.]+", "-", name).lower()
    return normalized, f"{normalized}=={version} --hash=sha256:{sha256(path)}"


def package_payload(wheelhouse: Path, installer: Path, output: Path, platform: str) -> Path:
    if platform not in PLATFORMS:
        raise ValueError("Unsupported macOS platform")
    wheels = sorted(wheelhouse.glob("*.whl"))
    if not wheels or any(path.is_symlink() for path in wheels):
        raise ValueError("Missing wheelhouse or linked wheel")
    requirements = {}
    release = None
    for wheel in wheels:
        name, requirement = wheel_requirement(wheel)
        if name in requirements:
            raise ValueError("Duplicate wheel distribution")
        requirements[name] = requirement
        if name == "ai-security-runtime":
            with zipfile.ZipFile(wheel) as archive:
                release = json.loads(archive.read("security_runtime/managed_release.json"))
    if not release or not re.fullmatch(r"[0-9a-f]{64}", release.get("build_id", "")):
        raise ValueError("A managed release wheel is required")
    if not re.fullmatch(r"[0-9a-f]{40}", release.get("source_commit", "")):
        raise ValueError("Source commit is required")
    output.mkdir(parents=True, exist_ok=True)
    target = output / f"ai-security-runtime-macos-trial-{platform}.tar.gz"
    if target.exists():
        raise ValueError("Refusing to overwrite a payload")
    with tempfile.TemporaryDirectory(prefix="macos-trial-payload-") as directory:
        root = Path(directory)
        (root / "wheelhouse").mkdir()
        for wheel in wheels:
            shutil.copyfile(wheel, root / "wheelhouse" / wheel.name)
        shutil.copyfile(installer, root / "managed_install.py")
        (root / "requirements.txt").write_text(
            "\n".join(requirements[name] for name in sorted(requirements)) + "\n", encoding="utf-8"
        )
        files = {
            path.relative_to(root).as_posix(): sha256(path)
            for path in sorted(root.rglob("*")) if path.is_file()
        }
        manifest = {
            "schema": "macos-trial-payload-v1", "release_tag": RELEASE_TAG,
            "version": release["version"], "source_commit": release["source_commit"],
            "build_id": release["build_id"], "platform": platform, "files": files,
        }
        (root / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        with tarfile.open(target, "w:gz", format=tarfile.PAX_FORMAT) as archive:
            for path in sorted(root.rglob("*")):
                if path.is_file():
                    archive.add(path, arcname=path.relative_to(root).as_posix(), recursive=False)
    target.with_name(target.name + ".sha256").write_text(
        f"{sha256(target)}  {target.name}\n", encoding="utf-8"
    )
    return target


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--platform", choices=sorted(PLATFORMS), required=True)
    parser.add_argument("--output", type=Path, default=Path("dist/macos-trial"))
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="macos-trial-wheels-") as directory:
        wheelhouse = Path(directory)
        # Resolve on the target macOS runner. Missing wheels fail the build;
        # end users never need an implicit C/Rust compilation toolchain.
        subprocess.run([
            sys.executable, "-m", "pip", "--isolated", "download", "--only-binary=:all:",
            "--index-url", "https://pypi.org/simple", "--dest", str(wheelhouse),
            str(args.wheel.resolve()),
        ], check=True, timeout=600)
        archive = package_payload(
            wheelhouse, repository / "distribution/macos/managed_install.py",
            args.output, args.platform,
        )
        print(archive)


if __name__ == "__main__":
    main()
