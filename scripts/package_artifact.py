"""Archive the built one-directory Runtime for the current host only."""
from __future__ import annotations

import argparse
import os
import tarfile
import zipfile
import hashlib
from pathlib import Path

from security_runtime._version import __version__
from security_runtime.toolchain import platform_key


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", required=True, choices=("windows-x64", "macos-arm64", "macos-x64", "linux-x64"))
    parser.add_argument('--experience', action='store_true', help='Local R2.2 experience archive; no external publication')
    parser.add_argument('--bundle', type=Path, help='Alternate standalone bundle under workspace dist')
    args = parser.parse_args()
    actual = "-".join(platform_key())
    if args.platform != actual:
        raise ValueError(f"Cannot label {actual} build as {args.platform}")
    root = Path(__file__).resolve().parents[1]
    bundle = root / "dist" / "standalone" / "security-check" if args.bundle is None else (root / args.bundle).absolute()
    from security_runtime.hook_state import no_links
    no_links(bundle)
    if not bundle.resolve().is_relative_to(root / 'dist'):
        raise ValueError('Bundle must remain under workspace dist')
    executable = bundle / ("security-check.exe" if os.name == "nt" else "security-check")
    if not executable.is_file():
        raise ValueError("Standalone executable is missing")
    release = root / "dist" / ("experience" if args.experience else "release")
    release.mkdir(parents=True, exist_ok=True)
    stem = f"ai-security-runtime-v{__version__}" + ('-r2.2-local' if args.experience else '') + f"-{args.platform}"
    destination = release / (stem + (".zip" if os.name == "nt" else ".tar.gz"))
    files = sorted(path for path in bundle.rglob("*") if path.is_file())
    for file in files: no_links(file)
    if os.name == "nt":
        with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for file in files:
                archive.write(file, (Path("security-check") / file.relative_to(bundle)).as_posix())
    else:
        with tarfile.open(destination, "w:gz", dereference=True) as archive:
            for file in files:
                archive.add(file, arcname=(Path("security-check") / file.relative_to(bundle)).as_posix(), recursive=False)
    checksum = hashlib.sha256(destination.read_bytes()).hexdigest()
    destination.with_suffix(destination.suffix+'.sha256').write_text(checksum+'  '+destination.name+'\n',encoding='utf-8')
    print(destination)
    print('SHA256 '+checksum)


if __name__ == "__main__":
    main()
