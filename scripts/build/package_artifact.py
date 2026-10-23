"""Archive the built one-directory Runtime for the current host only."""
from __future__ import annotations

import argparse
import os
import tarfile
import zipfile
import hashlib
import stat
from pathlib import Path

from security_runtime._version import __version__
from security_runtime.toolchain import platform_key


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", required=True, choices=("windows-x64", "macos-arm64", "macos-x64", "linux-x64"))
    parser.add_argument('--experience', action='store_true', help='Local R2.2 experience archive; no external publication')
    parser.add_argument('--experience-label', help='Safe local experience suffix; requires --experience')
    parser.add_argument('--bundle', type=Path, help='Alternate standalone bundle under workspace dist')
    args = parser.parse_args()
    if args.experience_label:
        import re
        if not args.experience or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', args.experience_label):
            raise ValueError('Experience label requires --experience and lowercase safe characters')
    actual = "-".join(platform_key())
    if args.platform != actual:
        raise ValueError(f"Cannot label {actual} build as {args.platform}")
    root = Path(__file__).resolve().parents[2]
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
    stem = f"ai-security-runtime-v{__version__}" + ('-'+(args.experience_label or 'r2.2-local') if args.experience else '') + f"-{args.platform}"
    destination = release / (stem + (".zip" if os.name == "nt" else ".tar.gz"))
    from security_runtime.delivery import package_metadata, package_inventory
    metadata = package_metadata(bundle)
    entries = package_inventory(bundle, allow_internal_links=bool(metadata.get('links')))
    files = [bundle / row[0] for row in entries if stat.S_ISREG(row[1])]
    if os.name == "nt":
        with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for file in files:
                archive.write(file, (Path("security-check") / file.relative_to(bundle)).as_posix())
    else:
        with tarfile.open(destination, "w:gz", dereference=False) as archive:
            for row in entries:
                archive.add(bundle / row[0], arcname='security-check/' + row[0], recursive=False)
    checksum = hashlib.sha256(destination.read_bytes()).hexdigest()
    destination.with_suffix(destination.suffix+'.sha256').write_text(checksum+'  '+destination.name+'\n',encoding='utf-8')
    print(destination)
    print('SHA256 '+checksum)


if __name__ == "__main__":
    main()
