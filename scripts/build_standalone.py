"""Build an inspectable one-directory Runtime without scanner engines."""
from __future__ import annotations

import json
import hashlib
import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

from security_runtime._version import __version__
from dependency_notices import inventory


def main(output_dir: Path | None = None) -> None:
    root = Path(__file__).resolve().parents[1]
    output = root / "dist" / "standalone" if output_dir is None else root / output_dir
    from security_runtime.hook_state import no_links
    no_links(output.absolute())
    output = output.resolve()
    if not output.is_relative_to(root / 'dist'):
        raise ValueError('Standalone output must remain inside workspace dist')
    subprocess.run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
                    "--distpath", str(output), "--workpath", str(root / "build" / "pyinstaller"),
                    str(root / "distribution" / "build" / "security-check.spec")],
                   cwd=root, check=True)
    bundle = output / "security-check"
    # Editable-install provenance is not needed by importlib.metadata and
    # contains the developer's absolute checkout path.
    for provenance in bundle.rglob("direct_url.json"):
        provenance.unlink()
    for name in ("LICENSE", "EULA.md", "LICENSING.md", "THIRD_PARTY_NOTICES.md", "SOURCE_OFFER.md"):
        shutil.copy2(root / name, bundle / name)
    shutil.copytree(root / "LICENSES", bundle / "LICENSES", dirs_exist_ok=True)
    inventory(bundle)
    for name in ('WINDOWS_EXPERIENCE.md','WINDOWS_EXPERIENCE.zh-CN.md','SCAN_TARGET_SELECTION.md','RULE_FOUNDATION.md','RULE_SOURCE_INVENTORY.md'):
        shutil.copy2(root / 'docs' / name,bundle / name)
    from security_runtime.build_identity import STATE_SCHEMA, git_provenance
    source_commit = git_provenance(root, 'rev-parse', 'HEAD')
    source_dirty = bool(git_provenance(root, 'status', '--porcelain'))
    from security_runtime.delivery import CONTRACT, encode, file_digest, package_metadata
    files = {p.relative_to(bundle).as_posix(): file_digest(p) for p in sorted(bundle.rglob('*'))
             if p.is_file() and p != bundle / 'version.json'}
    metadata = {"name": "AI Security Runtime", "version": __version__,
        "format": "pyinstaller-onedir", "source_commit": source_commit,
        "source_dirty":source_dirty, "experience_contract":"upgrade-and-scan-v1",
        "state_schema": STATE_SCHEMA, "capability_contract": "developer-guidance-v0.3",
        "launcher_contract": CONTRACT, "files": files,
        "managed_engines": ["semgrep", "gitleaks", "trivy"], "on_demand_engines": ["osv-scanner"]}
    metadata['build_id'] = hashlib.sha256(encode(metadata)).hexdigest()
    (bundle / "version.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    package_metadata(bundle)
    executable = bundle / ("security-check.exe" if os.name == "nt" else "security-check")
    subprocess.run([str(executable), "--version"], cwd=root, check=True, timeout=30)
    print(bundle)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-dir', type=Path, help='Alternate workspace dist directory; avoid replacing a running bundle')
    main(parser.parse_args().output_dir)
