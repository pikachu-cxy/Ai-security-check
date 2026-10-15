"""Build an inspectable one-directory Runtime without scanner engines."""
from __future__ import annotations

import json
import hashlib
import argparse
import os
import shutil
import subprocess
import sys
import stat
from pathlib import Path

from security_runtime._version import __version__
from dependency_notices import inventory


STANDALONE_DOCUMENTS = (
    'docs/guides/CURSOR_INSTALL_AND_TEST.zh-CN.md',
    'docs/PILOT_INSTALL_AND_USE.zh-CN.md',
    'docs/guides/WINDOWS_EXPERIENCE.md',
    'docs/guides/WINDOWS_EXPERIENCE.zh-CN.md',
    'docs/guides/PERSONAL_INSTALL_AND_GUIDANCE.zh-CN.md',
    'docs/archive/2026-10/INSTALL_FLOW_ACCEPTANCE.zh-CN.md',
    'docs/archive/2026-10/BACKGROUND_PREPARATION_ACCEPTANCE.zh-CN.md',
    'docs/design/SCAN_TARGET_SELECTION.md',
    'docs/design/RULE_FOUNDATION.md',
    'docs/design/RULE_SOURCE_INVENTORY.md',
)


def copy_standalone_documents(root: Path, bundle: Path) -> None:
    # Repository organization may change; installed document names stay stable.
    for relative_path in STANDALONE_DOCUMENTS:
        source = root / relative_path
        shutil.copy2(source, bundle / source.name)


def main(output_dir: Path | None = None, work_dir: Path | None = None,
         launcher_bundle: Path | None = None) -> None:
    root = Path(__file__).resolve().parents[1]
    output = root / "dist" / "standalone" if output_dir is None else root / output_dir
    from security_runtime.hook_state import no_links
    no_links(output.absolute())
    output = output.resolve()
    if not output.is_relative_to(root / 'dist'):
        raise ValueError('Standalone output must remain inside workspace dist')
    work = root / 'build' / 'pyinstaller' if work_dir is None else root / work_dir
    no_links(work.absolute())
    work = work.resolve()
    if not work.is_relative_to(root / 'build'):
        raise ValueError('Standalone work directory must remain inside workspace build')
    if work_dir is not None and (work.exists() or output.exists()):
        raise ValueError('Isolated build requires fresh work and output directories')
    launcher_source = None
    if launcher_bundle is not None:
        from security_runtime.delivery import package_metadata
        # Reuse only an explicitly chosen, fully checksum-verified local bundle.
        # Use when launcher.c has not changed; never silently reuse an old binary.
        package_metadata(launcher_bundle)
        launcher_source = launcher_bundle / '_launcher' / 'security-launcher.exe'
        if not launcher_source.is_file():
            raise ValueError('Verified launcher source is missing')
    subprocess.run([sys.executable, "-m", "PyInstaller", "--noconfirm",
                    *(["--clean"] if work_dir is None else []),
                    "--distpath", str(output), "--workpath", str(work),
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
    if os.name == 'nt':
        # Reviewed native source; the installed launcher no longer duplicates
        # the full Python Runtime. GCC is a build dependency, not a user dependency.
        tiny = bundle / '_launcher/security-launcher.exe'
        tiny.parent.mkdir(exist_ok=True)
        if launcher_source is not None:
            shutil.copy2(launcher_source, tiny)
        else:
            compiler = shutil.which('gcc')
            if not compiler:
                raise ValueError('Windows native launcher requires GCC on the build host')
            subprocess.run([compiler, '-Os', '-s', '-municode', '-Wall', '-Wextra',
                str(root / 'distribution/build/launcher.c'), '-o', str(tiny), '-lbcrypt'], check=True)
    copy_standalone_documents(root, bundle)
    from security_runtime.build_identity import STATE_SCHEMA, git_provenance
    # Local builds may contend with scanners/antivirus. Runtime probes retain
    # their short default; packaging still fails rather than inventing provenance.
    source_commit = git_provenance(root, 'rev-parse', 'HEAD', timeout=30)
    source_dirty = bool(git_provenance(root, 'status', '--porcelain', timeout=30))
    from security_runtime.delivery import CONTRACT, encode, file_digest, package_metadata, package_inventory
    entries = package_inventory(bundle, allow_internal_links=os.name != 'nt')
    files = {r[0]: file_digest(bundle / r[0]) for r in entries
             if stat.S_ISREG(r[1]) and r[0] != 'version.json'}
    links = {r[0]: r[7] for r in entries if stat.S_ISLNK(r[1])}
    metadata = {"name": "AI Security Runtime", "version": __version__,
        "format": "pyinstaller-onedir", "source_commit": source_commit,
        "source_dirty":source_dirty, "experience_contract":"upgrade-and-scan-v1",
        "state_schema": STATE_SCHEMA, "capability_contract": "developer-guidance-v0.3",
        "launcher_contract": CONTRACT, "files": files,
        "managed_engines": ["semgrep", "gitleaks", "trivy"], "on_demand_engines": ["osv-scanner"]}
    if links:
        metadata.update(links=links, bundle_link_contract='internal-relative-v1')
    metadata['build_id'] = hashlib.sha256(encode(metadata)).hexdigest()
    (bundle / "version.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    package_metadata(bundle)
    executable = bundle / ("security-check.exe" if os.name == "nt" else "security-check")
    subprocess.run([str(executable), "--version"], cwd=root, check=True, timeout=30)
    print(bundle)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-dir', type=Path, help='Alternate workspace dist directory; avoid replacing a running bundle')
    parser.add_argument('--work-dir', type=Path, help='Fresh workspace build directory; omit --clean and preserve existing build sites')
    parser.add_argument('--launcher-bundle', type=Path, help='Explicit checksum-verified local bundle supplying an unchanged native launcher')
    args = parser.parse_args()
    main(args.output_dir, args.work_dir, args.launcher_bundle)
