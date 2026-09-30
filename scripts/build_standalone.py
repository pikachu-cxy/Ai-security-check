"""Build an inspectable one-directory Runtime without scanner engines."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from security_runtime._version import __version__
from dependency_notices import inventory


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    output = root / "dist" / "standalone"
    subprocess.run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
                    "--distpath", str(output), "--workpath", str(root / "build" / "pyinstaller"),
                    str(root / "distribution" / "build" / "security-check.spec")],
                   cwd=root, check=True)
    bundle = output / "security-check"
    # Editable-install provenance is not needed by importlib.metadata and
    # contains the developer's absolute checkout path.
    for provenance in bundle.rglob("direct_url.json"):
        provenance.unlink()
    for name in ("LICENSE", "THIRD_PARTY_NOTICES.md", "SOURCE_OFFER.md"):
        shutil.copy2(root / name, bundle / name)
    inventory(bundle)
    (bundle / "version.json").write_text(json.dumps({"name": "AI Security Runtime", "version": __version__,
        "format": "pyinstaller-onedir", "managed_engines": ["semgrep", "gitleaks", "trivy"]}, indent=2) + "\n", encoding="utf-8")
    executable = bundle / ("security-check.exe" if os.name == "nt" else "security-check")
    subprocess.run([str(executable), "--version"], cwd=root, check=True, timeout=30)
    print(bundle)


if __name__ == "__main__":
    main()
