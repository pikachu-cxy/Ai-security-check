"""Fail-closed license inventory for packages in the standalone build closure."""
from __future__ import annotations

import importlib.metadata
import re
import shutil
import sys
import hashlib
import json
import urllib.request
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from security_runtime.licensing import LicensePolicy, PYINSTALLER_BOOTLOADER_LICENSE

REVIEWED_LICENSES = {
    "MIT", "MIT-0", "Apache-2.0", "BSD-3-Clause", "PSF-2.0", "PSF", "MPL-2.0",
    "Apache-2.0 OR BSD-2-Clause", "MIT OR Apache-2.0",
    "Apache-2.0 OR BSD-3-Clause",
    "GPLv2-or-later with a special exception which allows to use PyInstaller to build and distribute non-free programs (including commercial ones)",
}
REVIEWED_MISSING_LABELS = {
    # The product owner's Core is governed by the root LICENSE/EULA, not a
    # third-party license grant. This exact label applies only to this package.
    "ai-security-runtime": "LicenseRef-AI-Security-Runtime-Proprietary",
    "pyinstaller-hooks-contrib": "GPL-2.0-or-later (build hooks); Apache-2.0 (bundled runtime hooks)",
    "colorama": "BSD-3-Clause",
}


def inventory(bundle: Path) -> None:
    if not LicensePolicy.can_bundle(PYINSTALLER_BOOTLOADER_LICENSE):
        raise ValueError("PyInstaller bootloader distribution is prohibited")
    queue = [("ai-security-runtime", set()), ("pyinstaller", set())]
    seen: dict[str, set[str]] = {}
    rows = []
    while queue:
        name, extras = queue.pop()
        key = canonicalize_name(name)
        if key in seen and extras.issubset(seen[key]):
            continue
        first = key not in seen
        seen.setdefault(key, set()).update(extras)
        distribution = importlib.metadata.distribution(name)
        license_label = (distribution.metadata.get("License-Expression")
                         or distribution.metadata.get("License")
                         or REVIEWED_MISSING_LABELS.get(key))
        if license_label not in REVIEWED_LICENSES and not (key in REVIEWED_MISSING_LABELS
                                                             and license_label == REVIEWED_MISSING_LABELS[key]):
            raise ValueError(f"Unreviewed standalone dependency license: {key} {license_label!r}")
        texts = [entry for entry in distribution.files or ()
                 if "/licenses/" in str(entry).lower()
                 or str(entry).lower().endswith(("/license", "/license.txt", "/license.md", "/copying"))]
        if not texts:
            raise ValueError(f"Dependency license text missing: {key}")
        destination = bundle / "third_party_licenses" / key
        destination.mkdir(parents=True, exist_ok=True)
        copyrights = []
        for number, entry in enumerate(texts):
            source = Path(distribution.locate_file(entry))
            if not source.is_file() or source.stat().st_size > 2_000_000:
                raise ValueError(f"Dependency license text invalid: {key}")
            shutil.copy2(source, destination / f"{number:02d}-{source.name}")
            copyrights.extend(re.findall(r"(?im)^.*copyright[^\n]*", source.read_text(encoding="utf-8", errors="replace"))[:2])
        homepage = next((value for value in distribution.metadata.get_all("Project-URL", [])
                         if value.lower().startswith("homepage,")), "")
        if first:
            copyright_text = "; ".join(line.strip().replace("|", "\\|") for line in copyrights[:2]) or "See bundled original license texts"
            rows.append((key, distribution.version, copyright_text, license_label, homepage.split(",", 1)[-1].strip()))
        for declaration in distribution.requires or ():
            requirement = Requirement(declaration)
            if requirement.marker is None or any(requirement.marker.evaluate({"extra": extra}) for extra in {"", *seen[key]}):
                queue.append((requirement.name, set(requirement.extras)))
    python_license = next((candidate for candidate in (Path(sys.base_prefix) / "LICENSE.txt", Path(sys.base_prefix) / "LICENSE")
                           if candidate.is_file()), None)
    python_directory = bundle / "third_party_licenses" / "cpython"
    python_directory.mkdir(parents=True, exist_ok=True)
    python_version = ".".join(map(str, sys.version_info[:3]))
    source_url = f"https://raw.githubusercontent.com/python/cpython/v{python_version}/LICENSE"
    if python_license is not None:
        license_bytes = python_license.read_bytes()
        provenance = "Installed CPython distribution; " + source_url
    else:
        # setup-python's Unix toolcache omits the top-level license. Fetch the
        # original text for the exact interpreter tag; a failed fetch blocks build.
        with urllib.request.urlopen(source_url, timeout=60) as response:
            license_bytes = response.read(200_000)
        provenance = source_url
    if b"PYTHON SOFTWARE FOUNDATION LICENSE" not in license_bytes:
        raise ValueError("CPython original license text is invalid")
    (python_directory / "LICENSE.txt").write_bytes(license_bytes)
    (python_directory / "provenance.json").write_text(json.dumps({
        "version": python_version, "source": provenance,
        "sha256": hashlib.sha256(license_bytes).hexdigest()}, indent=2) + "\n", encoding="utf-8")
    rows.append(("CPython", ".".join(map(str, sys.version_info[:3])), "Python Software Foundation and contributors",
                 "Python-2.0", "https://www.python.org"))
    notice = bundle / "THIRD_PARTY_NOTICES.md"
    appendix = ["", "## Standalone dependency inventory", "",
                "This inventory is generated from the complete installed dependency closure used for this build. "
                "License texts are in `third_party_licenses/`.", "",
                "| Component | Version | Copyright | License | Homepage | Attribution |", "| --- | --- | --- | --- | --- | --- |"]
    appendix += [f"| {key} | {version} | {copyright_text} | {license_label} | {homepage} | Retain original license texts |"
                 for key, version, copyright_text, license_label, homepage in sorted(rows)]
    notice.write_text(notice.read_text(encoding="utf-8") + "\n".join(appendix) + "\n", encoding="utf-8")
    source_offer = bundle / "SOURCE_OFFER.md"
    source_offer.write_text(source_offer.read_text(encoding="utf-8") + "\n## Bundled dependency source locations\n\n" +
                            "\n".join(f"- {key} {version}: https://pypi.org/project/{key}/{version}/#files"
                                      for key, version, *_ in sorted(rows) if key not in {"CPython", "ai-security-runtime"}) +
                            f"\n- CPython {python_version}: https://github.com/python/cpython/tree/v{python_version}\n",
                            encoding="utf-8")
