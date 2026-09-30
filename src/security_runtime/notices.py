"""Generate third-party notices from reviewed engine and rule-pack metadata."""
from __future__ import annotations

from .engines import BUILTIN_ENGINES
from .rulepacks import FIRST_PARTY_RULE_PACK


def render_third_party_notices() -> str:
    lines = [
        "# Third-party notices", "",
        "This Runtime installs or invokes the independently licensed scanner engines below. "
        "Engine licenses do not grant rights to third-party rule collections. "
        "The pinned LICENSE and NOTICE texts are preserved in the `security_runtime/licenses/` package directory.",
        "", "| Component | Version | Copyright | License | Homepage | Attribution |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for engine in BUILTIN_ENGINES.values():
        metadata = engine.license_metadata
        attribution = "Retain LICENSE and NOTICE" if metadata.notice_required else "Retain LICENSE"
        if metadata.source_offer_required:
            attribution += "; see SOURCE_OFFER.md for source availability"
        lines.append(f"| {engine.display_name} | {engine.version} | {metadata.copyright} | "
                     f"{metadata.license_spdx} | {engine.homepage} | {attribution} |")
    pack = FIRST_PARTY_RULE_PACK
    lines += [
        "", "## Rule packs", "",
        "| Component | Version | Copyright | License | Source | Attribution |",
        "| --- | --- | --- | --- | --- | --- |",
        f"| {pack.display_name} (`{pack.rule_pack_id}`) | {pack.version} | {pack.copyright} | "
        f"{pack.license} | {pack.source} | First-party authored rules |",
        "",
        "The bundled rule pack is independently authored. Semgrep Community Rules and Semgrep Registry Rules "
        "are not bundled or fetched by default. User-provided rules remain under the user's own license "
        "and are never copied into the managed tool directory.",
        "",
        "Other Python dependency license terms are distributed with their respective installed Python packages.",
        "",
        "## Standalone bootloader and package dependencies",
        "",
        "| Component | Version | Copyright | License | Homepage | Attribution |",
        "| --- | --- | --- | --- | --- | --- |",
        "| PyInstaller bootloader | 6.22.3 | PyInstaller Development Team | GPL-2.0-or-later WITH Bootloader-exception | https://pyinstaller.org | Bootloader exception permits distribution; retain this notice |",
        "| MCP Python SDK | 1.29.0 | MCP contributors | MIT | https://github.com/modelcontextprotocol/python-sdk | Runtime dependency |",
        "| PyYAML | 6.0.3 | PyYAML contributors | MIT | https://pyyaml.org | Runtime dependency |",
        "| Managed CPython | 3.12.12 / 20260211 | Python Software Foundation and distribution contributors | Python-2.0 and included component licenses | https://github.com/astral-sh/python-build-standalone | Separate checksum-pinned download on first Semgrep preparation; preserve upstream license inventory; not bundled |",
        "",
    ]
    return "\n".join(lines)
