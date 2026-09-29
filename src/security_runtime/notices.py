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
    ]
    return "\n".join(lines)
