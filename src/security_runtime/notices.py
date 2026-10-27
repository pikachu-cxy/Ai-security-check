"""Generate third-party notices from reviewed engine and rule-pack metadata."""
from __future__ import annotations

from .engines import BUILTIN_ENGINES
from .rulepacks import DEFAULT_RULE_PACK
from .dataflow import PACK_ID, VERSION
from .go_sql import PACK_ID as GO_SQL_PACK_ID, VERSION as GO_SQL_VERSION


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
    pack = DEFAULT_RULE_PACK
    lines += [
        "", "## Rule packs", "",
        "| Component | Version | Copyright | License | Source | Attribution |",
        "| --- | --- | --- | --- | --- | --- |",
        f"| {pack.display_name} (`{pack.rule_pack_id}`) | {pack.version} | {pack.copyright} | "
        f"{pack.license} | {pack.source} | Upstream LICENSE retained; free personal distribution; Commons Clause restrictions apply |",
        f"| Bounded Java/Python dataflow (`{PACK_ID}`) | {VERSION} | AI Security Runtime contributors | Apache-2.0 | bundled local package | First-party authored; SQL, resolved cross-file Java/Python paths and exact Python io/codecs stream opens by default; other intrafile paths/command candidates experimental |",
        f"| Bounded Go SQL dataflow (`{GO_SQL_PACK_ID}`) | {GO_SQL_VERSION} | AI Security Runtime contributors | Apache-2.0 | bundled local package | First-party authored; same-package net/http to database/sql, at most two resolved call edges |",
        "",
        "The bundled opengrep-rules pack is an archived fork of semgrep-rules, pinned by commit. "
        "Its LGPL-2.1 plus Commons Clause license is distinct from the engine license. "
        "It is not represented as permissively licensed or unrestricted for commercial/SaaS redistribution. "
        "User-provided rules remain under the user's own license "
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
        "| packaging | 26.3 | packaging contributors | Apache-2.0 OR BSD-2-Clause | https://packaging.pypa.io | Python dependency declaration parsing; original license texts included in standalone inventory |",
        "| javalang | 0.13.0 | Copyright (c) 2013 Christopher Thunes | MIT | https://github.com/c2nes/javalang | Java 8 parser; original LICENSE retained |",
        "| six | 1.17.0 | Copyright (c) 2010-2024 Benjamin Peterson | MIT | https://github.com/benjaminp/six | Parser dependency; original LICENSE retained |",
        "| Managed CPython | 3.12.12 / 20260211 | Python Software Foundation and distribution contributors | Python-2.0 and included component licenses | https://github.com/astral-sh/python-build-standalone | Separate checksum-pinned download on first Semgrep preparation; preserve upstream license inventory; not bundled |",
        "",
    ]
    return "\n".join(lines)
