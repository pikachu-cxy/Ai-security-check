"""Fail closed when the wheel omits licensed runtime or first-party rule data."""
from __future__ import annotations

import sys
import zipfile
from email.parser import Parser
from pathlib import Path

import yaml
from security_runtime._version import __version__


def check(wheel: Path, project: Path) -> None:
    with zipfile.ZipFile(wheel) as package:
        names = set(package.namelist())
        data_prefixes = [name.split("/data/share/ai-security-runtime/")[0]
                         for name in names if "/data/share/ai-security-runtime/" in name]
        if len(set(data_prefixes)) != 1:
            raise ValueError("Wheel notice data directory is missing or ambiguous")
        data_prefix = data_prefixes[0] + "/data/share/ai-security-runtime/"
        required = {
            "security_runtime/licensing.py",
            "security_runtime/engines.py",
            "security_runtime/rulepacks.py",
            "security_runtime/python_downloads.json",
            "security_runtime/rules/LICENSE",
            data_prefix + "LICENSE",
            data_prefix + "EULA.md",
            data_prefix + "LICENSING.md",
            data_prefix + "LICENSES/Apache-2.0.txt",
            data_prefix + "THIRD_PARTY_NOTICES.md",
            data_prefix + "SOURCE_OFFER.md",
            data_prefix + "licenses/LICENSE",
        }
        source_package = project / "src" / "security_runtime"
        for engine in ("gitleaks", "trivy", "semgrep"):
            for name in ("LICENSE", "NOTICE"):
                required.add(f"security_runtime/licenses/{engine}/{name}")
        rule_files = sorted((source_package / "rules").rglob("*.yml")) + sorted((source_package / "rules").rglob("*.yaml"))
        if not rule_files:
            raise ValueError("No first-party rules found in source")
        for file in rule_files:
            relative = file.relative_to(source_package).as_posix()
            required.add("security_runtime/" + relative)
            if "security_runtime/" + relative not in names:
                continue
            payload = yaml.safe_load(package.read("security_runtime/" + relative))
            if not isinstance(payload, dict) or not isinstance(payload.get("rules"), list) or not payload["rules"]:
                raise ValueError(f"Invalid bundled rule file: {relative}")
            for rule in payload["rules"]:
                metadata = rule.get("metadata", {})
                provenance = metadata.get("provenance", {})
                if (not str(rule.get("id", "")).startswith("ai-security.")
                        or metadata.get("publisher") != "AI Security Runtime"
                        or metadata.get("license") != "Apache-2.0"
                        or metadata.get("rule_pack") != "ai-security-core"
                        or not metadata.get("rule_version")
                        or not metadata.get("references")
                        or provenance.get("origin") != "FIRST_PARTY"
                        or not provenance.get("author")
                        or not provenance.get("created_at")
                        or provenance.get("license") != "Apache-2.0"
                        or not provenance.get("references")):
                    raise ValueError(f"Rule metadata incomplete: {rule.get('id', relative)}")
        bundled_rules = {name for name in names if name.startswith("security_runtime/rules/")
                         and name.endswith((".yml", ".yaml"))}
        expected_rules = {"security_runtime/" + file.relative_to(source_package).as_posix()
                          for file in rule_files}
        if bundled_rules != expected_rules:
            raise ValueError("Wheel contains stale or missing rule files")
        missing = sorted(required - names)
        if missing:
            raise ValueError("Wheel missing required files: " + ", ".join(missing))
        if any(name.startswith("semgrep/") or "semgrep-rules" in name.lower()
               or name.endswith(("gitleaks.exe", "trivy.exe")) for name in names):
            raise ValueError("Runtime wheel unexpectedly bundles a third-party engine")
        metadata = [name for name in names if name.endswith(".dist-info/METADATA")]
        if len(metadata) != 1:
            raise ValueError("Wheel metadata missing or ambiguous")
        requirements = Parser().parsestr(package.read(metadata[0]).decode("utf-8")).get_all("Requires-Dist", [])
        if any(item.lower().startswith("semgrep") and "extra ==" not in item for item in requirements):
            raise ValueError("Runtime wheel still requires Semgrep")
    print(f"Wheel compliance OK: {wheel.name}, {len(rule_files)} first-party rule file(s)")


if __name__ == "__main__":
    repository = Path(__file__).resolve().parents[1]
    wheels = list((repository / "dist").glob(f"ai_security_runtime-{__version__}-*.whl")) if len(sys.argv) == 1 else [Path(sys.argv[1])]
    if len(wheels) != 1:
        raise SystemExit("Expected exactly one wheel in dist/")
    check(wheels[0], repository)
