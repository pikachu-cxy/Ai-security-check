"""Fail closed when the wheel omits licensed runtime or upstream rule data."""
from __future__ import annotations

import sys
import zipfile
from email.parser import Parser
from pathlib import Path

import yaml
from security_runtime._version import __version__


def check_python_modules(names: set[str], source_package: Path) -> None:
    expected = {'security_runtime/' + path.relative_to(source_package).as_posix()
                for path in source_package.rglob('*.py')}
    bundled = {name for name in names if name.startswith('security_runtime/') and name.endswith('.py')}
    if bundled != expected:
        raise ValueError('Wheel contains stale or missing Python modules: ' +
                         ', '.join(sorted(bundled ^ expected)))


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
            "security_runtime/rule_catalog.py",
            "security_runtime/rule_coverage.py",
            "security_runtime/rule_program.py",
            "security_runtime/rule_ground_truth.py",
            "security_runtime/opengrep_rules.json",
            "security_runtime/osv.py",
            "security_runtime/dependency_fallback.py",
            "security_runtime/triage.py",
            "security_runtime/triage_models.py",
            "security_runtime/triage_evidence.py",
            "security_runtime/triage_providers.py",
            "security_runtime/security_summary.py",
            "security_runtime/tasks/triage.py",
            "security_runtime/tasks/fix.py",
            "security_runtime/equivalence.py",
            "security_runtime/verification.py",
            "security_runtime/verification_policy.py",
            "security_runtime/guidance/host_guidance.py",
            "security_runtime/hook_runtime.py",
            "security_runtime/hook_state.py",
            "security_runtime/baseline_seed.py",
            "security_runtime/hook_adapters.py",
            "security_runtime/rules/README.md",
            "security_runtime/python_downloads.json",
            "security_runtime/rules/LICENSE",
            data_prefix + "LICENSE",
            data_prefix + "EULA.md",
            data_prefix + "LICENSING.md",
            data_prefix + "LICENSES/Apache-2.0.txt",
            data_prefix + "THIRD_PARTY_NOTICES.md",
            data_prefix + "SOURCE_OFFER.md",
        }
        source_package = project / "src" / "security_runtime"
        check_python_modules(names, source_package)
        # Compare the descriptor and catalog as well as rule filenames. A stale
        # wheel must fail even if its old metadata remains internally valid.
        for relative in ('rulepacks.py', 'opengrep_rules.json', 'rules/LICENSE', 'rules/README.md'):
            name = 'security_runtime/' + relative
            if name in names and package.read(name) != (source_package / relative).read_bytes():
                raise ValueError(f'Wheel rule metadata differs from source: {relative}')
        for engine in ("gitleaks", "trivy", "opengrep", "semgrep", "osv-scanner"):
            for name in ("LICENSE", "NOTICE"):
                required.add(f"security_runtime/licenses/{engine}/{name}")
        rule_files = sorted((source_package / "rules").rglob("*.yml")) + sorted((source_package / "rules").rglob("*.yaml"))
        if not rule_files:
            raise ValueError("No upstream rules found in source")
        for file in rule_files:
            relative = file.relative_to(source_package).as_posix()
            required.add("security_runtime/" + relative)
            if "security_runtime/" + relative not in names:
                continue
            if package.read('security_runtime/' + relative) != file.read_bytes():
                raise ValueError(f'Wheel rule content differs from source: {relative}')
            payload = yaml.safe_load(package.read("security_runtime/" + relative))
            if not isinstance(payload, dict) or not isinstance(payload.get("rules"), list) or not payload["rules"]:
                raise ValueError(f"Invalid bundled rule file: {relative}")
        bundled_rules = {name for name in names if name.startswith("security_runtime/rules/")
                         and name.endswith((".yml", ".yaml"))}
        expected_rules = {"security_runtime/" + file.relative_to(source_package).as_posix()
                          for file in rule_files}
        if bundled_rules != expected_rules:
            raise ValueError("Wheel contains stale or missing rule files")
        # Program metadata is integrity-critical, not optional documentation.
        from security_runtime.rulepacks import RulePackManager
        from security_runtime.rule_program import validate_manifest
        import json
        manifest_name = 'security_runtime/rules/capabilities.json'
        if manifest_name in names:
            source_manifest = source_package / 'rules/capabilities.json'
            if package.read(manifest_name) != source_manifest.read_bytes():
                raise ValueError('Wheel Rule Program manifest differs from source')
            validate_manifest(json.loads(package.read(manifest_name)), RulePackManager().resolve().catalog)
        missing = sorted(required - names)
        if missing:
            raise ValueError("Wheel missing required files: " + ", ".join(missing))
        if any(name.startswith("semgrep/") or "semgrep-rules" in name.lower()
               or name.endswith(("opengrep.exe", "gitleaks.exe", "trivy.exe", "osv-scanner.exe")) for name in names):
            raise ValueError("Runtime wheel unexpectedly bundles a third-party engine")
        metadata = [name for name in names if name.endswith(".dist-info/METADATA")]
        if len(metadata) != 1:
            raise ValueError("Wheel metadata missing or ambiguous")
        requirements = Parser().parsestr(package.read(metadata[0]).decode("utf-8")).get_all("Requires-Dist", [])
        if any(item.lower().startswith("semgrep") and "extra ==" not in item for item in requirements):
            raise ValueError("Runtime wheel still requires Semgrep")
    print(f"Wheel compliance OK: {wheel.name}, {len(rule_files)} upstream rule file(s)")


if __name__ == "__main__":
    repository = Path(__file__).resolve().parents[2]
    wheels = list((repository / "dist").glob(f"ai_security_runtime-{__version__}-*.whl")) if len(sys.argv) == 1 else [Path(sys.argv[1])]
    if len(wheels) != 1:
        raise SystemExit("Expected exactly one wheel in dist/")
    check(wheels[0], repository)
