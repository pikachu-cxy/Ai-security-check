from __future__ import annotations

import json
import importlib.metadata
import logging
import subprocess
import tempfile
import time
import shutil
from contextlib import contextmanager
from pathlib import Path
from typing import Protocol

from .findings import FindingNormalizer
from .models import Finding, RunStatus, ScanContext, ScannerRun, TargetProfile
from .capabilities import Capability
from .toolchain import ToolManager, ToolStatus, tool_environment, external_tool_loader
from .plugin_api import SCANNER_ENTRY_POINT, ScannerPluginMetadata
from .rulepacks import RulePackManager
from .sast import SASTRequest, SemgrepEngineProvider
from .target import TargetDetector


MAX_OUTPUT = 4_000_000
logger = logging.getLogger(__name__)


@contextmanager
def _snapshot(context: ScanContext):
    """Directory-based engines receive only validated, scoped project files."""
    root = Path(context.root)
    files = TargetDetector().detect(root, list(dict.fromkeys((*context.files, *context.context_files)))).files
    with tempfile.TemporaryDirectory(prefix="security-runtime-scope-") as temporary:
        scoped = Path(temporary)
        for name in files:
            destination = scoped / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / name, destination)
        yield scoped


class ScannerAdapter(Protocol):
    name: str
    scanner_id: str
    display_name: str
    capabilities: frozenset[Capability]
    supported_languages: frozenset[str]
    supported_ecosystems: frozenset[str]
    filter_changed_lines: bool
    def required_engines(self) -> tuple[str, ...]: ...
    def supports(self, profile: TargetProfile, context: ScanContext) -> bool: ...
    def scan(self, context: ScanContext, normalizer: FindingNormalizer) -> tuple[list[Finding], ScannerRun]: ...
    def normalize(self, raw: object, normalizer: FindingNormalizer) -> list[Finding]: ...


def _execute(args: list[str], cwd: str, timeout: int) -> tuple[int, str]:
    # Keep subprocess output bounded even if a scanner ignores quiet flags.
    with tempfile.TemporaryFile() as out:
        with external_tool_loader():
            proc = subprocess.Popen(args, cwd=cwd, stdin=subprocess.DEVNULL, stdout=out,
                                    stderr=subprocess.DEVNULL, env=tool_environment(Path(args[0])))
        deadline = time.monotonic() + timeout
        try:
            while proc.poll() is None:
                if out.seek(0, 2) > MAX_OUTPUT:
                    raise ValueError("scanner output limit exceeded")
                if time.monotonic() >= deadline:
                    raise TimeoutError("scanner timed out")
                time.sleep(0.05)
            if out.seek(0, 2) > MAX_OUTPUT:
                raise ValueError("scanner output limit exceeded")
        except (TimeoutError, ValueError):
            proc.kill()
            proc.wait(timeout=5)
            raise
        out.seek(0)
        return proc.returncode, out.read(MAX_OUTPUT).decode("utf-8", errors="replace")


class BaseScanner:
    name = ""
    scanner_id = ""
    display_name = ""
    capabilities: frozenset[Capability] = frozenset()
    supported_languages: frozenset[str] = frozenset()
    supported_ecosystems: frozenset[str] = frozenset()
    filter_changed_lines = False
    timeout = 30

    def __init__(self, tool_manager: ToolManager | None = None):
        self.tool_manager = tool_manager or ToolManager()

    def required_engines(self) -> tuple[str, ...]:
        return (self.scanner_id,)

    def supports(self, profile: TargetProfile, context: ScanContext) -> bool:
        return True

    def version(self) -> str:
        return self.tool_manager.resolve(self.scanner_id).version

    def scan(self, context: ScanContext, normalizer: FindingNormalizer) -> tuple[list[Finding], ScannerRun]:
        start = time.monotonic()
        try:
            resolved = self.tool_manager.ensure(self.scanner_id)
        except Exception as exc:
            logger.warning("scanner_engine_unavailable scanner=%s reason=%s", self.scanner_id, type(exc).__name__)
            return [], ScannerRun(self.name, "", RunStatus.UNAVAILABLE, round((time.monotonic()-start)*1000), error=type(exc).__name__)
        if resolved.status != ToolStatus.READY:
            return [], ScannerRun(self.name, "", RunStatus.UNAVAILABLE, round((time.monotonic()-start)*1000), error=f"{resolved.status}: {resolved.detail}"[:160])
        try:
            if self._prepare(resolved.path) != ToolStatus.READY:
                return [], ScannerRun(self.name, resolved.version, RunStatus.UNAVAILABLE, round((time.monotonic()-start)*1000), error="engine data unavailable")
            findings = self._scan(resolved.path, context, normalizer)
            return findings, ScannerRun(self.name, resolved.version, RunStatus.SUCCESS, round((time.monotonic()-start)*1000), len(findings))
        except TimeoutError:
            return [], ScannerRun(self.name, "", RunStatus.TIMEOUT, round((time.monotonic()-start)*1000), error="scanner timed out")
        except ValueError as exc:
            return [], ScannerRun(self.name, "", RunStatus.FAILED, round((time.monotonic()-start)*1000), error=str(exc)[:120])
        except (OSError, KeyError) as exc:
            return [], ScannerRun(self.name, "", RunStatus.FAILED, round((time.monotonic()-start)*1000), error=type(exc).__name__)

    def _scan(self, binary: str, context: ScanContext, normalizer: FindingNormalizer) -> list[Finding]:
        raise NotImplementedError

    def _prepare(self, binary: str) -> ToolStatus:
        return ToolStatus.READY


class PatternSASTScanner(BaseScanner):
    """Local rule-pack scanner whose execution engine is replaceable."""

    capabilities = frozenset({Capability.CODE_SAST})
    supported_languages = frozenset({"Python", "JavaScript", "TypeScript", "Java", "Go", "PHP"})
    filter_changed_lines = True
    timeout = 45

    def __init__(self, tool_manager: ToolManager | None = None, *, rule_packs: RulePackManager | None = None, engine_provider=None):
        super().__init__(tool_manager)
        self.rule_packs = rule_packs or RulePackManager()
        self.engine_provider = engine_provider or SemgrepEngineProvider()

    def supports(self, profile: TargetProfile, context: ScanContext) -> bool:
        return bool(profile.languages) and (context.mode == "release" or bool(context.files))

    def _scan(self, binary: str, context: ScanContext, n: FindingNormalizer) -> list[Finding]:
        targets = list(context.files)
        rule_pack = self.rule_packs.resolve(user_path=Path(context.rules_path) if context.rules_path else None)
        findings = []
        # Bound command-line length on Windows as well as scanner output.
        for offset in range(0, len(targets), 40):
            request = SASTRequest(Path(context.root), rule_pack, tuple(targets[offset:offset + 40]))
            code, output = _execute(self.engine_provider.command(binary, request), context.root, self.timeout)
            if code not in (0, 1):
                raise ValueError("Semgrep failed")
            findings.extend(self.normalize(json.loads(output), n))
        for finding in findings:
            finding.technical_details.update({"engine": self.engine_provider.engine_id,
                                              "rule_pack": rule_pack.descriptor.rule_pack_id,
                                              "rule_pack_version": rule_pack.descriptor.version})
            rule_id = finding.technical_details.get("rule_id", "")
            if rule_pack.descriptor.rule_pack_id == "ai-security-core" and "ai-security." in rule_id:
                finding.technical_details["rule_id"] = "ai-security." + rule_id.split("ai-security.", 1)[1]
        return findings

    def normalize(self, data: object, n: FindingNormalizer) -> list[Finding]:
        assert isinstance(data, dict)
        return [n.make(scanner=self.name, category="command-injection" if "command" in item.get("check_id", "").lower() else "code", title=item.get("extra", {}).get("message", "Code security issue"), description=item.get("extra", {}).get("message", ""), severity={"ERROR": "HIGH", "WARNING": "MEDIUM"}.get(item.get("extra", {}).get("severity"), "LOW"), confidence="HIGH" if "command" in item.get("check_id", "").lower() else "MEDIUM", file_path=item.get("path", ""), line=item.get("start", {}).get("line", 1), evidence=item.get("extra", {}).get("lines", ""), rule_id=item.get("check_id", "")) for item in data.get("results", [])]


class SemgrepAdapter(PatternSASTScanner):
    name = scanner_id = "semgrep"
    display_name = "Semgrep"


class GitleaksAdapter(BaseScanner):
    name = scanner_id = "gitleaks"
    display_name = "Gitleaks"
    capabilities = frozenset({Capability.SECRET_SCAN})
    filter_changed_lines = True
    timeout = 30

    def supports(self, profile: TargetProfile, context: ScanContext) -> bool:
        return context.mode == "release" or bool(context.files)

    def _scan(self, binary: str, context: ScanContext, n: FindingNormalizer) -> list[Finding]:
        # Quick and feature scan changed files only. Gitleaks directory mode is
        # intentionally not used here because it would read the whole project.
        if context.mode == "release":
            with _snapshot(context) as scoped:
                return self._scan_targets(binary, [str(scoped)], context, n, snapshot_root=scoped)
        targets = [str(Path(context.root) / f) for f in context.files]
        return self._scan_targets(binary, targets, context, n)

    def _scan_targets(self, binary, targets, context, n, snapshot_root=None):
        found = []
        for target in targets:
            with tempfile.TemporaryDirectory() as tmp:
                report = str(Path(tmp) / "findings.json")
                code, _ = _execute([binary, "dir", target, "--report-format", "json", "--report-path", report, "--redact=100", "--no-banner", "--exit-code", "0"], context.root, self.timeout)
                if code != 0:
                    raise ValueError("Gitleaks failed")
                data = json.loads(Path(report).read_text(encoding="utf-8")) if Path(report).exists() else []
                if snapshot_root is not None:
                    for item in data:
                        path = Path(item.get("File", ""))
                        if path.is_absolute():
                            item["File"] = path.resolve().relative_to(snapshot_root.resolve()).as_posix()
                found.extend(self.normalize(data, n))
        return found

    def normalize(self, data: object, n: FindingNormalizer) -> list[Finding]:
        assert isinstance(data, list)
        return [n.make(scanner=self.name, category="secret", title=item.get("Description", "Potential secret"), description="A possible secret was found in source code.", severity="HIGH", confidence="HIGH", file_path=item.get("File", ""), line=item.get("StartLine", 1), evidence="[REDACTED_SECRET]", rule_id=item.get("RuleID", "")) for item in data]


class TrivyAdapter(BaseScanner):
    name = scanner_id = "trivy"
    display_name = "Trivy"
    capabilities = frozenset({Capability.DEPENDENCY_VULN, Capability.SECRET_SCAN, Capability.IAC_MISCONFIG, Capability.CONTAINER_VULN, Capability.LICENSE_SCAN, Capability.SBOM})
    supported_ecosystems = frozenset({"pip", "npm", "yarn", "pnpm", "maven", "go"})
    timeout = 90

    def _prepare(self, binary: str) -> ToolStatus:
        return self.tool_manager.prepare_trivy_database(binary)

    def supports(self, profile: TargetProfile, context: ScanContext) -> bool:
        relevant = any(Path(f).name in {"requirements.txt", "pyproject.toml", "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "pom.xml", "build.gradle", "go.mod", "Dockerfile"} or f.endswith((".tf", ".yaml", ".yml")) for f in context.files)
        return context.mode in {"feature", "release"} and relevant

    def _scan(self, binary: str, context: ScanContext, n: FindingNormalizer) -> list[Finding]:
        with _snapshot(context) as scoped:
            code, output = _execute([binary, "fs", "--format", "json", "--scanners", "vuln,secret,misconfig", "--cache-dir", str(self.tool_manager.trivy_cache_dir()), "--skip-db-update", "--skip-java-db-update", "--skip-check-update", str(scoped)], str(scoped), self.timeout)
            if code != 0:
                raise ValueError("Trivy failed or local vulnerability database unavailable")
            data = json.loads(output)
            for result in data.get("Results", []):
                target = Path(result.get("Target", ""))
                if target.is_absolute():
                    result["Target"] = target.resolve().relative_to(scoped.resolve()).as_posix()
            return self.normalize(data, n)

    def normalize(self, data: object, n: FindingNormalizer) -> list[Finding]:
        assert isinstance(data, dict)
        found = []
        for result in data.get("Results", []):
            for item in result.get("Vulnerabilities", []):
                found.append(n.make(scanner=self.name, category="dependency", title=item.get("Title") or "Vulnerable dependency", description=item.get("Title") or "Dependency vulnerability", severity=item.get("Severity", "MEDIUM"), confidence="MEDIUM", file_path=result.get("Target", ""), line=1, rule_id=item.get("VulnerabilityID", "")))
            for item in result.get("Misconfigurations", []):
                found.append(n.make(scanner=self.name, category="configuration", title=item.get("Title", "Configuration issue"), description=item.get("Description", ""), severity=item.get("Severity", "MEDIUM"), confidence="MEDIUM", file_path=result.get("Target", ""), line=item.get("CauseMetadata", {}).get("StartLine", 1), rule_id=item.get("ID", "")))
            for item in result.get("Secrets", []):
                found.append(n.make(scanner=self.name, category="secret", title=item.get("Title", "Potential secret"), description="A possible secret was found in source code.", severity=item.get("Severity", "HIGH"), confidence="HIGH", file_path=result.get("Target", ""), line=item.get("StartLine", 1), evidence="[REDACTED_SECRET]", rule_id=item.get("RuleID", "")))
        return found


class ScannerRegistry:
    def __init__(self, adapters: list[ScannerAdapter] | None = None, tool_manager: ToolManager | None = None):
        self.tool_manager = tool_manager or ToolManager()
        self.adapters = adapters if adapters is not None else [SemgrepAdapter(self.tool_manager), GitleaksAdapter(self.tool_manager), TrivyAdapter(self.tool_manager), *self._discover_plugins()]

    def _discover_plugins(self) -> list[ScannerAdapter]:
        plugins = []
        used_ids = {"semgrep", "gitleaks", "trivy"}
        for entry in importlib.metadata.entry_points(group=SCANNER_ENTRY_POINT):
            try:
                loaded = entry.load()
                scanner = loaded() if callable(loaded) else loaded
                metadata = getattr(scanner, "metadata", None)
                if not isinstance(metadata, ScannerPluginMetadata):
                    raise ValueError("scanner plugin metadata is missing")
                if metadata.scanner_id != scanner.scanner_id or scanner.scanner_id in used_ids:
                    raise ValueError("scanner plugin id is duplicate or inconsistent")
                if not all(hasattr(scanner, name) for name in ("display_name", "capabilities", "required_engines", "supports", "scan", "normalize")):
                    raise ValueError("scanner plugin interface is incomplete")
                if tuple(scanner.required_engines()) != metadata.required_engines:
                    raise ValueError("scanner plugin engine metadata does not match")
                plugins.append(scanner)
                used_ids.add(scanner.scanner_id)
            except Exception as exc:
                logger.warning("scanner_plugin_skipped name=%s reason=%s", entry.name, type(exc).__name__)
                continue
        return plugins

    def plan(self, profile: TargetProfile, context: ScanContext) -> list[ScannerAdapter]:
        return [adapter for adapter in self.adapters if adapter.supports(profile, context)]
