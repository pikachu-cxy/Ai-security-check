from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Protocol

from .findings import FindingNormalizer
from .models import Finding, RunStatus, ScanContext, ScannerRun, TargetProfile


MAX_OUTPUT = 4_000_000


class ScannerAdapter(Protocol):
    name: str
    def supports(self, profile: TargetProfile, context: ScanContext) -> bool: ...
    def scan(self, context: ScanContext, normalizer: FindingNormalizer) -> tuple[list[Finding], ScannerRun]: ...


def _execute(args: list[str], cwd: str, timeout: int) -> tuple[int, str]:
    # Keep subprocess output bounded even if a scanner ignores quiet flags.
    with tempfile.TemporaryFile() as out:
        proc = subprocess.Popen(args, cwd=cwd, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.DEVNULL)
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
    executable = ""
    timeout = 30

    def supports(self, profile: TargetProfile, context: ScanContext) -> bool:
        return True

    def version(self) -> str:
        binary = shutil.which(self.executable)
        if not binary:
            return ""
        try:
            return _execute([binary, "--version"], ".", 3)[1].strip()[:80]
        except (OSError, TimeoutError, ValueError):
            return "unknown"

    def scan(self, context: ScanContext, normalizer: FindingNormalizer) -> tuple[list[Finding], ScannerRun]:
        start = time.monotonic()
        binary = shutil.which(self.executable)
        if not binary:
            return [], ScannerRun(self.name, "", RunStatus.UNAVAILABLE, 0, error="not installed")
        try:
            findings = self._scan(binary, context, normalizer)
            return findings, ScannerRun(self.name, self.version(), RunStatus.SUCCESS, round((time.monotonic()-start)*1000), len(findings))
        except TimeoutError:
            return [], ScannerRun(self.name, "", RunStatus.TIMEOUT, round((time.monotonic()-start)*1000), error="scanner timed out")
        except ValueError as exc:
            return [], ScannerRun(self.name, "", RunStatus.FAILED, round((time.monotonic()-start)*1000), error=str(exc)[:120])
        except (OSError, KeyError) as exc:
            return [], ScannerRun(self.name, "", RunStatus.FAILED, round((time.monotonic()-start)*1000), error=type(exc).__name__)

    def _scan(self, binary: str, context: ScanContext, normalizer: FindingNormalizer) -> list[Finding]:
        raise NotImplementedError


class SemgrepAdapter(BaseScanner):
    name, executable = "semgrep", "semgrep"
    timeout = 45

    def supports(self, profile: TargetProfile, context: ScanContext) -> bool:
        return bool(profile.languages) and (context.mode == "release" or bool(context.files))

    def _scan(self, binary: str, context: ScanContext, n: FindingNormalizer) -> list[Finding]:
        targets = ["."] if context.mode == "release" else list(context.files)
        # Local rule set: no network fetch and no project code execution.
        rules = str(Path(__file__).parent / "rules" / "core.yml")
        code, output = _execute([binary, "scan", "--config", rules, "--json", "--quiet", "--metrics", "off", "--disable-version-check", *targets], context.root, self.timeout)
        if code not in (0, 1):
            raise ValueError("Semgrep failed")
        data = json.loads(output)
        return [n.make(scanner=self.name, category="command-injection" if "command" in item.get("check_id", "").lower() else "code", title=item.get("extra", {}).get("message", "Code security issue"), description=item.get("extra", {}).get("message", ""), severity={"ERROR": "HIGH", "WARNING": "MEDIUM"}.get(item.get("extra", {}).get("severity"), "LOW"), confidence="HIGH" if "command" in item.get("check_id", "").lower() else "MEDIUM", file_path=item.get("path", ""), line=item.get("start", {}).get("line", 1), evidence=item.get("extra", {}).get("lines", ""), rule_id=item.get("check_id", "")) for item in data.get("results", [])]


class GitleaksAdapter(BaseScanner):
    name, executable = "gitleaks", "gitleaks"
    timeout = 30

    def supports(self, profile: TargetProfile, context: ScanContext) -> bool:
        return context.mode == "release" or bool(context.files)

    def _scan(self, binary: str, context: ScanContext, n: FindingNormalizer) -> list[Finding]:
        # Quick and feature scan changed files only. Gitleaks directory mode is
        # intentionally not used here because it would read the whole project.
        targets = [context.root] if context.mode == "release" else [str(Path(context.root) / f) for f in context.files]
        found = []
        for target in targets:
            with tempfile.TemporaryDirectory() as tmp:
                report = str(Path(tmp) / "findings.json")
                code, _ = _execute([binary, "dir", target, "--report-format", "json", "--report-path", report, "--redact=100", "--no-banner", "--exit-code", "0"], context.root, self.timeout)
                if code != 0:
                    raise ValueError("Gitleaks failed")
                data = json.loads(Path(report).read_text(encoding="utf-8")) if Path(report).exists() else []
                for item in data:
                    found.append(n.make(scanner=self.name, category="secret", title=item.get("Description", "Potential secret"), description="A possible secret was found in source code.", severity="HIGH", confidence="HIGH", file_path=item.get("File", ""), line=item.get("StartLine", 1), evidence="[REDACTED_SECRET]", rule_id=item.get("RuleID", "")))
        return found


class TrivyAdapter(BaseScanner):
    name, executable = "trivy", "trivy"
    timeout = 90

    def supports(self, profile: TargetProfile, context: ScanContext) -> bool:
        return context.mode == "release" or (context.mode == "feature" and any(Path(f).name in {"requirements.txt", "pyproject.toml", "package.json", "package-lock.json", "Dockerfile"} for f in context.files))

    def _scan(self, binary: str, context: ScanContext, n: FindingNormalizer) -> list[Finding]:
        code, output = _execute([binary, "fs", "--format", "json", "--scanners", "vuln,secret,misconfig", "--skip-db-update", "--skip-java-db-update", "--skip-check-update", "--skip-dirs", ".git", "--skip-dirs", ".venv", "--skip-dirs", ".tools", "--skip-dirs", ".security-runtime", context.root], context.root, self.timeout)
        if code != 0:
            raise ValueError("Trivy failed or local vulnerability database unavailable")
        data = json.loads(output)
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
    def __init__(self, adapters: list[ScannerAdapter] | None = None):
        self.adapters = adapters if adapters is not None else [SemgrepAdapter(), GitleaksAdapter(), TrivyAdapter()]

    def plan(self, profile: TargetProfile, context: ScanContext) -> list[ScannerAdapter]:
        return [adapter for adapter in self.adapters if adapter.supports(profile, context)]
