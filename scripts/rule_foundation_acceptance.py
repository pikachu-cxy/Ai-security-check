"""Real offline quick/Hook/recheck observations on disposable Java/JS/TS code.

This exercises scanner execution and finding disappearance, not Desktop Hook
dispatch, functional compatibility, repair authorization, or Episode closure.
Synthetic source is created only in an isolated temporary Git repository. The
report contains bounded scanner metadata and hashes, never source/evidence or
absolute workspace paths.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import statistics
import subprocess
import tempfile
import time

from security_runtime.hook_adapters import CodexHookAdapter
from security_runtime.hook_runtime import HookCoordinator
from security_runtime.hook_state import HookStateStore
from security_runtime.host_events import EventKind
from security_runtime.rulepacks import RulePackManager
from security_runtime.runtime import SecurityRuntime
from security_runtime.scanners import GitleaksAdapter, ScannerRegistry, SemgrepAdapter
from security_runtime.storage import SQLiteStore
from security_runtime.toolchain import ToolManager, ToolStatus


CASES = (
    ("java", "Sample.java", "ai-security.java.spring-named-jdbc"),
    ("javascript", "sample.js", "ai-security.javascript.command-injection"),
    ("typescript", "sample.ts", "ai-security.javascript.ssrf"),
)


@contextmanager
def isolated_state(directory):
    values = {"SECURITY_RUNTIME_OFFLINE": "1", "SECURITY_RUNTIME_STATE_DIR": str(directory),
              "PYTHONUTF8": "1"}
    previous = {key: os.environ.get(key) for key in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def source(language, risky, phase):
    """Independent synthetic inputs. The code is scanned, never executed."""
    marker = "// Isolated rule acceptance phase: " + phase + "\n"
    if language == "java":
        operation = (
            'db.queryForList("SELECT id FROM users WHERE name=\'" + name + "\'", '
            'java.util.Map.of());' if risky else
            'db.queryForList("SELECT id FROM users WHERE name=:name", '
            'java.util.Map.of("name", name));'
        )
        return marker + (
            "class Sample {\n"
            " void review(jakarta.servlet.http.HttpServletRequest request,\n"
            "   org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate db) {\n"
            '  String name = request.getParameter("name");\n'
            "  " + operation + "\n }\n}\n"
        )
    if language == "javascript":
        operation = ('cp.exec("echo " + req.query.value);' if risky else
                     'cp.execFile("/usr/bin/printf", ["%s", req.query.value], {shell: false});')
        return marker + (
            'const express = require("express");\n'
            'const cp = require("node:child_process");\n'
            "const app = express();\n"
            'app.get("/synthetic", (req, res) => {\n  ' + operation + "\n});\n"
        )
    operation = ('await fetch(req.query.url);' if risky else
                 'await fetch("https://fixed.example/status");')
    return marker + (
        'import express from "express";\n'
        "const app = express();\n"
        'app.get("/synthetic", async (req: any, res: any) => {\n  ' + operation + "\n});\n"
    )


def digest(file):
    return hashlib.sha256(file.read_bytes()).hexdigest()


def scan_projection(result):
    rules = result.rule_coverage
    return {
        "scan_id": result.scan_id,
        "mode": result.mode,
        "status": result.status,
        "coverage": result.coverage,
        "execution_state": result.execution_state,
        "capabilities": dict(result.capability_results),
        "duration_ms": result.duration_ms,
        "scope_files": list(rules.get("scope_files", [])),
        "selected_rules": rules.get("total_selected", 0),
        "executed_rules": rules.get("total_executed", 0),
        "rule_pack_version": rules.get("rule_pack_version"),
        "rule_pack_checksum": rules.get("rule_pack_checksum"),
        "per_language": {
            language: {key: row.get(key) for key in (
                "status", "selected_rules", "executed_rules", "target_files", "scanned_files",
                "selected_rule_ids", "executed_rule_ids")}
            for language, row in rules.get("per_language", {}).items()
        },
        "finding_count": len(result.findings),
        "findings": [{"finding_id": row.id, "rule_id": row.technical_details.get("rule_id"),
                      "severity": row.severity, "confidence": row.confidence,
                      "file": row.file_path, "line_start": row.line_start,
                      "line_end": row.line_end} for row in result.findings],
        "scanner_runs": [{key: getattr(run, key) for key in (
            "scanner", "version", "status", "duration_ms", "finding_count", "error_code",
            "coverage_contract")} for run in result.scanner_runs],
    }


class RecordingRuntime(SecurityRuntime):
    """Observe real returns without retaining or substituting scanner proof."""
    def __init__(self, registry, store):
        super().__init__(registry, store)
        self.observations = []

    def scan(self, *args, **kwargs):
        result = super().scan(*args, **kwargs)
        self.observations.append(scan_projection(result))
        return result


def git(root, hooks, *args):
    subprocess.run(["git", "-c", "core.hooksPath=" + str(hooks), "-c", "commit.gpgsign=false",
                    "-C", str(root), *args], check=True, stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)


def validate_scan(row, language, file, rule_id, risky):
    failures = []
    if row["coverage"] != "FULL" or row["execution_state"] != "EXECUTED":
        failures.append("SCANNER_COVERAGE_INCOMPLETE")
    if row["scope_files"] != [file]:
        failures.append("UNEXPECTED_FILE_SCOPE")
    per_language = row["per_language"].get(language, {})
    if (not row["selected_rules"] or row["executed_rules"] != row["selected_rules"]
            or rule_id not in per_language.get("executed_rule_ids", [])):
        failures.append("EXPECTED_RULE_EXECUTION_UNPROVEN")
    found = any(finding["rule_id"] == rule_id for finding in row["findings"])
    if found != risky or not risky and row["finding_count"]:
        failures.append("FINDING_EXPECTATION_MISMATCH")
    if any(run["status"] != "SUCCESS" for run in row["scanner_runs"]):
        failures.append("PROVIDER_DID_NOT_SUCCEED")
    return failures


def latency(values):
    if not values:
        return {"samples": 0}
    ordered = sorted(values)
    return {"samples": len(values), "minimum_ms": ordered[0],
            "median_ms": round(statistics.median(values), 3),
            "p95_ms": ordered[max(0, math.ceil(len(ordered) * .95) - 1)],
            "maximum_ms": ordered[-1]}


def run_acceptance():
    report = {
        "schema": "rule-foundation-acceptance-v1", "status": "RUNNING",
        "input_kind": "ISOLATED_SYNTHETIC_GIT_PROJECTS", "scanner_results_mocked": False,
        "model_called": False, "business_source_modified": False,
        "host_configuration_modified": False, "desktop_hook_acceptance": "PENDING_USER_TRIAL",
        "functional_tests": "NOT_RUN", "repair_episode_closed": False,
        "interpretation": "Real scanner observations and original-rule recheck only; no security-safety claim.",
        "cases": [], "failures": [],
    }
    with tempfile.TemporaryDirectory(prefix="runtime-rule-foundation-") as temporary:
        directory = Path(temporary).resolve()
        with isolated_state(directory / "state"):
            manager = ToolManager()
            prepared = {name: manager.resolve(name) for name in ("semgrep", "gitleaks")}
            report["tools"] = {name: {"version": tool.version, "status": str(tool.status)}
                               for name, tool in prepared.items()}
            if any(tool.status != ToolStatus.READY for tool in prepared.values()):
                report.update(status="BLOCKED_ENVIRONMENT", failures=["PREPARED_OFFLINE_ENGINES_REQUIRED"])
                return report
            pack = RulePackManager().resolve()
            report["rule_pack"] = {"version": pack.descriptor.version, "checksum": pack.checksum,
                                   "catalog_rules": len(pack.catalog)}
            report["timing_scope"] = (
                "Sequential source Runtime calls with preinstalled offline engines and process-local "
                "preparation reuse; first call is not a fresh installation or a Desktop latency claim."
            )
            for language, filename, expected_rule in CASES:
                root = directory / (language + " synthetic project")
                root.mkdir()
                hooks = directory / (language + " empty hooks")
                hooks.mkdir()
                file = root / filename
                file.write_text(source(language, False, "initial-safe-head"), encoding="utf-8")
                git(root, hooks, "init")
                git(root, hooks, "config", "user.name", "Synthetic Fixture")
                git(root, hooks, "config", "user.email", "fixture@example.invalid")
                git(root, hooks, "add", filename)
                git(root, hooks, "commit", "-m", "safe isolated fixture")
                state = directory / "state" / language
                registry = ScannerRegistry([SemgrepAdapter(manager), GitleaksAdapter(manager)],
                                           tool_manager=manager, fallback_adapters=[])
                runtime = RecordingRuntime(registry, SQLiteStore(state / "scans.db"))
                coordinator = HookCoordinator(runtime, HookStateStore(state / "hooks"), cooldown_ms=0)
                session = "synthetic-rule-foundation-" + language
                baseline = coordinator.handle_lifecycle(EventKind.SESSION_START, root, "codex", session)
                case = {"language": language, "file": filename, "expected_rule_id": expected_rule,
                        "baseline_status": baseline["status"],
                        "baseline_scanner_run": baseline["execution"]["scanner_run"], "steps": []}
                report["cases"].append(case)
                for cycle in (1, 2):
                    for phase, risky in (("safe_before", False), ("risk", True), ("safe_after", False)):
                        label = str(cycle) + "-" + phase
                        file.write_text(source(language, risky, label), encoding="utf-8")
                        before = digest(file)
                        started = time.perf_counter()
                        quick = scan_projection(runtime.scan(root, "quick"))
                        quick["wall_ms"] = round((time.perf_counter() - started) * 1000, 3)
                        quick["source_unchanged_by_scan"] = digest(file) == before
                        failures = validate_scan(quick, language, filename, expected_rule, risky)
                        calls = len(runtime.observations)
                        started = time.perf_counter()
                        hooked = coordinator.handle_lifecycle(EventKind.WORKSPACE_ACTIVITY, root, "codex", session)
                        hook_wall = round((time.perf_counter() - started) * 1000, 3)
                        new_scans = runtime.observations[calls:]
                        projection = new_scans[-1] if len(new_scans) == 1 else None
                        if projection is None or not hooked["execution"]["scanner_run"]:
                            failures.append("HOOK_SCANNER_EXECUTION_UNPROVEN")
                        else:
                            failures.extend(validate_scan(projection, language, filename, expected_rule, risky))
                        output = CodexHookAdapter().output({"hook_event_name": "PostToolUse"}, hooked)
                        hook = {"status": hooked["status"], "coverage": hooked["coverage"],
                                "execution_state": hooked["execution_state"], "wall_ms": hook_wall,
                                "scanner_run": hooked["execution"]["scanner_run"],
                                "scanner_invocation_count": hooked.get("scanner_invocation_count"),
                                "runtime_scan_calls": len(new_scans),
                                "source_unchanged_by_hook": digest(file) == before,
                                "delta": {key: hooked["delta"][key] for key in (
                                    "new", "persisting", "resolved", "additional_occurrences", "removed_occurrences")},
                                "advisory_message": output["systemMessage"],
                                "scan": projection}
                        if not quick["source_unchanged_by_scan"] or not hook["source_unchanged_by_hook"]:
                            failures.append("SCANNER_MODIFIED_SOURCE")
                        if risky and hook["delta"]["new"] < 1:
                            failures.append("HOOK_NEW_CANDIDATE_NOT_OBSERVED")
                        if phase == "safe_after" and hook["delta"]["resolved"] < 1:
                            failures.append("ORIGINAL_RULE_ABSENCE_UNPROVEN")
                        step = {"cycle": cycle, "phase": phase, "source_sha256": before,
                                "quick": quick, "hook": hook, "failures": sorted(set(failures))}
                        case["steps"].append(step)
                        report["failures"].extend({"language": language, "step": label, "code": code}
                                                  for code in sorted(set(failures)))
                case["latency"] = {
                    "quick": latency([step["quick"]["wall_ms"] for step in case["steps"]]),
                    "hook": latency([step["hook"]["wall_ms"] for step in case["steps"]]),
                }
                calls = len(runtime.observations)
                finalized = coordinator.handle_lifecycle(EventKind.SESSION_STOP, root, "codex", session)
                case["session_stop"] = {"status": finalized["status"],
                                        "scanner_run": finalized["execution"]["scanner_run"],
                                        "runtime_scan_calls": len(runtime.observations) - calls}
            report["status"] = "PASS" if not report["failures"] else "FAIL"
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run_acceptance()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "cases": len(report["cases"]),
                      "failures": len(report["failures"]),
                      "desktop_hook_acceptance": report["desktop_hook_acceptance"]}))
    raise SystemExit(0 if report["status"] == "PASS" else 2 if report["status"] == "BLOCKED_ENVIRONMENT" else 1)
