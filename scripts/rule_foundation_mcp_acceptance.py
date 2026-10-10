"""Exercise frozen Windows rule execution through the official MCP stdio SDK.

Use an extracted security-check.exe and an already prepared managed data dir.
The child is offline, has a private home/state, no developer Python on PATH,
and a temporary cwd unrelated to the source checkout. Synthetic risk inputs
are scanned, never executed. Reports contain metadata, not source or paths.
This is protocol/scanner evidence, not a Codex Desktop or functional test and
does not close a Runtime repair Episode or grant repair authorization.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time


CASES = (
    ("java", "Sample.java", "ai-security.java.spring-named-jdbc"),
    ("javascript", "sample.js", "ai-security.javascript.command-injection"),
    ("typescript", "sample.ts", "ai-security.javascript.ssrf"),
)


def source(language, risky, phase="initial"):
    """Original isolated samples; no target application is started."""
    marker = "// Isolated native MCP acceptance: " + ("risk" if risky else "safe") + " " + phase + "\n"
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


def child_environment(directory, project, executable, data_dir, git_executable):
    retained = ("SystemRoot", "WINDIR", "COMSPEC", "PATHEXT", "SYSTEMDRIVE",
                "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "OS", "LANG", "LC_ALL")
    env = {key: os.environ[key] for key in retained if key in os.environ}
    home, state, scratch = directory / "home", directory / "state", directory / "temp"
    codex, plugins = home / ".codex", directory / "plugins"
    for folder in (home, state, scratch, codex, plugins, home / "AppData" / "Local",
                   home / "AppData" / "Roaming"):
        folder.mkdir(parents=True, exist_ok=True)
    system = Path(os.environ.get("SystemRoot", "C:/Windows"))
    # Windows root can contain a developer py.exe launcher. COMSPEC is already
    # absolute; System32 supplies native tools without that bootstrap fallback.
    path = [executable.parent, git_executable.parent, system / "System32"]
    env.update({
        "PATH": os.pathsep.join(str(folder) for folder in path),
        "HOME": str(home), "USERPROFILE": str(home), "CODEX_HOME": str(codex),
        "APPDATA": str(home / "AppData" / "Roaming"),
        "LOCALAPPDATA": str(home / "AppData" / "Local"),
        "TEMP": str(scratch), "TMP": str(scratch),
        "SECURITY_RUNTIME_DATA_DIR": str(data_dir),
        "SECURITY_RUNTIME_STATE_DIR": str(state),
        "SECURITY_RUNTIME_PLUGIN_DIR": str(plugins),
        "SECURITY_RUNTIME_WORKSPACE": str(project),
        "SECURITY_RUNTIME_INTEGRATION": "generic-mcp",
        "SECURITY_RUNTIME_OFFLINE": "1", "PYTHONUTF8": "1",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": str(home / "empty-gitconfig"),
    })
    # Offline managed engines are allowed their own private Python. The host
    # PATH must not provide a developer/system Python as a bootstrap fallback.
    if any(shutil.which(name, path=env["PATH"]) for name in ("python", "python3", "py")):
        raise ValueError("DEVELOPER_PYTHON_ON_CHILD_PATH")
    return env


def git(executable, project, hooks, env, *args):
    subprocess.run([str(executable), "-c", "core.hooksPath=" + str(hooks),
                    "-c", "commit.gpgsign=false", "-C", str(project), *args],
                   check=True, env=env, stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)


def report_file(value):
    # Never serialize unexpected absolute scanner paths, even in a failed run.
    return value if value in {filename for _, filename, _ in CASES} else "UNEXPECTED_FILE_PATH"


def projection(data, tool, elapsed):
    rules = data.get("rule_coverage", {})
    return {
        "tool": tool, "mode": "release" if tool == "scan_project" else "quick",
        "scan_id": data.get("scan_id"), "coverage": data.get("coverage"),
        "status": data.get("status"), "execution_state": data.get("execution_state"),
        "duration_ms": data.get("duration_ms"), "wall_ms": elapsed,
        "capability_results": data.get("capability_results", {}),
        "selected_files": data.get("target_selection", {}).get("selected_files"),
        "selected_rules": rules.get("total_selected", 0),
        "executed_rules": rules.get("total_executed", 0),
        "rule_pack_version": rules.get("rule_pack_version"),
        "rule_pack_checksum": rules.get("rule_pack_checksum"),
        "per_language": {
            language: {key: value.get(key) for key in (
                "status", "selected_rules", "executed_rules", "target_files", "scanned_files",
                "selected_rule_ids", "executed_rule_ids")}
            for language, value in rules.get("per_language", {}).items()
        },
        "finding_count": len(data.get("findings", [])),
        "findings": [{"finding_id": value["id"], "file": report_file(value.get("file_path")),
                      "rule_id": value.get("technical_details", {}).get("rule_id"),
                      "severity": value.get("severity"), "confidence": value.get("confidence")}
                     for value in data.get("findings", [])],
        "scanner_runs": [{key: value.get(key) for key in (
            "scanner", "version", "status", "duration_ms", "finding_count", "error_code",
            "coverage_contract")}
            for value in data.get("scanner_runs", [])],
    }


def validate_scan(row, risky):
    failures = []
    if row["coverage"] != "FULL" or row["execution_state"] != "EXECUTED":
        failures.append("SCANNER_COVERAGE_INCOMPLETE")
    if row["selected_files"] != len(CASES):
        failures.append("UNEXPECTED_FILE_SCOPE")
    # 23 Java rules plus six shared JS/TS rules; shared rule ids count once.
    if row["selected_rules"] != 29 or row["executed_rules"] != 29:
        failures.append("RULE_EXECUTION_INCOMPLETE")
    expected = {(file, rule_id) for _, file, rule_id in CASES}
    actual = {(item["file"], item["rule_id"]) for item in row["findings"]}
    if actual != (expected if risky else set()):
        failures.append("FINDING_EXPECTATION_MISMATCH")
    for language, _, rule_id in CASES:
        details = row["per_language"].get(language, {})
        if (not details.get("selected_rules") or
                details.get("executed_rules") != details.get("selected_rules") or
                rule_id not in details.get("executed_rule_ids", [])):
            failures.append("EXPECTED_LANGUAGE_RULE_EXECUTION_UNPROVEN:" + language)
    if not row["scanner_runs"] or any(
            value["status"] not in {"SUCCESS", "NOT_APPLICABLE"}
            for value in row["scanner_runs"]):
        failures.append("PROVIDER_DID_NOT_SUCCEED")
    providers = {value["scanner"]: value for value in row["scanner_runs"]}
    for name in ("semgrep", "gitleaks"):
        value = providers.get(name, {})
        if value.get("status") != "SUCCESS" or value.get("coverage_contract") != "FULL":
            failures.append("REQUIRED_PROVIDER_FULL_EXECUTION_UNPROVEN:" + name)
    return failures


def response_data(response):
    if response.isError:
        # Rejected tool text may contain paths/source: never copy it to report.
        raise ValueError("MCP_TOOL_ERROR")
    data = response.structuredContent
    if data is None:
        texts = [item.text for item in response.content if getattr(item, "type", None) == "text"]
        if not texts:
            raise ValueError("MCP_RESPONSE_NOT_JSON")
        data = json.loads(texts[0])
    return data.get("result", data) if isinstance(data, dict) else data


async def protocol_acceptance(executable, data_dir, report):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    found_git = shutil.which("git")
    if not found_git:
        raise ValueError("GIT_UNAVAILABLE")
    git_executable = Path(found_git).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="runtime-native-rules-") as temporary:
        directory = Path(temporary).resolve()
        project, hooks, cwd = directory / "project", directory / "no-hooks", directory / "cwd"
        for folder in (project, hooks, cwd):
            folder.mkdir()
        env = child_environment(directory, project, executable, data_dir, git_executable)
        report["environment_validation"] = "PASS"
        report["child_developer_python_on_path"] = False
        report["child_pythonpath_present"] = False
        for language, filename, _ in CASES:
            (project / filename).write_text(source(language, False), encoding="utf-8")
        git(git_executable, project, hooks, env, "init", "--quiet")
        git(git_executable, project, hooks, env, "config", "user.name", "Synthetic acceptance")
        git(git_executable, project, hooks, env, "config", "user.email", "fixture@example.invalid")
        git(git_executable, project, hooks, env, "add", *(filename for _, filename, _ in CASES))
        git(git_executable, project, hooks, env, "commit", "-m", "safe isolated fixture")
        for language, filename, _ in CASES:
            (project / filename).write_text(source(language, True), encoding="utf-8")
        params = StdioServerParameters(command=str(executable), args=["mcp"], cwd=cwd, env=env)
        with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stderr:
            async with stdio_client(params, errlog=stderr) as (read, write):
                async with ClientSession(read, write) as client:
                    initialized = await asyncio.wait_for(client.initialize(), timeout=45)
                    tools = {tool.name: tool for tool in (await client.list_tools()).tools}
                    if not {"scan_project", "scan_diff", "get_findings", "get_runtime_info"} <= tools.keys():
                        raise ValueError("MCP_REQUIRED_TOOL_MISSING")
                    report["runtime_version"] = initialized.serverInfo.version
                    info = response_data(await client.call_tool("get_runtime_info", {}))
                    report["runtime_version"] = info.get("version", report["runtime_version"])
                    report["protocol"] = {"initialized": True, "official_sdk": True,
                        "required_tools_present": True,
                        "scan_project_mode_parameter": "mode" in tools["scan_project"].inputSchema.get("properties", {})}

                    async def scan(tool, risky):
                        before = {name: hashlib.sha256((project / name).read_bytes()).hexdigest()
                                  for _, name, _ in CASES}
                        started = time.perf_counter()
                        arguments = {} if tool == "scan_project" else {"mode": "quick"}
                        response = await asyncio.wait_for(client.call_tool(tool, arguments), timeout=240)
                        data = response_data(response)
                        elapsed = round((time.perf_counter() - started) * 1000, 3)
                        if not Path(data["workspace"]).samefile(project):
                            raise ValueError("MCP_WORKSPACE_BINDING_MISMATCH")
                        row = projection(data, tool, elapsed)
                        row["source_unchanged_by_scan"] = all(
                            hashlib.sha256((project / name).read_bytes()).hexdigest() == digest
                            for name, digest in before.items())
                        failures = validate_scan(row, risky)
                        if not row["source_unchanged_by_scan"]:
                            failures.append("SCANNER_MODIFIED_SOURCE")
                        row["failures"] = failures
                        report["scans"].append(row)
                        report["failures"].extend({"tool": tool, "code": failure} for failure in failures)
                        return data

                    original = await scan("scan_project", True)
                    for finding in original["findings"]:
                        detail = response_data(await client.call_tool("get_findings", {
                            "scan_id": original["scan_id"], "finding_id": finding["id"],
                            "include_evidence": True, "context_lines": 2, "view": "page", "limit": 1}))
                        items = detail.get("items", [])
                        if len(items) != 1:
                            raise ValueError("MCP_FINDING_DETAIL_NOT_SINGLE")
                        evidence = items[0].get("local_evidence", {})
                        exact = evidence.get("evidence_status") == "EXACT"
                        has_match = bool((evidence.get("original_evidence") or {}).get("matched_code"))
                        record = {"finding_id": finding["id"], "rule_id": finding["technical_details"].get("rule_id"),
                                  "file": report_file(finding["file_path"]), "evidence_status": evidence.get("evidence_status"),
                                  "reason": evidence.get("reason"), "matched_code_present": has_match,
                                  "current_context_present": evidence.get("current_context") is not None,
                                  "source_or_context_persisted_in_report": False}
                        report["evidence"].append(record)
                        if not exact or not has_match or record["current_context_present"]:
                            report["failures"].append({"tool": "get_findings", "code": "EXACT_LOCAL_EVIDENCE_UNPROVEN"})
                    await scan("scan_diff", True)
                    for language, filename, _ in CASES:
                        # A unique harmless phase comment keeps the safe files
                        # dirty versus HEAD, so quick really executes rules.
                        (project / filename).write_text(source(language, False, "safe-recheck"), encoding="utf-8")
                    await scan("scan_project", False)
                    rechecked = await scan("scan_diff", False)
                    report["original_rule_recheck"] = [
                        {"language": language, "file": filename, "rule_id": rule_id,
                         "executed": rule_id in rechecked.get("rule_coverage", {}).get(
                             "per_language", {}).get(language, {}).get("executed_rule_ids", []),
                         "finding_absent": not any(finding.get("file_path") == filename and
                             finding.get("technical_details", {}).get("rule_id") == rule_id
                             for finding in rechecked.get("findings", []))}
                        for language, filename, rule_id in CASES]
            stderr.seek(0)
            log = stderr.read()
            report["stdio_diagnostics"] = {
                "sdk_settings_warning": "IncompleteFieldDefinitionWarning" in log,
                "raw_diagnostics_persisted": False}
            if report["stdio_diagnostics"]["sdk_settings_warning"]:
                report["failures"].append({"tool": "initialize", "code": "SDK_SETTINGS_WARNING"})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", required=True, type=Path)
    parser.add_argument("--data-dir", required=True, type=Path,
                        help="Existing managed Semgrep/Gitleaks/tool data; no installation is performed.")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = {"schema": "rule-foundation-native-mcp-v1", "status": "RUNNING", "failures": [],
              "scans": [], "evidence": [], "offline": True, "managed_tools_preparation_requested": False,
              "input_kind": "ISOLATED_SYNTHETIC_GIT_PROJECT", "scanner_results_mocked": False,
              "environment_validation": "NOT_COMPLETED",
              "child_developer_python_on_path": None, "child_pythonpath_present": None,
              "child_source_checkout_dependency": False, "private_child_home_state": True,
              "business_source_modified": False, "host_configuration_modified": False,
              "model_called": False, "desktop_acceptance": "NOT_RUN", "functional_tests": "NOT_RUN",
              "repair_episode_closed": False,
              "safe_recheck_delta": "Synthetic phase comment keeps safe files changed versus initial Git HEAD.",
              "interpretation": "Original-rule scanner recheck only; not repair authorization or functional compatibility proof."}
    try:
        executable = args.executable.resolve(strict=True)
        data_dir = args.data_dir.resolve(strict=True)
        if os.name != "nt" or executable.suffix.lower() != ".exe" or not executable.is_file():
            raise ValueError("WINDOWS_NATIVE_EXECUTABLE_REQUIRED")
        if not data_dir.is_dir():
            raise ValueError("PREPARED_MANAGED_DATA_DIRECTORY_REQUIRED")
        report["executable_sha256"] = hashlib.sha256(executable.read_bytes()).hexdigest()
        asyncio.run(protocol_acceptance(executable, data_dir, report))
        report["status"] = "PASS" if not report["failures"] else "FAIL"
    except Exception as exc:
        # Fail closed without logging potentially private SDK error text.
        codes = {"DEVELOPER_PYTHON_ON_CHILD_PATH", "GIT_UNAVAILABLE", "MCP_TOOL_ERROR", "MCP_RESPONSE_NOT_JSON",
                 "MCP_REQUIRED_TOOL_MISSING", "MCP_WORKSPACE_BINDING_MISMATCH", "MCP_FINDING_DETAIL_NOT_SINGLE",
                 "WINDOWS_NATIVE_EXECUTABLE_REQUIRED", "PREPARED_MANAGED_DATA_DIRECTORY_REQUIRED"}
        code = str(exc) if isinstance(exc, ValueError) and str(exc) in codes else type(exc).__name__
        report["failures"].append({"tool": "acceptance", "code": code})
        report["status"] = "FAIL"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "scans": len(report["scans"]),
                      "exact_evidence": sum(item["evidence_status"] == "EXACT" for item in report["evidence"]),
                      "failures": len(report["failures"]), "desktop_acceptance": report["desktop_acceptance"]}))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
