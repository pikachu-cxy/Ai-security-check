"""Native Codex development acceptance; no fixed diff or simulated reviewer.

Use prepare for a NEW isolated demo, run for its real native development turn,
and report for read-only structured observations. Existing login and trusted
global hooks stay with Codex; authentication files are never read or copied.
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import sqlite3
import subprocess
import sys
import threading
import time
import tomllib


TASK = '''请遵循本项目 AGENTS.md 的实验流程，正常设计和实现功能，不要回放预设补丁。
先阅读项目，在首次修改源代码或配置前 begin_security_task，保留同一 task_ref。
请为订单列表增加按状态筛选和分页，page从1开始，page_size为1到100，顺序稳定，
筛选分页后仍只能看到当前用户订单。先完成服务与命令行的一批有意义改动，
调用 prepare_security_batch 交给本机实验宿主后台分析，然后立即继续开发：
为订单详情增加可选收据字段并保持用户隔离，补充分页边界、筛选和跨用户测试，运行测试。
不要为制造并行效果插入sleep或假任务，不要等待每个中间批次，不要启动其他Agent。
不要读取认证文件，不要联网，不要改实验项目外的文件或安装配置。
开发结束后 finish_security_task，prepare_task_security_review，依据真实最终证据完成
主Agent最终核对并submit_task_security_review，包括integration_review与批次候选处理。
用get_security_batches查看实际后台状态。遇缺口如实保留，不能伪造基线或检查通过。
最后简短说明完成的功能、测试和本次实际检查范围。'''
SESSION_ENV = frozenset({"CODEX_APP_TOOLS_PIPE_PATH", "CODEX_THREAD_ID", "CODEX_SESSION_ID",
    "CODEX_INTERNAL_ORIGINATOR_OVERRIDE", "CODEX_PERMISSION_PROFILE"})


def child_environment(environment=None):
    source = os.environ if environment is None else environment
    return {key: value for key, value in source.items() if key not in SESSION_ENV}


def stderr_diagnostic(line):
    """Classify startup errors without retaining their untrusted free text."""
    lowered = line.lower()
    option = re.search(r"unexpected argument ['\"](--[a-z][a-z0-9-]*)['\"]", lowered)
    category = "UNCLASSIFIED_STDERR"
    if option:
        category = "UNSUPPORTED_CLI_ARGUMENT"
    elif "no prompt provided via stdin" in lowered:
        category = "EMPTY_STDIN_PROMPT"
    elif any(word in lowered for word in ("not a tty", "not a terminal", "stdin is not")):
        category = "INTERACTIVE_TERMINAL_REQUIRED"
    elif "codex" in lowered and any(word in lowered for word in ("nested", "inside another", "already running")):
        category = "INHERITED_OR_NESTED_SESSION_REJECTED"
    elif "hook" in lowered and any(word in lowered for word in ("trust", "approval")):
        category = "HOOK_TRUST_OR_APPROVAL_REQUIRED"
    elif "trusted" in lowered and any(word in lowered for word in ("directory", "project", "workspace")):
        category = "PROJECT_TRUST_REQUIRED"
    elif any(word in lowered for word in ("error loading configuration", "error loading config.toml",
                                          "failed to parse", "invalid configuration", "invalid transport", "unknown variant")):
        category = "CONFIGURATION_REJECTED"
    elif any(word in lowered for word in ("unauthorized", "authentication", "login", "api key", "token expired")):
        category = "AUTHENTICATION_ERROR_TEXT_OMITTED"
    elif any(word in lowered for word in ("connection refused", "failed to connect", "network is unreachable")):
        category = "CONNECTION_ERROR_TEXT_OMITTED"
    elif lowered.lstrip().startswith("error:"):
        category = "CLI_ERROR_TEXT_OMITTED"
    value = dict(category=category, sha256=hashlib.sha256(line.encode("utf-8")).hexdigest(),
        bytes=len(line.encode("utf-8")))
    if option:
        value["option"] = option.group(1)
    return value


def _write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def _paths(args):
    values = {key: Path(getattr(args, key)).resolve() for key in
              ("workspace", "state_dir", "runtime_root", "python", "codex", "output_dir")}
    root, state, output = (values[key] for key in ("workspace", "state_dir", "output_dir"))
    if state.is_relative_to(root) or output.is_relative_to(root):
        raise ValueError("State and logs must stay outside the reviewed project")
    if not values["python"].is_file() or not values["codex"].is_file():
        raise ValueError("Installed Python and Codex executables are required")
    sys.path[:0] = [str(values["runtime_root"] / "scripts"), str(values["runtime_root"] / "src")]
    from security_runtime.hook_state import no_links
    for value in values.values():
        no_links(value)
    return values


def prepare(args):
    paths = _paths(args)
    from create_codex_pilot_demo import create_demo
    from install_codex_desktop_pilot import install
    root = create_demo(paths["workspace"])
    for command in (["git", "init", "-q", str(root)], ["git", "-C", str(root), "add", "."],
        ["git", "-C", str(root), "-c", "user.name=Codex local pilot", "-c",
         "user.email=local-pilot@example.invalid", "commit", "-qm", "Independent desktop pilot baseline"]):
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    installed = install(root, paths["state_dir"], runtime_root=paths["runtime_root"],
        python=paths["python"], codex=paths["codex"])
    value = dict(status="PREPARED", workspace=str(root), installation_status=installed["status"],
        actual_model_calls=0, fixed_development_diff=False)
    _write(paths["output_dir"] / "prepare.json", value)
    return value


def config_overrides(root, home):
    config_path = home / "config.toml"
    raw = config_path.read_bytes() if config_path.is_file() else b""
    document = tomllib.loads(raw.decode("utf-8"))
    # This native -c implementation splits dotted keys literally. Quoting a
    # dotted path segment creates a new key with quote characters; quoted
    # project keys must therefore be parsed as part of the TOML inline value.
    overrides = ['projects={' + json.dumps(str(root), ensure_ascii=False) + '={trust_level="trusted"}}',
                 'agents.enabled=false', 'approval_policy="never"']
    servers = document.get("mcp_servers", {})
    for name in sorted(servers):
        if name != "ai_security_runtime":
            if not re.fullmatch(r"[A-Za-z0-9_-]+", name):
                raise ValueError("Inherited MCP server name cannot be safely overridden by this native CLI")
            overrides.append('mcp_servers.' + name + '.enabled=false')
    return overrides, _hash(config_path)


def project_event(event, at_ms):
    """Project structural evidence only; never store raw arguments or output."""
    if not isinstance(event, dict):
        return None
    value = dict(type=event.get("type"), at_ms=at_ms)
    item = event.get("item")
    if isinstance(item, dict):
        value.update(item_id=item.get("id"), item_type=item.get("type"), status=item.get("status"))
        for key in ("server", "tool", "exit_code"):
            if key in item:
                value[key] = item[key]
        if isinstance(value.get("tool"), str) and value["tool"].startswith("mcp__ai_security_runtime__"):
            value["tool"] = value["tool"].removeprefix("mcp__ai_security_runtime__")
        arguments = item.get("arguments")
        if isinstance(arguments, dict):
            for key in ("task_ref", "batch_ref"):
                candidate = arguments.get(key)
                if isinstance(candidate, str) and re.fullmatch(r"(?:ts1|tb1)-[a-f0-9]{32}", candidate):
                    value[key] = candidate
        if isinstance(item.get("changes"), list):
            value["changed_files"] = [dict(path=row.get("path"), kind=row.get("kind"))
                for row in item["changes"] if isinstance(row, dict)][:100]
        if item.get("error"):
            value["error_present"] = True
        result = item.get("result")
        if isinstance(result, dict):
            structured = result.get("structured_content", result.get("structuredContent"))
            if isinstance(structured, dict):
                value["response_status"] = structured.get("status")
    if isinstance(event.get("usage"), dict):
        value["usage"] = {key: number for key, number in event["usage"].items()
            if key in {"input_tokens", "cached_input_tokens", "output_tokens", "reasoning_output_tokens"}
            and type(number) is int and number >= 0}
    if isinstance(event.get("thread_id"), str):
        value["thread_id"] = event["thread_id"]
    return value


def run(args):
    paths = _paths(args)
    root, output = paths["workspace"], paths["output_dir"]
    if not (root / ".codex/config.toml").is_file() or not (root / "AGENTS.md").is_file():
        raise ValueError("Prepare and install the independent pilot project first")
    if not 10 <= args.timeout <= 900:
        raise ValueError("Native acceptance timeout must be between ten and 900 seconds")
    output.mkdir(parents=True, exist_ok=True)
    event_path = output / "native-events.jsonl"
    if event_path.exists():
        raise ValueError("Use a fresh output directory; earlier native receipts must be retained")
    home = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
    overrides, config_before = config_overrides(root, home)
    hooks_before = _hash(home / "hooks.json")
    from security_runtime.task_security import capture
    initial = capture(root, include_text=False)
    _write(output / "initial-manifest.json", dict(hashes=initial["hashes"],
        inventory=initial.get("inventory"), limitations=initial.get("limitations")))
    command = [str(paths["codex"]), "exec", "--json", "-C", str(root), "--sandbox", "workspace-write",
        "--ephemeral", "--output-last-message", str(output / "last-message.txt")]
    for override in overrides:
        command += ["-c", override]
    command += ["-"]
    started = time.monotonic()
    process = subprocess.Popen(command, cwd=root, env=child_environment(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
    incoming = queue.Queue()
    stderr = dict(lines=0, bytes=0, diagnostics=[])

    def stdout_reader():
        for line in process.stdout:
            try:
                incoming.put(json.loads(line))
            except json.JSONDecodeError:
                incoming.put({"type": "non_json_stdout_omitted"})
        incoming.put(None)

    def stderr_reader():
        for line in process.stderr:
            stderr["lines"] += 1
            stderr["bytes"] += len(line.encode("utf-8"))
            if len(stderr["diagnostics"]) < 32:
                stderr["diagnostics"].append(stderr_diagnostic(line))

    readers = [threading.Thread(target=stdout_reader, daemon=True),
               threading.Thread(target=stderr_reader, daemon=True)]
    for reader in readers:
        reader.start()
    process.stdin.write(TASK)
    process.stdin.close()
    counts, events, timed_out = Counter(), [], False
    with event_path.open("x", encoding="utf-8") as stream:
        while True:
            if time.monotonic() - started >= args.timeout:
                timed_out = True
                if os.name == "nt":
                    subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                else:
                    process.terminate()
                break
            try:
                event = incoming.get(timeout=.25)
            except queue.Empty:
                if process.poll() is not None and not readers[0].is_alive():
                    break
                continue
            if event is None:
                break
            row = project_event(event, round((time.monotonic() - started) * 1000, 3))
            if row:
                events.append(row)
                counts[str(row.get("type"))] += 1
                stream.write(json.dumps(row, ensure_ascii=False) + "\n")
                stream.flush()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
    for reader in readers:
        reader.join(timeout=1)
    receipt = dict(status="TIMEOUT" if timed_out else "NATIVE_PROCESS_COMPLETED",
        exit_code=process.returncode, elapsed_ms=round((time.monotonic() - started) * 1000, 3),
        workspace=str(root), event_counts=dict(counts), native_event_count=len(events),
        parent_model_usage=[row["usage"] for row in events if row.get("usage")],
        parent_usage_scope="NATIVE_PARENT_TURN_CUMULATIVE; excludes child host receipts",
        global_config_unchanged=_hash(home / "config.toml") == config_before,
        global_hooks_unchanged=_hash(home / "hooks.json") == hooks_before,
        process_local_project_trust=True, global_trust_written=False,
        inherited_session_environment_removed=sorted(SESSION_ENV),
        driver_auth_files_read=False, authentication="EXISTING_NATIVE_CODEX_LOGIN",
        raw_stdout_stderr_stored=False, stderr_summary=stderr,
        last_message_sha256=_hash(output / "last-message.txt"), fixed_development_diff=False)
    _write(output / "native-run.json", receipt)
    return receipt


def report(args):
    paths = _paths(args)
    output = paths["output_dir"]
    native = json.loads((output / "native-run.json").read_text(encoding="utf-8"))
    events = [json.loads(line) for line in (output / "native-events.jsonl").read_text(encoding="utf-8").splitlines()]
    initial = json.loads((output / "initial-manifest.json").read_text(encoding="utf-8"))
    root, state = paths["workspace"], paths["state_dir"]
    from security_runtime.closeout_state import readonly_uri
    from security_runtime.hook_state import HookStateStore, no_links
    from security_runtime.task_security import TaskSecurityService
    from security_runtime.task_security_state import TaskSecurityStore
    from security_runtime.recent_hooks import RecentHookStore
    hooks = HookStateStore(state / "hooks")
    store = TaskSecurityStore(hooks, root)
    tasks = TaskSecurityService(lambda: None, hooks)
    records, task_rows = [], []
    if store.path.is_file():
        no_links(store.path)
        with closing(sqlite3.connect(readonly_uri(store.path), uri=True)) as db:
            db.execute("PRAGMA query_only=ON")
            refs = [row[0] for row in db.execute("SELECT ref FROM security_tasks ORDER BY rowid DESC LIMIT 32")]
        for ref in refs:
            record = store.get(ref)
            if record:
                records.append(record)
                static, review = record.get("static") or {}, record.get("review") or {}
                task_rows.append(dict(task_ref=ref, phase=record["phase"],
                    baseline_matches_pre_run_manifest=record["baseline"]["hashes"] == initial["hashes"],
                    changed_file_count=len(record.get("changes", [])),
                    static_attempts=record.get("static_attempts", 0),
                    static_status=static.get("status"), static_coverage=static.get("coverage"),
                    static_finding_count=len(static.get("findings", [])),
                    host_coverage=review.get("coverage"), host_finding_count=len(review.get("findings", [])),
                    final_integration_submitted=isinstance(review.get("integration_review"), dict),
                    final_current=tasks._fresh(root, record) if record.get("end") else None,
                    context_gap_count=len(record.get("context_gaps", [])),
                    limitations_present=bool(record.get("limitations") or review.get("limitations"))))
    background = []
    for record in records:
        ref = record["task_ref"]
        path = state / "background" / ref / "status.json"
        no_links(path)
        if not path.is_file() or path.stat().st_size > 256_000:
            continue
        saved = json.loads(path.read_text(encoding="utf-8"))
        batches = {batch["batch_ref"]: batch for batch in
                   (record.get("batch_state") or {}).get("batches", [])}
        for row in saved.get("reviews", [])[:8]:
            if not isinstance(row, dict) or row.get("batch_ref") not in batches:
                continue
            job_id = row.get("job_id")
            if not isinstance(job_id, str) or not re.fullmatch(r"[0-9a-f]{32}", job_id):
                continue
            receipt_path = path.parent / job_id / "receipt.json"
            no_links(receipt_path)
            receipt = (json.loads(receipt_path.read_text(encoding="utf-8"))
                       if receipt_path.is_file() and receipt_path.stat().st_size < 2_000_000 else {})
            calls = receipt.get("tool_calls") or []
            background.append(dict(task_ref=ref, batch_ref=row["batch_ref"],
                status=row.get("status"), host_status=receipt.get("status", row.get("host_status")),
                model_observed=receipt.get("model_observed") is True and receipt.get("simulation") is False,
                model=receipt.get("model"), usage=receipt.get("usage"),
                usage_complete=receipt.get("usage_complete") is True,
                usage_accounting_may_be_incomplete=receipt.get("usage_accounting_may_be_incomplete") is True,
                elapsed_ms=row.get("elapsed_ms"), callback_count=len(calls),
                snapshot_callbacks=[{key: call.get(key) for key in ("path", "start_line", "end_line", "at_ms")}
                    for call in calls if isinstance(call, dict)][:40],
                submission_accepted=row.get("submission_accepted") is True,
                coverage=(batches[row["batch_ref"]].get("review") or {}).get("coverage"),
                isolation_contract=receipt.get("isolation_contract"), receipt_sha256=_hash(receipt_path)))
    hook_rows = []
    hook_path = state / "hook-diagnostics.db"
    if hook_path.is_file():
        hook_rows = RecentHookStore(hook_path).recent(root, limit=32)["records"]
    checkpoints = [row["at_ms"] for row in events if row.get("tool") == "prepare_security_batch"
                   and row.get("type") == "item.completed"]
    later_edits = [row for row in events if row.get("item_type") in {"file_change", "fileChange"}
                   and row.get("type") == "item.completed"
                   and any(row["at_ms"] > checkpoint for checkpoint in checkpoints)]
    checks = dict(native_parent_completed=native.get("exit_code") == 0 and
        any(row.get("type") == "turn.completed" for row in events),
        exact_pre_edit_baseline=bool(task_rows) and all(row["baseline_matches_pre_run_manifest"] for row in task_rows),
        actual_development=any(row["changed_file_count"] > 0 for row in task_rows),
        checkpoint_then_later_file_edit=bool(later_edits),
        actual_background_model=any(row["model_observed"] and row["callback_count"] > 0 for row in background),
        parent_submitted_background=any(row["submission_accepted"] for row in background),
        synchronous_final_static=any(row["static_attempts"] >= 1 for row in task_rows),
        final_parent_integration_current=any(row["phase"] == "COMPLETE" and row["final_current"] is True
            and row["final_integration_submitted"] for row in task_rows),
        real_edit_hook_observed=any(row.get("event") == "PostToolUse" and
            row.get("host_claim_status") == "VALID" for row in hook_rows),
        global_config_unchanged=native.get("global_config_unchanged") is True,
        global_hooks_unchanged=native.get("global_hooks_unchanged") is True)
    value = dict(status="NATIVE_FLOW_OBSERVED" if all(checks.values()) else "ACCEPTANCE_GAPS",
        checks=checks, native=native, tasks=task_rows, background=background,
        hook_events=[{key: row.get(key) for key in ("event", "host_claim_status", "handler_status",
            "scanner_run", "changed_file_count", "last_stage", "timestamp")} for row in hook_rows],
        findings_semantically_adjudicated=False, project_safety_claim=False,
        note="Native flow evidence and source-version validation are separate from security coverage and finding quality.")
    _write(output / "acceptance.json", value)
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "run", "report"])
    for key in ("workspace", "state-dir", "runtime-root", "python", "codex", "output-dir"):
        parser.add_argument("--" + key, required=True, type=Path)
    parser.add_argument("--timeout", type=float, default=900)
    args = parser.parse_args(argv)
    try:
        value = globals()[args.action](args)
    except Exception as error:
        print(json.dumps(dict(status="FAILED", error_type=type(error).__name__), ensure_ascii=False))
        return 1
    print(json.dumps(value, ensure_ascii=False, indent=2))
    return 0 if value.get("exit_code", 0) == 0 and value.get("status") != "TIMEOUT" else 1


if __name__ == "__main__":
    raise SystemExit(main())
