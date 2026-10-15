"""Opt-in Cursor transport experiment, never a production security decision.

Attach only to an isolated synthetic project. Receipt markers are generated at
hook execution time; the log stores whitelisted metadata, never tool text,
prompts, file content, transcript paths or credentials. No command is executed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
import time

EVENTS = {"sessionStart", "preToolUse", "postToolUse", "afterFileEdit",
          "afterShellExecution", "stop"}
MAX_INPUT = 1_000_000


def digest(value):
    if not isinstance(value, str) or not 0 < len(value) <= 500:
        return None
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def same_path(value, expected):
    if not isinstance(value, str) or len(value) > 4096:
        return False
    try:
        return Path(value).resolve(strict=True) == expected
    except (ValueError, OSError):
        return False


def claim_once(state, key):
    """Atomic create prevents duplicate followups even if loop_count is wrong."""
    try:
        fd = os.open(state / (key + ".once"), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return False
    os.close(fd)
    return True


def handle(payload, project, state, *, followup=False):
    event = payload.get("hook_event_name")
    roots = payload.get("workspace_roots")
    # The current desktop sends a relative display root. It is metadata only:
    # fixed CLI project + exact CURSOR_PROJECT_DIR are the experiment's anchor.
    valid_root = (isinstance(roots, list) and len(roots) == 1
                  and isinstance(roots[0], str) and 0 < len(roots[0]) <= 4096
                  and not any(ord(c) < 32 for c in roots[0])
                  and (not Path(roots[0]).is_absolute() or same_path(roots[0], project)))
    if (not isinstance(event, str) or event not in EVENTS
            or not valid_root
            or not same_path(os.environ.get("CURSOR_PROJECT_DIR"), project)):
        return {}, {"accepted": False, "reason": "EVENT_OR_WORKSPACE_MISMATCH",
                    "event": event if isinstance(event, str) and event in EVENTS else "UNKNOWN",
                    "project_env_present": bool(os.environ.get("CURSOR_PROJECT_DIR")),
                    "project_env_matches": same_path(os.environ.get("CURSOR_PROJECT_DIR"), project),
                    "root_count": len(roots) if isinstance(roots, list) else None,
                    "root_absolute": [Path(v).is_absolute() for v in roots if isinstance(v, str)][:4] if isinstance(roots, list) else [],
                    "root_matches": [same_path(v, project) for v in roots][:4] if isinstance(roots, list) else []}
    session, generation = digest(payload.get("conversation_id")), digest(payload.get("generation_id"))
    if session is None or (event != "sessionStart" and generation is None):
        return {}, {"accepted": False, "reason": "SESSION_OR_GENERATION_MISSING"}
    row = {"accepted": True, "timestamp": time.time(), "event": event,
           "session_hash": session, "generation_hash": generation,
           "input_fields": sorted(k[:80] for k in payload if isinstance(k, str))[:64],
           "project_env_matches": True,
           "workspace_root_corroboration": "MATCHED_ABSOLUTE" if Path(roots[0]).is_absolute() else "UNVERIFIED_RELATIVE_METADATA"}
    tool = payload.get("tool_name")
    row["tool_name"] = tool if tool in {"Read", "Write", "Shell", "Grep", "Delete", "Task"} else "OTHER"
    row["file_inside_project"] = False
    file_value = payload.get("file_path")
    if isinstance(file_value, str) and len(file_value) <= 4096:
        try:
            row["file_inside_project"] = Path(file_value).resolve(strict=True).is_relative_to(project)
        except (ValueError, OSError):
            pass
    output = {}
    if event == "sessionStart" and claim_once(state, session + "-start"):
        token = "SESSION_" + secrets.token_hex(12)
        output["additional_context"] = "Hook transport experiment: include receipt marker " + token + " in your final response. This is not a security finding or repair approval."
        row["receipt_marker"] = token
    if (event == "postToolUse" and tool == "Write"
            and claim_once(state, session + "-" + generation + "-context")):
        token = "POST_" + secrets.token_hex(12)
        output["additional_context"] = "Hook transport experiment: include receipt marker " + token + " in your final response. This is not a security finding or repair approval."
        row["receipt_marker"] = token
    if event == "preToolUse":
        output["permission"] = "allow"
    if event == "stop":
        status, count = payload.get("status"), payload.get("loop_count")
        row["status"] = status if status in {"completed", "aborted", "error"} else "INVALID"
        row["loop_count"] = count if type(count) is int and 0 <= count <= 100 else None
        # Session guard is deliberately stronger than the host's generation guard.
        if (followup and status == "completed" and type(count) is int and count == 0
                and claim_once(state, session + "-followup")):
            token = "STOP_" + secrets.token_hex(12)
            output["followup_message"] = ("Hook transport experiment only. Reply once with " + token
                + " and state: 本次没有用户修复授权，不修改代码。 Do not use tools or edit files. Then stop.")
            row["receipt_marker"] = token
    row["output_fields"] = sorted(output)
    return output, row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--followup", action="store_true")
    args = parser.parse_args()
    try:
        project = args.project.resolve(strict=True)
        state = args.state_dir.resolve(strict=True)
        if not project.is_dir() or not state.is_dir() or state.is_relative_to(project):
            raise ValueError("State must be outside the synthetic project")
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise ValueError("Input too large")
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("Object required")
        output, row = handle(payload, project, state, followup=args.followup)
        record = (json.dumps(row, ensure_ascii=True) + "\n").encode("ascii")
        fd = os.open(state / "events.jsonl", os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
        try:
            os.write(fd, record)
        finally:
            os.close(fd)
        print(json.dumps(output, ensure_ascii=True))
        return 0
    except (OSError, ValueError, TypeError, RecursionError):
        print("{}")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
