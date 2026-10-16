"""Project-bound host orchestration for the opt-in desktop experience.

The core Runtime remains model-free. This trusted adapter owns model dispatch,
the only context callback, cancellation and parent submission. No model-facing
argument can grant this adapter or select its backend, executable or state path.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
import json
from pathlib import Path
import re
import threading
import time
import uuid


_TASK = re.compile(r"ts1-[0-9a-f]{32}")
_BATCH = re.compile(r"tb1-[0-9a-f]{32}")
_RESULT_KEYS = {"task_ref", "batch_ref", "review_session", "findings", "coverage", "limitations"}
_UNAVAILABLE = {"UNSUPPORTED_HOST", "HOST_UNAVAILABLE"}
_PUBLIC_REVIEW_FIELDS = frozenset({"job_id", "batch_ref", "status", "started_at",
    "elapsed_ms", "model_observed", "usage", "submission_accepted", "coverage",
    "candidate_count", "host_status", "completed_at", "usage_complete",
    "usage_accounting_may_be_incomplete", "model", "reasoning_effort", "error_type", "validity"})


def _batch_schema(packet):
    from security_runtime.batch_reviewer import _result_schema
    schema = _result_schema(packet)
    fields = schema["properties"]["findings"]["items"]["properties"]
    identifier = r"^be1-[0-9a-f]{32}$"
    # Replace each field mapping rather than mutating shared short-schema
    # aliases used by unrelated title/category strings in the core contract.
    fields["primary_evidence"] = dict(fields["primary_evidence"], pattern=identifier,
        description="One exact context-reader-issued evidence identifier from this batch session. "
            "It must occur in evidence_refs. Never add line numbers or explanatory prose.")
    fields["evidence_refs"] = {**fields["evidence_refs"], "items": dict(
        fields["evidence_refs"]["items"], pattern=identifier,
        description="An exact issued batch evidence identifier, without added text.")}
    fields["task_evidence"] = dict(fields["task_evidence"], pattern=identifier,
        description="One exact issued identifier for a batch-changed file, also present in evidence_refs. "
            "This is an identifier, never an explanation. Put reasoning in impact or counterevidence.")
    return schema


@dataclass
class _Job:
    packet: dict
    row: dict
    cancel: threading.Event = field(default_factory=threading.Event)
    done: threading.Event = field(default_factory=threading.Event)
    thread: threading.Thread | None = None
    result: dict | None = None
    submit_value: dict | None = None


@dataclass
class _TaskState:
    rows: list = field(default_factory=list)
    active: _Job | None = None
    pending_key: str | None = None
    dispatch_closed: bool = False
    final_closed: bool = False
    disabled_reason: str | None = None


class ExperimentalBatchHost:
    def __init__(self, task_service, batch_service, root, state_dir, codex=None,
                 max_reviews_per_task=2, review_timeout_s=180,
                 drain_timeout_s=60, backend=None):
        if type(max_reviews_per_task) is not int or not 1 <= max_reviews_per_task <= 8:
            raise ValueError("Experimental model budget must be between one and eight")
        if not 10 <= review_timeout_s <= 180 or not 0 <= drain_timeout_s <= 60:
            raise ValueError("Use bounded review and final-drain timeouts")
        self.tasks, self.batches = task_service, batch_service
        self.root = Path(root).resolve()
        self.directory = Path(state_dir).resolve()
        if self.directory.is_relative_to(self.root):
            raise ValueError("Review state must stay outside the reviewed project")
        self.directory.mkdir(parents=True, exist_ok=True)
        from security_runtime.hook_state import no_links
        no_links(self.directory)
        self.codex, self.maximum = codex, max_reviews_per_task
        self.timeout, self.drain_timeout = review_timeout_s, drain_timeout_s
        if backend is None:
            from codex_readonly_host import run_review
            backend = run_review
        self.backend = backend
        self._lock = threading.RLock()
        self._states = {}
        self._closed = False

    def _bound(self, root, ref):
        if Path(root).resolve() != self.root:
            raise ValueError("Experimental host is bound to another project")
        if not isinstance(ref, str) or not _TASK.fullmatch(ref):
            raise ValueError("Invalid task reference")

    def _state(self, ref):
        if ref not in self._states:
            if len(self._states) >= 32:
                raise ValueError("Experimental host task history is full")
            state = _TaskState()
            from security_runtime.hook_state import no_links
            path = self.directory / ref / "status.json"
            no_links(path)
            if path.is_file():
                try:
                    if path.stat().st_size > 256_000:
                        raise ValueError("Previous host receipt is oversized")
                    saved = json.loads(path.read_text(encoding="utf-8"))
                    if saved.get("task_ref") != ref or not isinstance(saved.get("reviews"), list):
                        raise ValueError("Previous host receipt is invalid")
                    # Old receipts are display/accounting only. Reconnection
                    # never resets a model budget or replays an orphaned batch.
                    state.rows = [row for row in saved["reviews"][:8] if isinstance(row, dict)]
                    if state.rows or saved.get("reviews_started"):
                        state.dispatch_closed = state.final_closed = True
                        state.disabled_reason = "连接已重建；保留旧回执，本任务不重派后台模型，剩余范围交由最终版本核对。"
                        for row in state.rows:
                            if row.get("status") in {"RUNNING", "PARENT_SUBMISSION_PENDING"}:
                                row["status"] = "INTERRUPTED_ON_RECONNECT"
                except (OSError, ValueError, TypeError, UnicodeError):
                    state.dispatch_closed = state.final_closed = True
                    state.disabled_reason = "旧后台回执无法核验；本任务不重派模型，保留最终版本核对。"
            self._states[ref] = state
        return self._states[ref]

    def _persist(self, ref, state):
        # Only operational metadata is copied here. Source, prompts, sessions
        # and credentials are never written to the public status receipt.
        from security_runtime.hook_state import atomic_bytes, no_links
        path = self.directory / ref / "status.json"
        no_links(path)
        value = self._summary(ref, state)
        atomic_bytes(path, (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode())

    def _summary(self, ref, state):
        running = state.active and not state.active.done.is_set()
        return dict(experimental_background_review=True, task_ref=ref,
            message="后台安全分析正在进行，开发可以继续。" if running else
                "后台分析已停止；最终版本仍由当前开发 Agent 核对。" if state.final_closed else
                "后台分析回执可用；最终版本仍需核对。" if state.rows else "尚未启动后台安全分析。",
            running=bool(running), pending_checkpoint=state.pending_key is not None,
            dispatch_closed=state.dispatch_closed, final_closed=state.final_closed,
            disabled_reason=state.disabled_reason, reviews_started=len(state.rows),
            max_reviews_per_task=self.maximum, reviews=[deepcopy({key: value for key, value in row.items()
                if key in _PUBLIC_REVIEW_FIELDS}) for row in state.rows],
            automatic_restart=False, final_review="CURRENT_DEVELOPMENT_AGENT")

    def checkpoint(self, root, task_ref, checkpoint_key, packet):
        self._bound(root, task_ref)
        with self._lock:
            state = self._state(task_ref)
            self._try_submit(task_ref, state)
            if self._closed or state.dispatch_closed or state.disabled_reason:
                return self._summary(task_ref, state)
            if not isinstance(packet, dict) or packet.get("task_ref") != task_ref:
                raise ValueError("Batch packet is not bound to this task")
            if packet.get("status") == "BATCH_QUEUED":
                state.pending_key = checkpoint_key
            elif packet.get("dispatch_required"):
                self._start(task_ref, state, packet)
            self._safe_promote(task_ref, state)
            self._persist(task_ref, state)
            return self._summary(task_ref, state)

    def _start(self, ref, state, packet):
        if state.active is not None:
            # Idempotent checkpoint replays may return the original dispatch.
            if state.active.packet.get("batch_ref") == packet.get("batch_ref"):
                return
            raise ValueError("Only one background review may run for a task")
        if len(state.rows) >= self.maximum:
            state.disabled_reason = "本任务后台模型调用次数已到上限；其余改动交由最终版本核对。"
            return
        historical = (self.tasks.load(self.root, ref).get("batch_state") or {}).get("batches", [])
        position = next((i for i, item in enumerate(historical)
                         if item.get("batch_ref") == packet.get("batch_ref")), None)
        if position is None or position >= self.maximum:
            state.disabled_reason = "签名任务中的批次次数已到本实验上限；其余改动交由最终版本核对。"
            return
        if (not _BATCH.fullmatch(packet.get("batch_ref", ""))
                or not isinstance(packet.get("review_session"), str)
                or not packet["review_session"]):
            raise ValueError("Invalid bound batch packet")
        if any(row["batch_ref"] == packet["batch_ref"] for row in state.rows):
            return
        job_id = uuid.uuid4().hex
        row = dict(job_id=job_id, batch_ref=packet["batch_ref"], status="RUNNING",
            started_at=time.time(), elapsed_ms=None, model_observed=False, usage=None,
            submission_accepted=False, coverage=None, candidate_count=None)
        job = _Job(deepcopy(packet), row)
        state.rows.append(row)
        state.active = job
        job.thread = threading.Thread(target=self._run, args=(ref, job),
            name="experimental-security-" + job_id[:8], daemon=True)
        job.thread.start()

    def _read(self, ref, job, path, start_line=1, end_line=80):
        with self._lock:
            state = self._state(ref)
            if self._closed or state.final_closed or job.cancel.is_set():
                raise ValueError("Background inputs are closed for final review")
            from security_runtime.task_security import TaskContextError
            try:
                value = self.batches.read(self.root, ref, job.packet["batch_ref"],
                    job.packet["review_session"], path, start_line, end_line, "SNAPSHOT")
            except TaskContextError as error:
                return error.response(ref, job.packet["review_session"])
            if value.get("next_read"):
                continuation = value["next_read"]
                value = {**value, "next_read": dict(path=continuation["file_path"],
                    start_line=continuation["start_line"], end_line=continuation["end_line"])}
            return value

    def _run(self, ref, job):
        started = time.monotonic()
        from security_runtime.batch_reviewer import REVIEWER_INSTRUCTIONS
        packet = deepcopy(job.packet)
        packet.pop("review_handoff", None)
        prompt = (REVIEWER_INSTRUCTIONS + "\nRead every changed scope path and relevant unchanged controls. "
            "Evidence fields contain exact issued identifiers, without prose or line suffixes. "
            "Do not duplicate static findings as AI candidates. This is an intermediate snapshot; "
            "final applicability is decided by the parent. Return the supplied JSON contract.\n"
            + json.dumps(packet, ensure_ascii=False))
        try:
            result = self.backend(prompt=prompt, schema=_batch_schema(packet),
                read_context=lambda **kw: self._read(ref, job, **kw),
                output_dir=self.directory / ref / job.row["job_id"], timeout_s=self.timeout,
                codex=self.codex, cancel_event=job.cancel)
            if not isinstance(result, dict):
                raise ValueError("Backend returned an invalid receipt")
        except Exception as error:
            receipt = getattr(error, "receipt", None)
            result = deepcopy(receipt) if isinstance(receipt, dict) else {}
            result.setdefault("status", "HOST_EXCEPTION")
            result["error_type"] = type(error).__name__
        with self._lock:
            state = self._state(ref)
            job.result = result
            job.row.update(elapsed_ms=round((time.monotonic() - started) * 1000, 3),
                host_status=result.get("status"), model_observed=result.get("model_observed") is True,
                usage=deepcopy(result.get("usage")), completed_at=time.time(),
                usage_complete=result.get("usage_complete") is True,
                usage_accounting_may_be_incomplete=(result.get("usage_accounting_may_be_incomplete") is True
                    or result.get("accounting_may_be_incomplete") is True),
                model=result.get("model"), reasoning_effort=result.get("reasoning_effort"),
                error_type=result.get("error_type"))
            if result.get("status") in _UNAVAILABLE:
                state.disabled_reason = "当前宿主只读隔离不可用；本任务停止后台派发，保留最终版本核对。"
            job.done.set()
            if state.final_closed or self._closed or job.cancel.is_set():
                job.row["status"] = "CANCELLED_AT_FINAL" if job.cancel.is_set() else "LATE_RESULT_NOT_SUBMITTED"
                if state.active is job:
                    state.active = None
            else:
                self._try_submit(ref, state)
                self._safe_promote(ref, state)
            self._persist(ref, state)

    def _try_submit(self, ref, state):
        job = state.active
        if not job or not job.done.is_set() or state.final_closed or self._closed:
            return
        result = job.result or {}
        value = result.get("result")
        valid = (result.get("status") == "COMPLETED" and isinstance(value, dict)
            and set(value) == _RESULT_KEYS and all(value.get(key) == job.packet[key]
                for key in ("task_ref", "batch_ref", "review_session")))
        if not valid:
            value = dict(findings=[], coverage="PARTIAL", limitations=[
                "后台模型未完成可接受的结构化审查；此批次不能视为已检查，最终版本需重新核对。"])
        try:
            submission = self.batches.submit(self.root, ref, job.packet["batch_ref"],
                job.packet["review_session"], value["findings"], value["coverage"], value["limitations"])
        except Exception as error:
            job.row.update(status="SUBMISSION_REJECTED", error_type=type(error).__name__)
            state.disabled_reason = "后台回执未被当前任务接受；停止后续派发，最终版本核对将保留此缺口。"
            state.active = None
            return
        if submission.get("status") == "BUSY":
            job.row["status"] = "PARENT_SUBMISSION_PENDING"
            return
        accepted = submission.get("status") == "COMPLETE"
        job.row.update(status=("ACCEPTED" if valid else "FAILED_PARTIAL") if accepted else "SUBMISSION_REJECTED",
            submission_accepted=accepted, coverage=submission.get("coverage"),
            candidate_count=len(submission.get("findings", [])) if accepted else None,
            validity=submission.get("validity"))
        state.active = None

    def _safe_promote(self, ref, state):
        try:
            self._promote(ref, state)
        except Exception:
            # Do not copy arbitrary source/path exception text into status.
            state.disabled_reason = "待处理批次无法继续；本任务停止后台派发，剩余范围交由最终版本核对。"

    def _promote(self, ref, state):
        if (not state.pending_key or state.active or state.dispatch_closed or state.final_closed
                or self._closed or state.disabled_reason):
            return
        if len(state.rows) >= self.maximum:
            state.disabled_reason = "本任务后台模型调用次数已到上限；其余改动交由最终版本核对。"
            return
        record = self.tasks.load(self.root, ref)
        if record["phase"] != "ACTIVE":
            state.dispatch_closed = True
            return
        packet = self.batches.prepare(self.root, ref, state.pending_key)
        if packet.get("dispatch_required"):
            state.pending_key = None
            self._start(ref, state, packet)

    def status(self, root, ref):
        self._bound(root, ref)
        with self._lock:
            state = self._state(ref)
            self._try_submit(ref, state)
            self._persist(ref, state)
            return self._summary(ref, state)

    def stop_dispatch(self, root, ref):
        self._bound(root, ref)
        with self._lock:
            state = self._state(ref)
            state.dispatch_closed = True
            state.pending_key = None
            self._persist(ref, state)

    def before_final(self, root, ref):
        self.stop_dispatch(root, ref)
        deadline = time.monotonic() + self.drain_timeout
        while True:
            with self._lock:
                state = self._state(ref)
                self._try_submit(ref, state)
                job = state.active
                if job is None or time.monotonic() >= deadline:
                    state.final_closed = True
                    if job is not None:
                        job.cancel.set()
                        job.row["status"] = "CANCEL_REQUESTED_AT_FINAL"
                    self._persist(ref, state)
                    return self._summary(ref, state)
            # Only the existing worker/parent submission is drained. No model
            # retry, new checkpoint or new final model is started here.
            if not job.done.is_set():
                job.done.wait(min(.1, max(0, deadline - time.monotonic())))
            else:
                time.sleep(min(.025, max(0, deadline - time.monotonic())))

    def close(self):
        with self._lock:
            self._closed = True
            for ref, state in self._states.items():
                state.dispatch_closed = state.final_closed = True
                state.pending_key = None
                if state.active:
                    state.active.cancel.set()
                    state.active.row["status"] = "CANCEL_REQUESTED_ON_CLOSE"
                self._persist(ref, state)
