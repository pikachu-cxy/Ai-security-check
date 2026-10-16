"""Parent-only Runtime bridge for the experimental real-host benchmark.

No models are launched here. The host exposes only a bound context callback to
each reviewer, then submits its structured response through this trusted parent.
Set PYTHONPATH to the selected baseline or experimental src before importing.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import threading
import time


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fingerprint(root, *, source=False):
    selected = root / 'src/security_runtime' if source else root
    files = {p.relative_to(root).as_posix(): _sha(p)
             for p in sorted(selected.rglob('*')) if p.is_file()
             and '.git' not in p.relative_to(root).parts
             and (not source or p.suffix in {'.py', '.md', '.json', '.yaml', '.yml'})}
    return hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()


def _finding_schema():
    short = {'type': 'string', 'minLength': 1, 'maxLength': 500}
    text = {'type': 'string', 'minLength': 1, 'maxLength': 1200}
    strings = {'type': 'array', 'maxItems': 10, 'items': deepcopy(short)}
    fields = dict(title=deepcopy(short), category=deepcopy(short),
        severity={'enum': ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']},
        primary_evidence=deepcopy(short), evidence_refs={'type': 'array',
            'minItems': 1, 'maxItems': 10, 'uniqueItems': True, 'items': deepcopy(short)},
        impact=deepcopy(text), preconditions=deepcopy(strings), unknowns=deepcopy(strings),
        counterevidence=deepcopy(strings), fix_advice=deepcopy(text))
    required = list(fields)
    fields.update(risk_scope={'enum': ['TASK_CHANGED', 'RELATED_EXISTING']},
        task_evidence=deepcopy(short), current_protections=deepcopy(strings))
    result = dict(type='object', additionalProperties=False, required=required,
        properties=fields, allOf=[{'if': {'required': ['risk_scope'],
            'properties': {'risk_scope': {'const': 'RELATED_EXISTING'}}},
            'then': {'required': ['task_evidence', 'current_protections'],
                'properties': {'preconditions': {'minItems': 1}, 'unknowns': {'minItems': 1}}}}])
    return _describe_finding_evidence(result)


def _describe_finding_evidence(schema):
    """Explain issued identifiers without relaxing Runtime evidence checks."""
    fields = schema['properties']
    identifier = r'^(?:be1|te1)-[0-9a-f]{32}$'
    fields['primary_evidence'] = dict(fields['primary_evidence'], pattern=identifier, description=
        'One exact evidence identifier issued by the context reader in this review session. '
        'It must occur in evidence_refs. Never add line numbers or explanatory prose to the identifier.')
    fields['evidence_refs'] = {**fields['evidence_refs'], 'items': dict(
        fields['evidence_refs']['items'], pattern=identifier, description=
        'An exact issued evidence identifier from this session, without added text.')}
    fields['task_evidence'] = dict(fields['task_evidence'], pattern=identifier, description=
        'One exact issued evidence identifier for a TASK-CHANGED file, also present in evidence_refs. '
        'This field is an identifier, never an explanation. Put reasoning in impact or counterevidence.')
    return schema


def batch_result_schema(packet):
    from security_runtime.batch_reviewer import _result_schema
    result = _result_schema(packet)
    _describe_finding_evidence(result['properties']['findings']['items'])
    return result


def _allowed_array_items(values, *, description, max_items):
    """Keep empty allowlists enforceable locally and explicit in model text."""
    items = dict(type='string')
    if values:
        items['enum'] = list(values)
    return dict(type='array', maxItems=max_items if values else 0,
        uniqueItems=True, items=items, description=description +
            (' Allowed values: '+json.dumps(list(values), ensure_ascii=False) if values
             else ' No values are allowed; return the empty array [].'))


def final_result_schema(packet):
    """Use the same candidate contract on both sides; no scanner authority."""
    short = {'type': 'string', 'minLength': 1, 'maxLength': 500}
    evidence = {'type': 'array', 'maxItems': 40, 'items': deepcopy(short)}
    properties = dict(task_ref={'const': packet['task_ref']},
        review_session={'const': packet['review_session']},
        coverage={'enum': ['REVIEWED', 'PARTIAL']},
        findings={'type': 'array', 'maxItems': 10, 'items': _finding_schema()},
        limitations={'type': 'array', 'maxItems': 30, 'items': deepcopy(short)})
    required = list(properties)
    if 'batch_review' in packet:
        final_scope = packet['batch_review']['review_scope']
        reusable_refs = [item['batch_ref'] for item in packet['batch_review']['reusable_candidates']]
        disposition_fields = dict(batch_ref=deepcopy(short), candidate_id=deepcopy(short),
            outcome={'enum': ['PRESENT', 'EXCLUDED', 'UNKNOWN']}, evidence_refs={
                'type': 'array', 'minItems': 1, 'maxItems': 10, 'items': deepcopy(short)},
            reason={'type': 'string', 'minLength': 1, 'maxLength': 800})
        disposition_required = list(disposition_fields)
        disposition_fields['primary_evidence'] = deepcopy(short)
        integration = dict(snapshot_id={'const': packet['batch_review']['snapshot_id']},
            batch_refs=_allowed_array_items(reusable_refs, max_items=8, description=
                'Only reusable proof references listed in batch_review.reusable_candidates. '
                'This is not an inventory of historical or inspected batches. Never include STALE, '
                'unfinished or cancelled batches; reading their final code does not make them reusable.'),
            reviewed_paths=_allowed_array_items(final_scope, max_items=1000, description=
                'Only reviewed TASK-CHANGED paths from batch_review.review_scope. '
                'Do not include related unchanged files here; record their issued identifiers '
                'in evidence_refs and discuss their checks instead.'),
            evidence_refs=evidence,
            checks={'type': 'object', 'additionalProperties': False,
                'required': ['authorization', 'data_flow', 'configuration', 'cross_batch_calls'],
                'properties': {k: deepcopy(short) for k in
                    ('authorization', 'data_flow', 'configuration', 'cross_batch_calls')}},
            candidate_dispositions={'type': 'array', 'maxItems': 80, 'items': {
                'type': 'object', 'additionalProperties': False,
                'required': disposition_required, 'properties': disposition_fields}},
            limitations={'type': 'array', 'maxItems': 30, 'items': deepcopy(short)})
        properties['integration_review'] = dict(type='object', additionalProperties=False,
            required=list(integration), properties=integration)
        required.append('integration_review')
    return dict(type='object', additionalProperties=False, required=required,
        properties=properties, allOf=[{'if': {'properties': {'coverage': {'const': 'PARTIAL'}}},
            'then': {'properties': {'limitations': {'minItems': 1}}}}])


class _ObservedRuntime:
    def __init__(self, runtime, bridge):
        self.runtime = runtime
        self.registry = runtime.registry
        self.store = runtime.store
        self.bridge = bridge
        self.calls = []
        self.stage = 'setup'

    def scan(self, root, mode='quick', **kwargs):
        started = time.perf_counter()
        result = self.runtime.scan(root, mode, **kwargs)
        self.calls.append(dict(stage=self.stage, scope=list(kwargs.get('_hook_scope', ())),
            elapsed_ms=round((time.perf_counter()-started)*1000, 3),
            status=result.status, coverage=result.coverage, finding_count=len(result.findings),
            findings=[dict(file_path=f.file_path, line_start=f.line_start,
                rule=f.technical_details.get('rule_id', '')) for f in result.findings],
            scanner_runs=[asdict(run) for run in result.scanner_runs]))
        return result


class RuntimeCase:
    """A fresh fixture workspace, real synchronous Hooks, and parent submissions.

    Both source trees can load this script by file path. Baseline imports never
    touch experimental modules. The reviewer receives no instance of this class.
    """
    def __init__(self, outputdir, initialfiles, *, source=None, side='experimental',
                 task_key='real-host-benchmark'):
        import security_runtime
        from security_runtime.dynamic_function import NativeFunctionScanner, rule_pack
        from security_runtime.hook_runtime import HookCoordinator
        from security_runtime.hook_state import HookStateStore
        from security_runtime.integration_state import WorkspaceBinding
        from security_runtime.runtime import SecurityRuntime
        from security_runtime.scanners import ScannerRegistry
        from security_runtime.storage import SQLiteStore
        from security_runtime.task_security import TaskSecurityService
        if side not in {'baseline', 'experimental'}:
            raise ValueError('Use baseline or experimental')
        self.side = side
        self.source = (Path(source).resolve() if source is not None
                       else Path(security_runtime.__file__).resolve().parents[2])
        if not Path(security_runtime.__file__).resolve().is_relative_to(self.source/'src'):
            raise ValueError('Imported Runtime source differs from selected source')
        self.starting_source_fingerprint = _fingerprint(self.source, source=True)
        self.started = time.perf_counter()
        self.outputdir = Path(outputdir).resolve()
        self.outputdir.mkdir(parents=True, exist_ok=False)
        self.project = self.outputdir/'project'
        self.project.mkdir()
        self.events, self.timings, self.hook_rows, self.batch_rows = [], [], [], []
        self._events_lock = threading.Lock()
        self._step = 0
        self.final_packet = self.finish_result = self.final_result = None
        self._write_changes(initialfiles)
        self.initial_files = self.file_hashes()
        self._git('init', '-q', str(self.project))
        self._git('-C', str(self.project), 'add', '.')
        self._git('-C', str(self.project), '-c', 'user.name=Local benchmark', '-c',
                  'user.email=local-benchmark@example.invalid', 'commit', '-qm', 'benchmark baseline')
        self.hooks = HookStateStore(self.outputdir/'state')
        registry = ScannerRegistry([NativeFunctionScanner()], fallback_adapters=[])
        self.runtime = _ObservedRuntime(SecurityRuntime(registry,
            SQLiteStore(self.outputdir/'scans.db')), self)
        self.core = HookCoordinator(self.runtime, self.hooks, cooldown_ms=0)
        self.binding = WorkspaceBinding('real-host-benchmark', str(self.project),
            str(self.project), 'codex', 'PROJECT', '')
        self.rules_identity = rule_pack().checksum
        self.runtime.stage = 'hook_baseline'
        self.initial_hook = self._measured('hook_baseline', lambda: self.core.handle(
            'SESSION_START', self.project, 'codex', 'real-host-benchmark'))
        self.tasks = TaskSecurityService(self.runtime, self.hooks)
        self.task_ref = self._measured('begin', lambda:
            self.tasks.begin(self.project, task_key))['task_ref']
        self.batches = None
        if side == 'experimental':
            from security_runtime.task_security_batch import TaskSecurityBatchService
            self.batches = TaskSecurityBatchService(self.tasks,
                scan_reader=lambda scan_id: self.runtime.store.get_scan(scan_id))
        self.event('case_ready', source=str(self.source), side=self.side)

    @staticmethod
    def _git(*args):
        return subprocess.run(['git', *args], check=True, capture_output=True, text=True).stdout.strip()

    def event(self, name, **details):
        entry = dict(event=name, at_ms=round((time.perf_counter()-self.started)*1000, 3),
            utc=datetime.now(timezone.utc).isoformat(), **details)
        with self._events_lock:
            self.events.append(entry)
        return entry

    def _measured(self, name, call):
        started = time.perf_counter()
        self.event(name+'_start')
        try:
            value = call()
        except Exception as error:
            self.event(name+'_error', error_type=type(error).__name__, error=str(error)[:500])
            raise
        elapsed = round((time.perf_counter()-started)*1000, 3)
        self.timings.append(dict(stage=name, elapsed_ms=elapsed))
        self.event(name+'_end', elapsed_ms=elapsed, status=value.get('status') if isinstance(value,dict) else None)
        return value

    def _path(self, name):
        if not isinstance(name, str) or '\\' in name or not name or ':' in name:
            raise ValueError('Use a fixture-relative POSIX path')
        relative = Path(name)
        path = (self.project/relative).resolve()
        if relative.is_absolute() or '..' in relative.parts or '.git' in relative.parts or not path.is_relative_to(self.project):
            raise ValueError('Fixture path escapes the project')
        return path

    def _write_changes(self, changes):
        if not isinstance(changes, dict) or not changes:
            raise ValueError('A step needs explicit changed files')
        paths = [(name, self._path(name), text) for name, text in changes.items()]
        if any(text is not None and not isinstance(text,str) for _,_,text in paths):
            raise ValueError('Fixture content must be text or None for deletion')
        for _, path, text in paths:
            if text is None:
                path.unlink()
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding='utf-8')

    def file_hashes(self):
        return {p.relative_to(self.project).as_posix(): _sha(p)
            for p in sorted(self.project.rglob('*')) if p.is_file()
            and '.git' not in p.relative_to(self.project).parts}

    def workspace_fingerprint(self):
        return _fingerprint(self.project)

    def apply_step(self, changes, *, checkpoint=None):
        """Trusted fixed development edits; Hook completion precedes dispatch."""
        from security_runtime.codex_mcp_hook import handle_codex_hook
        self._step += 1
        self.event('development_step_start', step=self._step, files=sorted(changes))
        self._write_changes(changes)
        rows = []
        for index, name in enumerate(changes, 1):
            self.runtime.stage = f'hook_edit_{self._step}_{index}'
            event = self._measured(self.runtime.stage, lambda name=name: handle_codex_hook(
                'PostToolUse', str(self.project), 'real-host-benchmark', 'Write',
                {'file_path': str(self._path(name))}, binding=self.binding, coordinator=self.core))
            row = dict(step=self._step, path=name, **{key: event.get(key) for key in (
                'status', 'scanner_run', 'changed_file_count', 'hook_scope_files', 'hook_check_recording')})
            rows.append(row)
            self.hook_rows.append(row)
        self.event('development_step_end', step=self._step, workspace_sha256=self.workspace_fingerprint())
        return self.prepare_batch(checkpoint) if checkpoint is not None else rows

    def prepare_batch(self, checkpoint):
        if self.batches is None:
            raise ValueError('Baseline does not dispatch intermediate reviewers')
        before = len(self.runtime.calls)
        packet = self._measured('batch_prepare', lambda: self.batches.prepare(
            self.project, self.task_ref, checkpoint))
        if len(self.runtime.calls) != before:
            raise RuntimeError('Batch preparation unexpectedly scanned source')
        self.batch_rows.append(dict(checkpoint=checkpoint, batch_ref=packet.get('batch_ref'),
            prepare_status=packet.get('status'), prepare_scanner_calls=0))
        return packet

    def _validate_batch_binding(self, packet):
        if self.batches is None or packet.get('task_ref') != self.task_ref:
            raise ValueError('Batch binding differs from this case')

    def read_batch_bound(self, packet, path, start_line=1, end_line=80):
        self._validate_batch_binding(packet)
        result = self._measured('batch_context_read', lambda: self.batches.read(self.project,
            self.task_ref, packet['batch_ref'], packet['review_session'], path, start_line, end_line))
        self.event('batch_evidence_issued', batch_ref=packet['batch_ref'], path=path,
            start_line=start_line, end_line=end_line, evidence_id=result.get('evidence_id'))
        return result

    @staticmethod
    def _validate_result(value, schema):
        from jsonschema import Draft202012Validator
        Draft202012Validator(schema).validate(value)

    def submit_batch(self, packet, model_result):
        self._validate_batch_binding(packet)
        self._validate_result(model_result, batch_result_schema(packet))
        result = self._measured('batch_parent_submit', lambda: self.batches.submit(self.project,
            self.task_ref, packet['batch_ref'], packet['review_session'],
            model_result['findings'], model_result['coverage'], model_result['limitations']))
        for row in reversed(self.batch_rows):
            if row['batch_ref'] == packet['batch_ref']:
                row['result'] = result
                break
        return result

    def finish_static(self):
        """Close development with one synchronous static check.

        An already running reviewer can still return evidence/candidates while
        the parent is READY. The controller drains it before final preparation.
        """
        if self.finish_result is not None:
            return self.finish_result
        self.runtime.stage = 'task_finish'
        self.finish_result = self._measured('task_finish', lambda:
            self.tasks.finish(self.project, self.task_ref))
        return self.finish_result

    def finish_prepare_final(self):
        if self.final_packet is not None:
            return self.final_packet
        self.finish_static()
        before = len(self.runtime.calls)
        self.final_packet = self._measured('final_prepare', lambda:
            self.tasks.prepare(self.project, self.task_ref))
        if len(self.runtime.calls) != before:
            raise RuntimeError('Final preparation unexpectedly repeated the finished scan')
        return self.final_packet

    def read_final_bound(self, path, start_line=1, end_line=80, source_version='CURRENT'):
        if self.final_packet is None or 'review_session' not in self.final_packet:
            raise ValueError('Final review is not ready')
        result = self._measured('final_context_read', lambda: self.tasks.read(self.project,
            self.task_ref, self.final_packet['review_session'], path, start_line, end_line, source_version))
        self.event('final_evidence_issued', path=path, start_line=start_line, end_line=end_line,
            evidence_id=result.get('evidence_id'))
        return result

    def submit_final(self, model_result):
        if self.final_packet is None:
            raise ValueError('Final review is not ready')
        self._validate_result(model_result, final_result_schema(self.final_packet))
        extra = ({'integration_review': model_result['integration_review']}
                 if 'batch_review' in self.final_packet else {})
        self.final_result = self._measured('final_parent_submit', lambda: self.tasks.submit(
            self.project, self.task_ref, self.final_packet['review_session'],
            model_result['findings'], model_result['coverage'], model_result['limitations'], **extra))
        return self.final_result

    def receipt(self):
        ending_source = _fingerprint(self.source, source=True)
        return dict(side=self.side, source=str(self.source),
            source_commit=self._git('-C', str(self.source), 'rev-parse', 'HEAD'),
            source_tree_sha256=self.starting_source_fingerprint,
            source_unchanged=ending_source == self.starting_source_fingerprint,
            static_provider='native-js-function', rules_identity=self.rules_identity,
            static_execution='REAL_BUNDLED_LOCAL_PROVIDER', application_executed=False,
            task_ref=self.task_ref, workspace=str(self.project),
            initial_hook_status=self.initial_hook.get('status'),
            initial_files=self.initial_files, final_files=self.file_hashes(),
            workspace_sha256=self.workspace_fingerprint(), hooks=deepcopy(self.hook_rows),
            scans=deepcopy(self.runtime.calls), scan_count=len(self.runtime.calls),
            timings=deepcopy(self.timings), events=deepcopy(self.events),
            batches=deepcopy(self.batch_rows),
            batch_summary=self.batches.get(self.project, self.task_ref) if self.batches else None,
            finish_result=deepcopy(self.finish_result), final_packet=deepcopy(self.final_packet),
            final_result=deepcopy(self.final_result), task=self.tasks.get(self.project, self.task_ref))
