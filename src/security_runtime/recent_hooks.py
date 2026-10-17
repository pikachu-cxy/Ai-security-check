"""Bounded, non-authoritative Hook observations; never a security proof store."""
from __future__ import annotations

import contextvars
import hashlib
import json
import os
import sqlite3
import time
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from .codex_host_claims import EVENTS, schema_diagnostics
from .hook_state import no_links
from .storage import ReadOnlySQLiteStore, SQLiteStore

RETENTION = 32
TOTAL_RETENTION = 1024
UNBOUND = hashlib.sha256(b'recent-hook-unbound-v1').hexdigest()
CLOCK_SCOPE = uuid.uuid4().hex
CURRENT = contextvars.ContextVar('recent_hook_observation', default=None)
STAGES = {'HOOK_RECEIVED', 'CLAIMS_VALID', 'CLAIMS_REJECTED', 'READ_ONLY_SKIPPED',
          'RECONCILIATION_STARTED', 'RECONCILIATION_COMPLETED', 'MUTATION_NOT_OBSERVED',
          'SCANNER_TRIGGERED', 'SCANNER_COMPLETED', 'HANDLER_ERROR', 'HANDLER_COMPLETED'}
STAGES |= {'BASELINE_CAPTURE_STARTED', 'BASELINE_PUBLISHED', 'SESSION_FINALIZED'}
CLAIM_FIELDS = {'event', 'workspace_path', 'session_id', 'turn_id', 'tool_use_id',
                'tool_name', 'permission_mode', 'tool_input', 'stop_hook_active',
                'input_shape', 'unexpected_fields'}
CURSOR_EVENTS = {'sessionStart', 'afterFileEdit', 'afterShellExecution', 'stop', 'preToolUse', 'postToolUse'}
CLAIM_FIELDS |= {'conversation_id', 'generation_id', 'hook_event_name', 'workspace_roots', 'file_path', 'command', 'status', 'loop_count'}
STATUS = {'UNKNOWN', 'VALID', 'INVALID', 'REJECTED', 'INCONCLUSIVE', 'NOT_SCANNED',
          'SCANNED', 'FAILED', 'PARTIAL', 'COMPLETED', 'BASELINE_ESTABLISHED', 'NO_CHANGE',
          'NO_CHANGES', 'REUSED_LAST_RESULT', 'DEBOUNCED', 'BUSY', 'READY', 'INITIALIZING',
           'DEGRADED', 'ERROR', 'ALLOW_STOP', 'CONTINUE_SECURITY_FIX'}
STATUS |= {'SESSION_FINALIZED'}
STATUS |= {'BASELINE_CAPTURED', 'BASELINE_PARTIAL', 'BASELINE_UNAVAILABLE',
           'READ_ONLY_OR_UNSUPPORTED', 'DELIVERED', 'NOT_APPLICABLE', 'FOLLOWUP'}
STATUS |= {'CLOSEOUT_PENDING', 'CLOSEOUT_REQUIRED', 'ALLOW_STOP_PENDING'}
REASONS = {'INVALID_HOST_CLAIMS', 'HOST_CLAIMS_REJECTED', 'WORKSPACE_BINDING_REQUIRED',
           'WORKSPACE_OR_REFERENCE_REJECTED', 'WORKSPACE_CLAIM_REQUIRED',
           'GLOBAL_CONFIGURATION_NOT_READY', 'LEGACY_PROJECT_CONFIGURATION_REQUIRES_REPAIR',
           'SESSION_WORKSPACE_MISMATCH', 'TOOL_USE_CLAIM_REPLAYED', 'HOST_CLAIM_BUDGET_EXCEEDED',
           'WORKSPACE_CONNECTION_BUDGET_EXCEEDED', 'SESSION_CONNECTION_BUDGET_EXCEEDED',
           'INVALID_SESSION_CLAIM', 'WORKSPACE_INITIALIZING', 'WORKSPACE_DEGRADED', 'WORKSPACE_ERROR',
           'READ_ONLY_BASH', 'POST_TOOL_USE_MUTATION', 'HOOK_CHECK_INCONCLUSIVE', 'UNSUPPORTED_TOOL',
           'FIRST_SCAN_UNATTRIBUTED_RISK_PRESENT', 'NO_CHANGE', 'NO_CHANGES', 'REUSED_LAST_RESULT',
           'DEBOUNCED', 'BUSY', 'HANDLER_EXCEPTION', 'STRUCTURED_RESULT_UNAVAILABLE', 'OTHER',
            'WORKSPACE_BASELINE_ATTRIBUTION_UNAVAILABLE'}
REASONS |= {'READ_ONLY_ACTIVITY', 'WORKSPACE_CONTENT_DELTA'}
REASONS |= {'CURSOR_REMOTE_NOT_SUPPORTED'}
REASONS |= {'CURSOR_AUTOMATIC_TASK_UNAVAILABLE'}
REASONS |= {'SESSION_STOP_WITHOUT_BASELINE', 'SESSION_BASELINE_ONLY', 'SESSION_FINALIZATION_ONLY',
            'BASELINE_ATTRIBUTION_UNAVAILABLE', 'BASELINE_CAPTURE_FAILED', 'BASELINE_REFERENCE_REJECTED',
            'WORKSPACE_SINGLE_FLIGHT_TIMEOUT'}
CURSOR_WORKSPACE_REJECTIONS = {'CURSOR_WORKSPACE_SOURCE_MISMATCH', 'CURSOR_FILE_WORKSPACE_MISMATCH',
                             'CURSOR_EMPTY_WORKSPACE_UNSUPPORTED', 'CURSOR_MULTI_ROOT_UNSUPPORTED',
                             'CURSOR_PROJECT_DIR_REQUIRED'}
from .cursor_workspace import REJECTIONS as CURSOR_RESOLVER_REJECTIONS
CURSOR_WORKSPACE_REJECTIONS |= CURSOR_RESOLVER_REJECTIONS
BOOL_FIELDS = {'workspace_claim_match', 'session_claim_match', 'turn_claim_present',
               'tool_use_claim_present', 'workspace_mutation_observed', 'scanner_run',
               'workspace_registered', 'session_binding_present', 'snapshot_available',
               'pre_snapshot_match', 'content_delta_detected', 'cursor_project_dir_present',
               'workspace_sources_match', 'generation_id_present', 'generation_id_type_valid',
               'generation_id_shape_valid', 'file_path_containment', 'file_path_absolute',
               'cursor_project_dir_valid', 'workspace_root_relative'}
BOOL_FIELDS |= {'cursor_task_begin_tool'}
BOOL_FIELDS |= {'activity_waited_for_baseline', 'mutation_event_dropped', 'pending_mutation'}
BOOL_FIELDS |= {'first_scan_attribution_attempted', 'pre_edit_targeted_scan_run', 'attribution_scanner_equivalent'}
BOOL_FIELDS |= {'agent_continuation_available'}
BOOL_FIELDS |= {'security_feedback_pending', 'security_feedback_waited', 'security_feedback_deduped',
                'security_feedback_generation_match', 'security_feedback_workspace_match', 'security_feedback_session_match'}
REASONS |= {'FEEDBACK_WAIT_TIMEOUT', 'FEEDBACK_DELIVERY_ONLY'}
REASONS |= {'HOST_CAPABILITY_UNAVAILABLE'}
REASONS |= {'FIRST_SCAN_NO_RISK', 'FIRST_SCAN_EXISTING_RISK', 'FIRST_SCAN_NEW_RISK_ATTRIBUTED', 'FIRST_SCAN_ATTRIBUTION_INCONCLUSIVE'}
for _prefix in ('workspace_root', 'cursor_project_dir'):
    BOOL_FIELDS |= {_prefix+'_'+field for field in
        ('is_absolute', 'exists', 'drive_present', 'git_repo_detected', 'canonicalized')}


def workspace_hash(root):
    return hashlib.sha256(os.path.normcase(str(root)).encode('utf-8')).hexdigest()


def safe_fields(values):
    """Closed enums/field names: neither exception text nor arbitrary metadata."""
    result = {}
    from .bootstrap_diagnostics import BASELINE_REASONS
    for field in ('bootstrap_reason', 'bootstrap_recovered_from'):
        if field in values:
            code = values[field]
            result[field] = code if isinstance(code, str) and code in BASELINE_REASONS else 'UNKNOWN'
    build = values.get('runtime_build_id')
    if isinstance(build, str) and len(build) == 64 and all(c in '0123456789abcdef' for c in build):
        result['runtime_build_id'] = build
    for key, allowed in (
            ('policy_decision', {'NONE', 'ADVISE', 'AUTO_FIX', 'CONFIRM_REQUIRED', 'MANUAL_ONLY', 'ESCALATE'}),
            ('remediation_execution_capability', {'ADVISORY_ONLY', 'AGENT_CONTINUATION', 'UNAVAILABLE'}),
            ('remediation_transport_mode', {'ADVISORY', 'AGENT_CONTINUATION'}),
            ('remediation_status', {'OFFERED', 'NOT_OFFERED', 'INCONCLUSIVE', 'EXISTING_FLOW'}),
            ('remediation_workspace_source', {'VERIFIED_HOST_CONTEXT', 'RUNTIME_WORKSPACE_ARGUMENT', 'UNAVAILABLE'})):
        if key in values:
            value = values[key]
            result[key] = value if isinstance(value, str) and value in allowed else 'UNKNOWN'
    for key, allowed in (
            ('security_feedback_delivery_channel', {'CURSOR_POST_TOOL_USE_ADDITIONAL_CONTEXT'}),
            ('security_feedback_delivery_status', {'NONE', 'PENDING', 'CONTEXT_INJECTED', 'WAIT_TIMEOUT', 'STALE', 'DEDUPED', 'HOST_CAPABILITY_UNAVAILABLE_ON_OBSERVED_PATH'}),
            ('security_feedback_template_version', {'cursor-security-feedback-v1'})):
        if key in values:
            result[key] = values[key] if isinstance(values[key], str) and values[key] in allowed else 'UNKNOWN'
    from .first_scan_attribution import STATUSES, REASONS as ATTRIBUTION_REASONS
    for key, allowed in (('first_scan_attribution_status', STATUSES),
                         ('first_scan_attribution_reason', ATTRIBUTION_REASONS)):
        if key in values:
            value = values[key]
            result[key] = value if value is None or isinstance(value, str) and value in allowed else 'UNKNOWN'
    if isinstance(values.get('host_capabilities'), dict):
        from .host_events import HostCapabilities
        allowed = HostCapabilities.__dataclass_fields__
        capabilities = values['host_capabilities']
        if set(capabilities) == set(allowed) and all(type(v) is bool for v in capabilities.values()):
            result['host_capabilities'] = dict(capabilities)
    from .global_workspace import WORKSPACE_REJECTIONS, WORKSPACE_STAGES
    for prefix in ('workspace_root', 'cursor_project_dir'):
        for suffix, allowed in (
            ('path_style', {'WINDOWS_NATIVE', 'POSIX', 'FILE_URI', 'UNKNOWN'}),
            ('git_probe_status', {'NOT_RUN', 'OK', 'NOT_REPOSITORY', 'DUBIOUS_OWNERSHIP', 'FAILED', 'TIMEOUT', 'UNAVAILABLE'}),
            ('resolution_step', {'PATH_SHAPE', 'FILESYSTEM', 'BOUNDARY', 'GIT_PROBE', 'CANONICAL_RESOLVER', 'COMPLETE'}),
            ('resolution_reason', WORKSPACE_REJECTIONS | CURSOR_WORKSPACE_REJECTIONS)):
            key = prefix+'_'+suffix
            if key in values:
                value = values[key]
                result[key] = value if value is None or isinstance(value, str) and value in allowed else 'UNKNOWN'
    for key, allowed in (('workspace_rejection_reason', WORKSPACE_REJECTIONS | CURSOR_WORKSPACE_REJECTIONS),
                         ('cursor_workspace_rejection_detail', CURSOR_RESOLVER_REJECTIONS),
                         ('cursor_workspace_source', {'WORKSPACE_ROOTS', 'CURSOR_PROJECT_DIR', 'CORROBORATED'}),
                         ('cursor_workspace_anchor', {'CURSOR_PROJECT_DIR'}),
                         ('workspace_roots_state', {'EMPTY_HOST_LIST', 'SINGLE_ABSOLUTE', 'SINGLE_RELATIVE', 'MULTI_ROOT'}),
                         ('workspace_root_corroboration', {'MATCHED', 'UNVERIFIED_RELATIVE', 'EMPTY_HOST_LIST', 'MISMATCH'}),
                         ('workspace_binding_reason', WORKSPACE_REJECTIONS | CURSOR_WORKSPACE_REJECTIONS |
                          {'MATCHED', 'EMPTY_HOST_LIST', 'WORKSPACE_ROOT_RELATIVE_UNVERIFIED'}),
                         ('cursor_workspace_resolution_stage', {'WORKSPACE_ROOTS', 'CURSOR_PROJECT_DIR', 'FILE_CONTAINMENT', 'FILE_WORKSPACE', 'COMPLETE'}),
                         ('generation_id_validation_reason', {'MISSING', 'INVALID_TYPE', 'EMPTY', 'OVERSIZED', 'CONTROL_CHARACTER', 'INVALID_UNICODE', 'VALID', 'NOT_YET_AVAILABLE'}),
                         ('generation_state', {'NOT_YET_AVAILABLE', 'AVAILABLE', 'INVALID'}),
                         ('generation_binding_status', {'NOT_YET_AVAILABLE', 'OBSERVED', 'UNCHANGED', 'UPDATED', 'RETAINED'}),
                         ('tool_use_id_state', {'NOT_APPLICABLE', 'MISSING', 'NULL', 'EMPTY', 'VALID', 'INVALID'}),
                         ('workspace_roots_validation_reason', {'MISSING', 'INVALID_TYPE', 'EMPTY_ROOTS', 'EMPTY_HOST_LIST', 'MULTI_ROOT_UNSUPPORTED', 'INVALID_ROOT', 'VALID'}),
                         ('snapshot_source', {'NONE', 'SESSION_BASELINE', 'SESSION_PROCESSED', 'SETUP_SEED', 'LAZY_BOOTSTRAP'}),
                         ('event_dispatch_route', {'SESSION_BASELINE', 'WORKSPACE_RECONCILIATION', 'SESSION_FINALIZATION'}),
                         ('baseline_state_before', {'AVAILABLE', 'MISSING', 'INVALID'}),
                         ('baseline_state_after', {'AVAILABLE', 'MISSING', 'INVALID'}),
                         ('baseline_publish_status', {'NOT_ATTEMPTED', 'PUBLISHED', 'RETAINED', 'FAILED', 'REJECTED_ACTIVITY_ORDER'}),
                         ('busy_reason', {'WORKSPACE_SINGLE_FLIGHT_TIMEOUT'}),
                         ('reconciliation_reason', {'NO_TRUSTED_PRE_EDIT_SNAPSHOT', 'DIGEST_MATCH', 'CONTENT_DIGEST_DELTA', 'SNAPSHOT_DIGEST_DELTA'}),
                         ('workspace_binding_stage', WORKSPACE_STAGES),
                         ('workspace_relation', {'SAME_ROOT', 'SUBDIRECTORY', 'OUTSIDE_ROOT', 'UNKNOWN'})):
        if key in values:
            value = values[key]
            result[key] = value if value is None or isinstance(value, str) and value in allowed else 'UNKNOWN'
    for key in ('workspace_claim_hash', 'resolved_workspace_hash', 'registered_workspace_hash', 'session_workspace_hash', 'snapshot_generation', 'cursor_project_workspace_hash'):
        if key in values:
            value = values[key]
            result[key] = value if isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value) else None
    for key in BOOL_FIELDS:
        if key in values:
            result[key] = values[key] if type(values[key]) is bool else None
    for key in ('missing_claims', 'invalid_claims'):
        if isinstance(values.get(key), list):
            result[key] = sorted({v for v in values[key][:32] if isinstance(v, str) and v in CLAIM_FIELDS})
    for key in ('host_claim_status', 'handler_status'):
        if key in values:
            value = values[key]
            result[key] = value if isinstance(value, str) and value in STATUS else 'UNKNOWN'
    for key in ('scanner_trigger_reason', 'scanner_skipped_reason', 'handler_reason'):
        if key in values:
            value = values[key]
            result[key] = None if value is None else value if isinstance(value, str) and value in REASONS | WORKSPACE_REJECTIONS | CURSOR_WORKSPACE_REJECTIONS else 'OTHER'
    for key, allowed in (
        ('host', {'codex', 'cursor', 'kiro', 'workbuddy', 'codebuddy', 'qoder', 'generic'}),
        ('host_event_contract', {'host-event-v1'}),
        ('normalized_event_kind', {'SESSION_START', 'WORKSPACE_ACTIVITY', 'SESSION_STOP'}),
        ('normalized_operation_class', {'READ_ONLY', 'DIRECT_FILE_MUTATION', 'POSSIBLE_WORKSPACE_MUTATION', 'UNKNOWN'}),
        ('workspace_binding_status', {'BINDING_CONSISTENT'}),
        ('normalized_scanner_trigger_reason', {'WORKSPACE_CONTENT_DELTA'}),
        ('event_schema', {'codex-' + e + '-v1' for e in EVENTS.values()} | {'cursor-'+e+'-v1' for e in CURSOR_EVENTS}),
        ('tool_name', {'Bash', 'apply_patch', 'Edit', 'Write', 'Shell'}),
        ('tool_classification', {'READ_ONLY', 'DIRECT_FILE_MUTATION', 'POSSIBLE_WORKSPACE_MUTATION', 'UNKNOWN'}),
        ('continuation_status', {'PENDING_CURSOR_CONTINUATION_CAPABILITY'}),
        ('invocation_identity_status', {'UNAVAILABLE_CONTENT_RECONCILIATION_ONLY'}),
    ):
        if key in values:
            result[key] = (None if key == 'normalized_scanner_trigger_reason' and values[key] is None else
                           values[key] if isinstance(values[key], str) and values[key] in allowed else 'UNKNOWN')
    for field in ('changed_file_count', 'snapshot_file_count', 'workspace_root_count', 'generation_id_length', 'scanner_invocation_count',
                  'pre_edit_targeted_scan_count', 'pre_existing_risk_count', 'newly_attributed_risk_count', 'security_feedback_count'):
        if field in values:
            n = values[field]
            result[field] = n if type(n) is int and 0 <= n <= 10000 else None
    if 'activity_wait_ms' in values:
        n = values['activity_wait_ms']
        result['activity_wait_ms'] = n if type(n) in (int,float) and 0 <= n <= 60000 else None
    if 'security_feedback_wait_ms' in values:
        n = values['security_feedback_wait_ms']
        result['security_feedback_wait_ms'] = n if type(n) in (int,float) and 0 <= n <= 60000 else None
    if 'first_scan_attribution_ms' in values:
        n = values['first_scan_attribution_ms']
        result['first_scan_attribution_ms'] = n if type(n) in (int,float) and 0 <= n <= 10**9 else None
    return result


class RecentHookStore:
    def __init__(self, path=None):
        # Caller-controlled Hook arguments never select this location.
        self.path = Path(path) if path is not None else SQLiteStore.default_path().parent/'hook-diagnostics.db'

    def write(self, record, *, create=False):
        no_links(self.path)
        if create:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            no_links(self.path)
        with closing(sqlite3.connect(self.path, timeout=.05)) as db:
            with db:
                db.execute('PRAGMA secure_delete=ON')
                if create:
                    db.execute('CREATE TABLE IF NOT EXISTS recent_hook_diagnostics '
                               '(sequence INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE, workspace TEXT, data TEXT)')
                    db.execute('CREATE INDEX IF NOT EXISTS recent_hook_workspace ON recent_hook_diagnostics(workspace, sequence)')
                payload = json.dumps(record, ensure_ascii=True, separators=(',', ':'))
                if len(payload) > 12000:
                    raise ValueError('Diagnostic budget exceeded')
                if create:
                    db.execute('INSERT INTO recent_hook_diagnostics(id,workspace,data) VALUES(?,?,?)',
                               (record['diagnostic_id'], record['workspace_hash'] or UNBOUND, payload))
                else:
                    updated = db.execute('UPDATE recent_hook_diagnostics SET workspace=?,data=? WHERE id=?',
                                         (record['workspace_hash'] or UNBOUND, payload, record['diagnostic_id']))
                    if not updated.rowcount:
                        return False  # Evicted in-flight records cannot resurrect.
                db.execute('DELETE FROM recent_hook_diagnostics WHERE workspace=? AND sequence NOT IN '
                           '(SELECT sequence FROM recent_hook_diagnostics WHERE workspace=? ORDER BY sequence DESC LIMIT ?)',
                           (record['workspace_hash'] or UNBOUND, record['workspace_hash'] or UNBOUND, RETENTION))
                db.execute('DELETE FROM recent_hook_diagnostics WHERE sequence NOT IN '
                           '(SELECT sequence FROM recent_hook_diagnostics ORDER BY sequence DESC LIMIT ?)', (TOTAL_RETENTION,))
                return True

    def recent(self, root=None, *, limit=16, unbound=False):
        if type(limit) is not int or not 1 <= limit <= RETENTION:
            raise ValueError('Recent limit must be between 1 and 32')
        if root is None and not unbound:
            raise ValueError('A diagnostic workspace is required')
        no_links(self.path)
        key = UNBOUND if unbound else workspace_hash(root)
        rows = ReadOnlySQLiteStore(self.path)._rows('recent_hook_diagnostics',
            'SELECT data FROM recent_hook_diagnostics WHERE workspace=? ORDER BY sequence DESC LIMIT ?', (key, limit))
        records = []
        for row in rows:
            value = json.loads(row[0])
            # Stored diagnostics are untrusted too; never echo unknown content.
            record = {**safe_fields(value)}
            for field in ('diagnostic_id', 'workspace_hash', 'session_hash', 'monotonic_scope'):
                item = value.get(field)
                if item is not None and (not isinstance(item, str) or len(item) not in {32, 64}
                                         or any(c not in '0123456789abcdef' for c in item)):
                    raise ValueError('Invalid diagnostic identity')
                record[field] = item
            if (record['workspace_hash'] or UNBOUND) != key:
                raise ValueError('Invalid diagnostic partition')
            record['event'] = value.get('event') if value.get('event') in set(EVENTS.values()) | CURSOR_EVENTS else 'UNKNOWN'
            stamp = value.get('timestamp')
            try:
                record['timestamp'] = datetime.fromisoformat(stamp).isoformat()
            except (ValueError, TypeError):
                raise ValueError('Invalid diagnostic timestamp') from None
            record['completed'] = value.get('completed') is True
            record['stages'] = []
            for point in value.get('stages', [])[:32]:
                stage, elapsed = point.get('stage'), point.get('elapsed_ms')
                if stage not in STAGES or type(elapsed) not in (int, float) or not 0 <= elapsed <= 10**9:
                    raise ValueError('Invalid diagnostic marker')
                record['stages'].append(dict(stage=stage, elapsed_ms=elapsed))
            record['last_stage'] = record['stages'][-1]['stage'] if record['stages'] else 'UNKNOWN'
            records.append(record)
        return dict(status='OBSERVED' if records else 'NO_RECORDS', records=records, retention=RETENTION,
                    total_retention=TOTAL_RETENTION, diagnostic_only=True, security_proof=False,
                    scope='UNBOUND' if unbound else 'WORKSPACE', workspace_hash=None if unbound else key,
                    note='Absence is not proof of non-delivery: check state namespace, retention and diagnostic write availability.')


class Observation:
    def __init__(self, name, arguments, store=None, *, host='codex', event=None):
        self.store = store or RecentHookStore()
        self.started = time.monotonic()
        self.available = True
        self.persisted = False
        self.expired = False
        args = arguments if isinstance(arguments, dict) else {}
        session = args.get('conversation_id') if host == 'cursor' else args.get('session_id')
        session_hash = (hashlib.sha256(session.encode('utf-8')).hexdigest() if isinstance(session, str)
                        and 0 < len(session) <= 500 and not any(0xD800 <= ord(c) <= 0xDFFF for c in session) else None)
        event = event if host == 'cursor' and event in CURSOR_EVENTS else 'UNKNOWN' if host == 'cursor' else EVENTS[name]
        self.record = dict(diagnostic_id=uuid.uuid4().hex, event=event, event_schema=host+'-'+event+'-v1',
                           timestamp=datetime.now(timezone.utc).isoformat(), monotonic_scope=CLOCK_SCOPE,
                           workspace_hash=None, session_hash=session_hash, stages=[], completed=False,
                           host_claim_status='UNKNOWN', missing_claims=[], invalid_claims=[],
                           workspace_claim_match=None, session_claim_match=None, turn_claim_present=None,
                           tool_use_claim_present=None, tool_name='UNKNOWN', tool_classification='UNKNOWN',
                           workspace_mutation_observed=None, changed_file_count=None,
                           scanner_trigger_reason=None, scanner_skipped_reason=None, scanner_run=None,
                            handler_status='UNKNOWN', handler_reason=None)
        if host == 'cursor':
            self.record['host'] = 'cursor'
        self.record.update(safe_fields({'tool_name': args.get('tool_name')}))
        self.stage('HOOK_RECEIVED')

    def save(self):
        if not self.available or self.expired:
            return
        try:
            if not self.expired:
                self.expired = not self.store.write(self.record, create=not self.persisted)
                self.persisted = True
        except Exception:
            # Diagnostic failure cannot change claims/policy/scanner authority.
            self.available = False

    def bind(self, root):
        self.record['workspace_hash'] = workspace_hash(root)
        self.save()

    def stage(self, stage, **values):
        self.record.update(safe_fields(values))
        if stage in STAGES and (not self.record['stages'] or self.record['stages'][-1]['stage'] != stage):
            self.record['stages'] = (self.record['stages'] + [dict(stage=stage,
                elapsed_ms=round((time.monotonic()-self.started)*1000, 3))])[-32:]
        self.save()

    def finish(self, data):
        # Preserve measured reconciliation facts over the legacy transport's
        # unconditional mutation flag; this projection grants no authority.
        reconciliation = {k: self.record[k] for k in ('workspace_mutation_observed', 'changed_file_count')}
        measured_scanner = self.record['scanner_run']
        self.record.update(safe_fields(data))
        if isinstance(data.get('remediation'), dict):
            self.record.update(safe_fields(data['remediation']))
        if any(p['stage'] == 'RECONCILIATION_COMPLETED' for p in self.record['stages']):
            self.record.update(reconciliation)
        if any(p['stage'] == 'SCANNER_TRIGGERED' for p in self.record['stages']):
            self.record['scanner_run'] = measured_scanner
        self.record.update(safe_fields(dict(handler_status=data.get('status'),
            handler_reason=data.get('reason_code', data.get('reason')))))
        if any(p['stage'] == 'HANDLER_ERROR' for p in self.record['stages']):
            pass  # A transport's generic rejection must not hide an observed exception.
        elif self.record['host_claim_status'] in {'INVALID', 'REJECTED'}:
            self.stage('CLAIMS_REJECTED')
        elif self.record['tool_classification'] == 'READ_ONLY':
            self.stage('READ_ONLY_SKIPPED', scanner_run=False)
        elif data.get('reason') == 'HOOK_CHECK_INCONCLUSIVE':
            self.stage('HANDLER_ERROR')
        elif not any(p['stage'] in {'SCANNER_COMPLETED', 'MUTATION_NOT_OBSERVED', 'HANDLER_ERROR'}
                     for p in self.record['stages']):
            self.stage('HANDLER_COMPLETED')
        if self.record['scanner_run'] is False and not self.record['scanner_skipped_reason']:
            self.record.update(safe_fields(dict(scanner_skipped_reason=data.get('status'))))
        self.record['completed'] = True
        self.save()


def observe(stage, **values):
    observation = CURRENT.get()
    if observation is not None:
        try:
            observation.stage(stage, **values)
        except Exception:
            observation.available = False


def instrument(call, *, schemas, resolve_root, adapter=None):
    """Wrap transport before validation; nested Global→project calls share a row."""
    if adapter is None:
        from .host_event_adapters import event_adapter
        adapter = event_adapter('codex')  # Existing public transport default.
    events = adapter.mcp_events
    async def recorded(name, arguments, *args, **kwargs):
        if name not in events or CURRENT.get() is not None:
            return await call(name, arguments, *args, **kwargs)
        try:
            observation = Observation(name, arguments)
        except Exception:
            return await call(name, arguments, *args, **kwargs)
        token = CURRENT.set(observation)
        try:
            try:
                root = resolve_root(arguments)
                if root is not None:
                    observation.bind(root)
            except Exception:
                pass  # Remains explicitly unbound; no routing/admission grant.
            try:
                diag = adapter.validate_claims(arguments, events[name], schemas[name])
                observation.record.update(safe_fields(diag))
                if diag['host_claim_status'] == 'INVALID':
                    observation.stage('CLAIMS_REJECTED')
            except Exception:
                observation.available = False
            try:
                result = await call(name, arguments, *args, **kwargs)
            except BaseException:
                invalid = observation.record['host_claim_status'] == 'INVALID'
                try:
                    observation.finish(dict(status='INCONCLUSIVE' if invalid else 'ERROR',
                        reason='INVALID_HOST_CLAIMS' if invalid else 'HANDLER_EXCEPTION'))
                    if not invalid:
                        observation.stage('HANDLER_ERROR')
                except Exception:
                    observation.available = False
                raise
            inner = getattr(result, 'root', result)
            data = getattr(inner, 'structuredContent', None)
            if data is None and isinstance(inner, tuple) and len(inner) == 2 and isinstance(inner[1], dict):
                data = inner[1]
            if data is None and isinstance(inner, dict):
                data = inner
            if not isinstance(data, dict):
                invalid = observation.record['host_claim_status'] == 'INVALID'
                if not invalid and getattr(inner, 'isError', False):
                    observe('HANDLER_ERROR', handler_reason='HANDLER_EXCEPTION')
                data_for_record = dict(status='INCONCLUSIVE' if invalid else 'UNKNOWN',
                    reason='INVALID_HOST_CLAIMS' if invalid else 'STRUCTURED_RESULT_UNAVAILABLE')
            else:
                data_for_record = data
            try:
                observation.finish(data_for_record)
            except Exception:
                observation.available = False
            if isinstance(data, dict):
                data.update(recent_hook_diagnostic_id=observation.record['diagnostic_id'] if observation.persisted else None,
                            recent_hook_diagnostic_status='RETENTION_EXPIRED' if observation.expired else
                            'RECORDED' if observation.available else 'WRITE_UNAVAILABLE')
            return result
        finally:
            CURRENT.reset(token)
    return recorded


def install_project_observer(server, binding):
    """Observe SDK requests before its existing validator, without replacing it."""
    from mcp.types import CallToolRequest
    schemas = {t.name: t.parameters for t in server._tool_manager.list_tools()}
    resolver = lambda arguments: Path(binding.root) if binding is not None else None
    manager = server._tool_manager
    manager.call_tool = instrument(manager.call_tool, schemas=schemas, resolve_root=resolver)
    original = server._mcp_server.request_handlers[CallToolRequest]
    async def request_handler(request):
        async def invoke(name, arguments):
            return await original(request)
        return await instrument(invoke, schemas=schemas, resolve_root=resolver)(
            request.params.name, request.params.arguments)
    server._mcp_server.request_handlers[CallToolRequest] = request_handler
