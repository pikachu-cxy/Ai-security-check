"""View model for the optional sidecar; writes only monitor preferences.

No product state, task ledger, scanner, model or host configuration is touched.
Manual task windows live only in this process and are never security tasks.
"""
from __future__ import annotations

import threading
import time

from ..context_report import phase_for, percentile, timing
from ..token_usage import TOKEN_FIELDS
from .host_reader import HostReader, canonical_project

SCOPES = ('all', 'chat', 'project', 'task', 'scan')
SCAN_ENTRIES = frozenset({'scan_diff', 'scan_project', 'scan_files'})


def entry_kind(tool):
    """Public entry categories, not proof of an internal scan or business purpose."""
    if tool in SCAN_ENTRIES:
        return 'scan_entry'
    if tool.startswith(('begin_', 'finish_', 'prepare_', 'read_task_', 'get_task_',
                        'submit_', 'handle_', 'verify', 'run_closeout')):
        return 'review_flow'
    return 'other_runtime'


class MonitorService:
    def __init__(self, store, *, project=None, chat_log=None, run=None):
        self.store = store
        self.project = canonical_project(project) if project is not None else None
        self.run = run
        self.reader = HostReader(chat_log, project)
        self.lock = threading.RLock()
        self.started_at = time.time()
        self.window = None
        self.window_baseline = None
        self.window_host_identity = None
        self.window_host_end = None
        self.window_monotonic_start = None
        self.window_elapsed_ms = None
        self.samples = []

    def task(self, action):
        with self.lock:
            host = self.reader.poll()
            if action == 'start':
                self.window = dict(started_at=time.time(), finished_at=None)
                self.window_baseline = host['usage'] if host['status'] == 'AVAILABLE' else None
                self.window_host_identity = self.reader.identity
                self.window_host_end = None
                self.window_monotonic_start = time.monotonic()
                self.window_elapsed_ms = None
            elif action == 'stop' and self.window is not None:
                if self.window['finished_at'] is not None:
                    raise ValueError('INVALID_TASK_ACTION')
                self.window['finished_at'] = time.time()
                self.window_host_end = host['usage'] if host['status'] == 'AVAILABLE' else None
                self.window_elapsed_ms = max(0, (time.monotonic()-self.window_monotonic_start)*1000)
            else:
                raise ValueError('INVALID_TASK_ACTION')
            return dict(status='AVAILABLE', window=self.window)

    def set_mode(self, mode):
        with self.lock:
            if mode not in {'off', 'basic', 'debug'}:
                raise ValueError('INVALID_MODE')
            return self.store.set_monitoring(mode)

    def _project_events(self, events):
        if self.project is None or not events:
            return []
        try:
            key = self.store._key()
            selector = self.store._digest(key, 'workspace', self.project)
            return [item for item in events if item.get('workspace_hash') == selector]
        except Exception:
            return []

    def snapshot(self, scope='all'):
        if scope not in SCOPES:
            raise ValueError('INVALID_SCOPE')
        with self.lock:
            started = time.monotonic()
            now = time.time()
            host = self.reader.poll()
            saved = self.store.snapshot(self.run)
            events = saved.get('events', [])
            unassociated = sum(not item.get('workspace_hash') for item in events)
            matching = self._project_events(events)
            window = dict(self.window) if self.window is not None else None
            window_untimed = 0
            selected = events if scope == 'all' else matching if scope == 'project' else [
                item for item in events if item['tool'] in SCAN_ENTRIES] if scope == 'scan' else []
            host_usage = host['usage'] if scope in {'all', 'chat'} else host['project_usage'] if scope == 'project' else None
            token_scope = 'CURRENT_CHAT_CUMULATIVE' if scope in {'all', 'chat'} else 'SELECTED_CHAT_PROJECT_DELTAS_PARTIAL'
            if scope == 'scan':
                token_scope = 'UNKNOWN_NO_SCAN_USAGE_LINK'
            if scope == 'task':
                token_scope = 'MANUAL_WINDOW_CURRENT_CHAT_COUNTER_DELTA; NOT_PRODUCT_TASK_IDENTITY'
                if window:
                    candidates = matching if self.project else events
                    # Basic/legacy records cannot be assigned to or excluded
                    # from a manual window. Keep timed details, not false totals.
                    window_untimed = sum(item.get('started_at') is None or item.get('finished_at') is None
                                        for item in candidates)
                    # A tool must start and end inside this observation window.
                    selected = [item for item in candidates
                                if item.get('started_at') is not None and item.get('finished_at') is not None
                                and item['started_at'] >= window['started_at']
                                and item['finished_at'] <= (window['finished_at'] or now)]
                    end = self.window_host_end if window['finished_at'] is not None else host['usage']
                    before = self.window_baseline
                    if (before is not None and end is not None and self.window_host_identity == self.reader.identity
                            and (window['finished_at'] is not None or host['status'] == 'AVAILABLE')
                            and all(end[name] >= before[name] for name in TOKEN_FIELDS)):
                        host_usage = {name: end[name] - before[name] for name in (*TOKEN_FIELDS, 'total_tokens')}
            groups = {}
            categories = {kind: dict(kind=kind, calls=0, elapsed_ms=0)
                          for kind in ('scan_entry', 'review_flow', 'other_runtime')}
            for event in selected:
                category = categories[entry_kind(event['tool'])]
                category['calls'] += 1
                category['elapsed_ms'] += event['elapsed_ms']
                row = groups.setdefault(event['tool'], dict(tool=event['tool'], phase=phase_for(event['tool']),
                    calls=0, errors=0, elapsed_ms=0, wire_bytes=0, samples=[]))
                row['calls'] += 1
                row['errors'] += not event['succeeded']
                row['elapsed_ms'] += event['elapsed_ms']
                row['wire_bytes'] += event['wire_bytes']
                row['samples'].append(event['elapsed_ms'])
            for row in groups.values():
                values = row.pop('samples')
                row.update(p50_ms=percentile(values, .5), p95_ms=percentile(values, .95))
            fields = ('tool', 'run_label', 'started_at', 'finished_at', 'elapsed_ms', 'wire_bytes', 'succeeded')
            details = [dict({name: event.get(name) for name in fields}, phase=phase_for(event['tool']))
                       for event in selected[:1000]]
            if host['usage'] is not None and (not self.samples or self.samples[-1]['total_tokens'] != host['usage']['total_tokens']):
                self.samples.append(dict(at=host['as_of'] or now, total_tokens=host['usage']['total_tokens']))
                self.samples = self.samples[-240:]
            timing_data = timing(selected)
            window_elapsed = None if window is None else round(self.window_elapsed_ms if
                self.window_elapsed_ms is not None else max(0, (time.monotonic()-self.window_monotonic_start)*1000), 3)
            known = (saved['status'] == 'AVAILABLE' and scope != 'chat'
                     and (scope != 'task' or window is not None and not window_untimed))
            return dict(status='AVAILABLE' if saved['status'] == 'AVAILABLE' and not saved.get('invalid') and not window_untimed else 'PARTIAL',
                generated_at=now, scope=scope, monitoring=self.store.monitoring(),
                project_name=self.project.rsplit('/', 1)[-1].rsplit('\\', 1)[-1] if self.project else None,
                run=self.run, host=host, usage=host_usage, token_scope=token_scope,
                tool_scope='EXPLICIT_SCAN_ENTRY_CALLS; NOT_ALL_INTERNAL_SCANS; NOT_ENGINE_TIME' if scope == 'scan' else
                    'SELECTED_RETAINED_RUNS' if scope == 'all' else
                    'WORKSPACE_PARAMETER_ASSOCIATION' if scope == 'project' else
                    'UNLINKED_TO_CHAT' if scope == 'chat' else 'TIME_WINDOW_NOT_PROVEN_TASK_OWNERSHIP',
                tools_known=known, calls=len(selected) if known else None,
                elapsed_ms=sum(item['elapsed_ms'] for item in selected) if known else None,
                wire_bytes=sum(item['wire_bytes'] for item in selected) if known else None,
                errors=sum(not item['succeeded'] for item in selected) if known else None,
                groups=sorted(groups.values(), key=lambda item: item['elapsed_ms'], reverse=True),
                entry_categories=list(categories.values()) if known else [],
                attribution=dict(chat_total_tokens=host['usage'], development_only_tokens=None,
                    product_scan_tokens=None, engine_elapsed_ms=None,
                    reason='NO_VERIFIED_MODEL_USAGE_TO_SCAN_OR_DEVELOPMENT_LINK'),
                events=details, details_omitted=max(0, len(selected)-len(details)),
                invalid_records=saved.get('invalid', 0), unassociated_project_calls=unassociated,
                project_observed_calls=len(matching), timing=timing_data, window=window,
                window_untimed_retained_calls=window_untimed,
                window_elapsed_ms=window_elapsed,
                host_samples=list(self.samples) if scope in {'all', 'chat'} else [],
                monitor_read_ms=round((time.monotonic()-started)*1000, 3),
                coverage='MCP_ONLY; HOST_USAGE_FROM_ONE_EXPLICIT_FILE; OTHER_CHATS_NOT_DISCOVERED',
                task_scope='MANUAL_OBSERVATION_WINDOW; NOT_RUNTIME_SECURITY_TASK',
                refresh_seconds=2)
