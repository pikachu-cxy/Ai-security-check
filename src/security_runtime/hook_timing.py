"""Bounded observation metadata, never execution authorization or policy."""
from enum import Enum
import time
from time import perf_counter
import math
import os
from pathlib import Path
import threading


class ExecutionTrigger(str, Enum):
    HOOK = 'HOOK'
    MANUAL = 'MANUAL'
    STOP = 'STOP'
    PR = 'PR'
    CI = 'CI'
    SCHEDULED = 'SCHEDULED'


PHASES = ('hook_total', 'scanner', 'finding_policy', 'remediation_preparation',
          'auto_remediation', 'security_rescan')

CYCLE_POINTS = (
    'risk_hook_started', 'initial_scan_finished', 'auto_fix_authorization_started',
    'auto_fix_authorized', 'policy_finished', 'initial_hook_response_ready',
    'host_continuation_observed', 'prepare_task_fix_started',
    'prepare_task_fix_finished', 'fix_edit_hook_started', 'host_edit_observed',
    'security_rescan_started',
    'security_rescan_finished', 'episode_closed', 'return_to_host',
    'fast_fix_plan_ready', 'fast_fix_apply_authorized', 'host_fast_edit_observed',
    'inline_prepare_started', 'inline_prepare_finished', 'consent_handoff_ready')

CYCLE_SEGMENTS = {
    'initial_runtime': ('risk_hook_started', 'initial_hook_response_ready'),
    'runtime_to_host_continuation_wait': ('initial_hook_response_ready', 'host_continuation_observed'),
    'continuation_to_prepare': ('host_continuation_observed', 'prepare_task_fix_started'),
    'prepare_fix': ('prepare_task_fix_started', 'prepare_task_fix_finished'),
    'host_fix_window': ('prepare_task_fix_finished', 'fix_edit_hook_started'),
    'post_edit_hook': ('fix_edit_hook_started', 'security_rescan_started'),
    'security_rescan': ('security_rescan_started', 'security_rescan_finished'),
    'close/finalization': ('security_rescan_finished', 'return_to_host'),
}

FAST_CYCLE_SEGMENTS = {
    'initial_runtime': ('risk_hook_started', 'initial_hook_response_ready'),
    'host_fast_apply_window': ('initial_hook_response_ready', 'fix_edit_hook_started'),
    'post_edit_hook': ('fix_edit_hook_started', 'security_rescan_started'),
    'security_rescan': ('security_rescan_started', 'security_rescan_finished'),
    'close/finalization': ('security_rescan_finished', 'return_to_host'),
}

INLINE_CYCLE_SEGMENTS = {
    'initial_runtime': ('risk_hook_started', 'initial_hook_response_ready'),
    'inline_host_edit_window': ('initial_hook_response_ready', 'fix_edit_hook_started'),
    'post_edit_hook': ('fix_edit_hook_started', 'security_rescan_started'),
    'security_rescan': ('security_rescan_started', 'security_rescan_finished'),
    'close/finalization': ('security_rescan_finished', 'return_to_host'),
}

UNKNOWN_POINTS = ('initial_hook_response_sent', 'host_received_advisory',
                  'host_fix_started', 'host_edit_completed')
DETAILS = ('initial_scanner', 'initial_finding_policy', 'auto_fix_authorization',
           'post_edit_scanner')


def timings():
    # null means not observed/not executed, never a fabricated zero duration.
    return dict.fromkeys(PHASES)


def elapsed(start):
    return round(max(0, time.perf_counter() - start) * 1000, 3)


def core_context(trigger=ExecutionTrigger.HOOK):
    return {'trigger': trigger.value, 'profile': 'CORE',
            'timing_contract': 'core-hook-timing-v1',
            'auto_remediation_measurement': 'HOST_CONTINUATION_WINDOW_NOT_EDIT_CPU_TIME',
            'unobserved_duration': None}


class RemediationCycles:
    """Bounded connection observations; never persist, authorize, or infer Host CPU."""
    def __init__(self, clock=perf_counter):
        self.clock = clock
        self.entries = {}
        self.lock = threading.RLock()

    @staticmethod
    def key(root, episode):
        return os.path.normcase(str(Path(root).resolve())), episode

    @staticmethod
    def _number(value):
        return type(value) in (float, int) and math.isfinite(value) and value >= 0

    def _now(self):
        try:
            value = self.clock()
            return value if self._number(value) else None
        except Exception:
            return None

    @staticmethod
    def _instance():
        from .scanner_cache import lifetime
        return lifetime()['runtime_instance_id']

    def start(self, root, episode, started, *, token_hash=None, scope=None, points=None, detail=None,
              fix_path='AGENT_FIX'):
        now = self._now()
        if now is None or not self._number(started) or started > now:
            return
        key = self.key(root, episode)
        with self.lock:
            if key in self.entries:
                # A validated retry may rotate a grant, never restart this Episode.
                entry = self.entries[key]
                if entry['instance'] == self._instance() and entry['end'] is None:
                    if entry.get('token_hash') is not None and entry.get('token_hash') != token_hash:
                        entry['retried'] = True
                    entry['token_hash'] = token_hash
                return
            if len(self.entries) >= 32:
                self.entries.pop(next(iter(self.entries)))
            observed = {name: value for name, value in (points or {}).items()
                        if name in CYCLE_POINTS and self._number(value) and started <= value <= now}
            observed['risk_hook_started'] = started
            self.entries[key] = dict(start=started, end=None, instance=self._instance(),
                token_hash=token_hash, scope=scope, points=observed, continuation_source=None,
                fix_path=fix_path if fix_path == 'DETERMINISTIC_FAST_FIX' else 'AGENT_FIX',
                rechecks=0, retried=False,
                detail={name: round(value, 3) for name, value in (detail or {}).items()
                        if name in DETAILS and self._number(value)})

    def bind_grant(self, root, episode, token_hash):
        """Observe confirmation without renewing start time or granting authority."""
        with self.lock:
            entry = self.entries.get(self.key(root, episode))
            if entry and entry['instance'] == self._instance() and entry['end'] is None:
                entry['token_hash'] = token_hash

    def _put(self, entry, point, at, source=None):
        now = self._now()
        value = now if at is None else at
        if (entry is None or entry['instance'] != self._instance() or entry['end'] is not None
                or point not in CYCLE_POINTS or now is None or not self._number(value)
                or not entry['start'] <= value <= now):
            return False
        if point not in entry['points']:
            entry['points'][point] = value
            if point == 'host_continuation_observed' and source in ('STOP_GUARD', 'PREPARE_REQUEST'):
                entry['continuation_source'] = source
        if point == 'security_rescan_started':
            entry['rechecks'] += 1
        return True

    def mark(self, root, episode, point, at=None, *, source=None):
        with self.lock:
            return self._put(self.entries.get(self.key(root, episode)), point, at, source)

    def set_fix_path(self, root, episode, fix_path):
        with self.lock:
            entry = self.entries.get(self.key(root, episode))
            if (entry and entry['instance'] == self._instance() and entry['end'] is None
                    and fix_path in {'AGENT_FIX', 'DETERMINISTIC_FAST_FIX'}):
                entry['fix_path'] = fix_path

    def set_inline(self, root, episode, value=True):
        with self.lock:
            entry = self.entries.get(self.key(root, episode))
            if entry and entry['instance'] == self._instance() and entry['end'] is None:
                entry['inline_prepared'] = bool(value)

    def mark_token(self, token_hash, point, at=None, *, root, source=None):
        # Only an already validated record may supply this internal hash/root pair.
        if not isinstance(token_hash, str) or not token_hash:
            return False
        root_key = self.key(root, None)[0]
        with self.lock:
            matches = [entry for key, entry in self.entries.items()
                       if key[0] == root_key and entry.get('token_hash') == token_hash]
            return len(matches) == 1 and self._put(matches[0], point, at, source)

    def detail(self, root, episode, name, value):
        with self.lock:
            entry = self.entries.get(self.key(root, episode))
            if (entry and entry['instance'] == self._instance() and entry['end'] is None
                    and name in DETAILS and self._number(value)):
                entry['detail'].setdefault(name, round(value, 3))

    @staticmethod
    def _relative(entry):
        values = {name: (round((entry['points'][name] - entry['start']) * 1000, 3)
                         if name in entry['points'] else None) for name in CYCLE_POINTS}
        values.update(dict.fromkeys(UNKNOWN_POINTS))
        return values

    @staticmethod
    def _breakdown(entry, wall):
        points = entry['points']
        fast = entry.get('fix_path') == 'DETERMINISTIC_FAST_FIX'
        inline = entry.get('inline_prepared', False)
        segments = FAST_CYCLE_SEGMENTS if fast else INLINE_CYCLE_SEGMENTS if inline else CYCLE_SEGMENTS
        values, intervals = {}, []
        invalid = False
        for name, (left, right) in segments.items():
            if (name in {'inline_host_edit_window', 'host_fast_apply_window'} and
                    'consent_handoff_ready' in points):
                left = 'consent_handoff_ready'  # Never include waiting for consent in an edit window.
            values[name] = None
            if name == 'close/finalization' and (entry['retried'] or entry['rechecks'] > 1):
                continue  # Later Host/retry work cannot be called Runtime finalization.
            if left in points and right in points:
                if points[right] < points[left]:
                    invalid = True
                else:
                    values[name] = round((points[right] - points[left]) * 1000, 3)
                    intervals.append((points[left], points[right]))
        previous = entry['start']
        for left, right in sorted(intervals):
            if left < previous:
                invalid = True
            previous = max(previous, right)
        if invalid:
            values = dict.fromkeys(segments)
        # Only disjoint endpoint spans enter this partition. Nested scanner/policy
        # detail values are separate and are never added to the wall clock.
        known = sum(value for value in values.values() if value is not None)
        values['unaccounted'] = round(max(0, wall - known), 3) if wall is not None else None
        status = 'UNKNOWN' if invalid else ('OBSERVED' if all(values[n] is not None for n in segments) else 'PARTIAL')
        if fast or inline:
            # Nonexistent Agent windows stay null; never hide Host delay as zero.
            values.update({name:None for name in CYCLE_SEGMENTS if name not in segments})
        return values, {'status': status, 'reason_code': 'OVERLAPPING_OR_REVERSED_ENDPOINTS' if invalid else None,
                        'detail_values_additive': False, 'rounding_tolerance_ms': 0.01}

    def result(self, root, episode, *, complete=False):
        value = None
        status, reason = 'NOT_APPLICABLE', 'NO_REMEDIATION_EPISODE'
        timing = dict.fromkeys(('remediation_cycle_timepoints_ms', 'remediation_cycle_breakdown_ms',
                               'remediation_cycle_boundary', 'remediation_cycle_detail_ms',
                               'remediation_cycle_breakdown_measurement'))
        if episode is not None:
            status, reason = 'UNKNOWN', 'CYCLE_START_NOT_OBSERVED_IN_THIS_CONNECTION'
            with self.lock:
                entry = self.entries.get(self.key(root, episode))
                if entry and entry['instance'] == self._instance():
                    now = self._now()
                    if now is None or now < max(entry['points'].values()) or now < (entry['end'] or entry['start']):
                        reason = 'MONOTONIC_CLOCK_NOT_CONTINUOUS'
                    else:
                        status, reason = 'IN_PROGRESS', None
                        if complete and entry['end'] is None:
                            entry['end'] = now
                            entry['points'].setdefault('return_to_host', now)
                        if entry['end'] is not None:
                            status = 'OBSERVED'
                            value = round((entry['end'] - entry['start']) * 1000, 3)
                        timing['remediation_cycle_timepoints_ms'] = self._relative(entry)
                        timing['remediation_cycle_breakdown_ms'], timing['remediation_cycle_breakdown_measurement'] = self._breakdown(entry, value)
                        timing['remediation_cycle_detail_ms'] = {name: entry['detail'].get(name) for name in DETAILS}
                        timing['remediation_cycle_boundary'] = {
                            'initial_runtime': 'RUNTIME_ADAPTER_TO_RESPONSE_READY; includes scanner/policy',
                            'runtime_to_host_continuation_wait': 'CROSS_BOUNDARY_WINDOW; Host/transport/queue components UNKNOWN',
                            'continuation_to_prepare': 'CROSS_BOUNDARY_WINDOW_AFTER_STOP; not Host CPU',
                            'prepare_fix': 'RUNTIME_MCP_TOOL_FUNCTION; excludes MCP transport',
                            'host_fix_window': 'HOST_AGENT_AND_TRANSPORT_WINDOW; exact edit duration UNKNOWN',
                            'post_edit_hook': 'RUNTIME_HOOK_PROCESSING; includes post-edit incremental scanner',
                            'security_rescan': 'SCANNER_PROCESSING + RUNTIME_PROCESSING',
                            'close/finalization': 'RUNTIME_PROOF_GUARDS_AND_STATE_COMMIT_TO_RETURN_DECISION',
                            'unaccounted': 'UNATTRIBUTED_ENDPOINT_RESIDUAL',
                            'user_consent_wait': 'INCLUDED_IN_WALL; NOT_EDIT_CPU; may remain in unaccounted',
                            'host_continuation_source': entry['continuation_source'],
                            'multiple_attempts_observed': entry['retried'] or entry['rechecks'] > 1,
                            'endpoint_observation': 'FIRST_VALID_PREPARE_AND_FIRST_RECHECK; retries remain in residual',
                            'fix_path': entry.get('fix_path', 'AGENT_FIX'),
                        }
                        if entry.get('fix_path') == 'DETERMINISTIC_FAST_FIX':
                            timing['remediation_cycle_boundary'].update(
                                host_fast_apply_window='HOST_BRIDGE_AND_TRANSPORT_WINDOW; Host CPU UNKNOWN',
                                endpoint_observation='PLAN_READY_TO_POST_EDIT; no Agent prepare endpoint')
                        if entry.get('inline_prepared'):
                            timing['remediation_cycle_boundary'].update(
                                agent_fix_ticket_mode='INLINE_PREPARED',
                                inline_host_edit_window='RESPONSE_READY_TO_POST_EDIT; Host/Agent/transport components UNKNOWN',
                                endpoint_observation='INLINE_PREPARATION_INSIDE_INITIAL_RUNTIME; no prepare MCP endpoint')
        return {'remediation_cycle_wall_ms': value, 'remediation_cycle_measurement': {
            'status': status, 'reason_code': reason, 'scope': 'CONNECTION_MONOTONIC',
            'definition': 'FIRST_RISK_HOOK_ENTRY_TO_SCANNER_RESOLVED_CLOSED_RETURN_DECISION'}, **timing}
