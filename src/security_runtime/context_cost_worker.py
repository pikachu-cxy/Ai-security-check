"""Optional bounded metadata collector; product calls never wait for storage.

Only copied, allowlisted scalars reach the queue. The daemon owns all settings,
lease and database access. It is deliberately not an exit-time flush service.
"""
from __future__ import annotations

import os
import queue
import re
import secrets
import threading
import time

CAPACITY = 256
MAX_LINKS = 64
_HEX = re.compile(r'[a-f0-9]{64}\Z')
_CALL_ID = re.compile(r'[A-Za-z0-9_-]{1,64}\Z')
_RELATIONS = frozenset({'TASK_RECORD_READ', 'TASK_CREATED', 'TASK_RESULT_RETURNED',
    'SCAN_PERSISTED', 'HOST_EVENT_CLAIMED', 'HOST_EVENT_REUSED',
    'HOST_EVENT_UNCONFIRMED', 'HOST_EVENT_REFERENCED', 'TASK_EVENT_TARGET', 'SCAN_RECORD_READ'})
_FLAGS = frozenset({'scanner_run', 'cache_reused', 'cache_reuse', 'reused',
                    'full_project_reusable'})
_FIELDS = frozenset({'tool', 'tool_name', 'transport', 'succeeded', 'elapsed_ms',
    'started_at', 'finished_at', 'connection_id', 'workspace', 'run_label', 'mode',
    'chat_owner', 'measurements', 'observations', 'correlation', 'collection', 'model_request', 'product_fact'})


def _number(value, maximum, *, floating=False):
    types = (int, float) if floating else (int,)
    if type(value) not in types or not 0 <= value <= maximum:
        raise ValueError('INVALID_OBSERVATION_METADATA')
    return value


def _text(value, limit):
    if type(value) is not str or len(value) > limit:
        raise ValueError('INVALID_OBSERVATION_METADATA')
    return value


def _mapping(value, fields):
    if type(value) is not dict or len(value) > len(fields) or not value.keys() <= fields:
        raise ValueError('INVALID_OBSERVATION_METADATA')
    return value


def bounded_record(value):
    """Copy one fixed metadata contract without retaining arbitrary objects.

    Invalid types/unknown fields are rejected, never stringified. This is also
    the store's boundary for callers that bypass the asynchronous collector.
    """
    try:
        value = _mapping(value, _FIELDS)
        copied = {}
        limits = {'tool': 128, 'tool_name': 128, 'transport': 32, 'connection_id': 128,
                  'workspace': 4096, 'run_label': 64, 'mode': 8}
        for name, limit in limits.items():
            if value.get(name) is not None:
                copied[name] = _text(value[name], limit)
        for name, maximum in (('elapsed_ms', 86_400_000), ('started_at', 32_503_680_000),
                              ('finished_at', 32_503_680_000)):
            if value.get(name) is not None:
                copied[name] = _number(value[name], maximum, floating=True)
        if 'succeeded' in value:
            if type(value['succeeded']) is not bool:
                raise ValueError('INVALID_OBSERVATION_METADATA')
            copied['succeeded'] = value['succeeded']
        if value.get('chat_owner') is not None:
            owner = _mapping(value['chat_owner'], {'host', 'session'})
            if owner.get('host') not in {'codex', 'cursor'} or not _HEX.fullmatch(_text(owner.get('session'), 64)):
                raise ValueError('INVALID_OBSERVATION_METADATA')
            copied['chat_owner'] = dict(owner)
        measures = _mapping(value.get('measurements', {}),
            {'text_bytes', 'structured_bytes', 'wire_bytes', 'measurement_limited'})
        copied['measurements'] = {name: _number(measures[name], 64 * 1024 * 1024)
            for name in ('text_bytes', 'structured_bytes', 'wire_bytes') if name in measures}
        if 'measurement_limited' in measures:
            if type(measures['measurement_limited']) is not bool:
                raise ValueError('INVALID_OBSERVATION_METADATA')
            copied['measurements']['measurement_limited'] = measures['measurement_limited']
        observations = _mapping(value.get('observations', {}), {'source_lines_delivered',
            'duplicate_receipts', 'evidence_hashes', 'flags', 'inspection_limited', 'observation_status'})
        facts = {name: _number(observations[name], 10_000_000)
            for name in ('source_lines_delivered', 'duplicate_receipts') if name in observations}
        if 'evidence_hashes' in observations:
            evidence = observations['evidence_hashes']
            if type(evidence) not in (list, tuple) or len(evidence) > 64:
                raise ValueError('INVALID_OBSERVATION_METADATA')
            facts['evidence_hashes'] = [_text(item, 64) for item in evidence]
            if any(not _HEX.fullmatch(item) for item in facts['evidence_hashes']):
                raise ValueError('INVALID_OBSERVATION_METADATA')
        if 'flags' in observations:
            flags = _mapping(observations['flags'], _FLAGS)
            if any(type(item) is not bool for item in flags.values()):
                raise ValueError('INVALID_OBSERVATION_METADATA')
            facts['flags'] = dict(flags)
        if 'inspection_limited' in observations:
            if type(observations['inspection_limited']) is not bool:
                raise ValueError('INVALID_OBSERVATION_METADATA')
            facts['inspection_limited'] = observations['inspection_limited']
        if 'observation_status' in observations:
            if observations['observation_status'] not in {'UNKNOWN', 'PARTIAL', 'COMPLETE'}:
                raise ValueError('INVALID_OBSERVATION_METADATA')
            facts['observation_status'] = observations['observation_status']
        copied['observations'] = facts
        if 'product_fact' in value:
            from .product_metrics import validate_fact
            copied['product_fact'] = validate_fact(value['product_fact'])
        if 'model_request' in value:
            from .model_observation import validate_model_record
            copied['model_request'] = validate_model_record(value['model_request'])
        if 'correlation' in value:
            correlation = _mapping(value['correlation'], {'call_id', 'host', 'session_binding',
                'trigger_invocation_binding', 'turn_binding', 'links', 'limited', 'chat_conflict'})
            identity = {}
            if correlation.get('call_id') is not None:
                call_id = _text(correlation['call_id'], 64)
                if not _CALL_ID.fullmatch(call_id):
                    raise ValueError('INVALID_OBSERVATION_METADATA')
                identity['call_id'] = call_id
            if correlation.get('host') is not None:
                if correlation['host'] not in {'codex', 'cursor'}:
                    raise ValueError('INVALID_OBSERVATION_METADATA')
                identity['host'] = correlation['host']
            for name in ('session_binding', 'trigger_invocation_binding', 'turn_binding'):
                if correlation.get(name) is not None:
                    binding = _text(correlation[name], 64)
                    if not _HEX.fullmatch(binding):
                        raise ValueError('INVALID_OBSERVATION_METADATA')
                    identity[name] = binding
            links = correlation.get('links', [])
            if type(links) not in (list, tuple) or len(links) > MAX_LINKS:
                raise ValueError('INVALID_OBSERVATION_METADATA')
            identity['links'] = []
            for link in links:
                link = _mapping(link, {'kind', 'reference', 'relation'})
                if link.get('kind') not in {'task', 'scan', 'host_event'} or link.get('relation') not in _RELATIONS:
                    raise ValueError('INVALID_OBSERVATION_METADATA')
                identity['links'].append(dict(kind=link['kind'],
                    reference=_text(link.get('reference'), 256), relation=link['relation']))
            for name in ('limited', 'chat_conflict'):
                if name in correlation:
                    if type(correlation[name]) is not bool:
                        raise ValueError('INVALID_OBSERVATION_METADATA')
                    identity[name] = correlation[name]
            copied['correlation'] = identity
        if 'collection' in value:
            collection = _mapping(value['collection'], {'producer_id', 'process_id',
                'producer_sequence', 'dropped_before', 'write_errors_before', 'settings_source'})
            producer = _text(collection.get('producer_id'), 64)
            if not _CALL_ID.fullmatch(producer):
                raise ValueError('INVALID_OBSERVATION_METADATA')
            copied['collection'] = dict(producer_id=producer, **{name:
                _number(collection.get(name), 2 ** 63 - 1) for name in
                ('process_id', 'producer_sequence', 'dropped_before', 'write_errors_before')})
            if 'settings_source' in collection:
                if collection['settings_source'] not in {'startup', 'default', 'saved', 'environment', 'unavailable'}:
                    raise ValueError('INVALID_OBSERVATION_METADATA')
                copied['collection']['settings_source'] = collection['settings_source']
        return copied
    except (ValueError, TypeError, KeyError):
        return None


def _default_store():
    from .context_cost import ContextCostStore
    return ContextCostStore()


class ObservationWorker:
    def __init__(self, store_factory=None, *, capacity=CAPACITY, refresh_seconds=1.0):
        if type(capacity) is not int or not 1 <= capacity <= CAPACITY:
            raise ValueError('INVALID_OBSERVATION_CAPACITY')
        self._factory = store_factory or _default_store
        self._queue = queue.Queue(maxsize=capacity)
        self._refresh_seconds = max(.01, min(float(refresh_seconds), 60.0))
        initial_mode = os.getenv('SECURITY_RUNTIME_CONTEXT_MODE')
        initial_mode = initial_mode if initial_mode in {'basic','debug'} and os.getenv('SECURITY_RUNTIME_CONTEXT_MONITOR') != '0' else 'off'
        self._settings = dict(status='AVAILABLE', mode=initial_mode, source='startup', run='default')
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._thread = None
        self._producer_id = secrets.token_hex(12)
        self._pid = os.getpid()
        self._counts = dict(offered=0, enqueued=0, dropped=0, invalid=0, persisted=0,
                            write_errors=0, disabled=0, settings_errors=0)

    def start(self):
        """Start only at optional-observer assembly; never opens storage here."""
        with self._lock:
            if self._thread is None and not self._stop.is_set():
                self._thread = threading.Thread(target=self._run,
                    name='runtime-observation', daemon=True)
                self._thread.start()
        return self

    def offer(self, record):
        copied = bounded_record(record)
        with self._lock:
            self._counts['offered'] += 1
            if copied is None:
                self._counts['invalid'] += 1
                self._counts['dropped'] += 1
                return False
            if self._stop.is_set() or self._pid != os.getpid():
                self._counts['dropped'] += 1
                return False
            copied['collection'] = dict(producer_id=self._producer_id, process_id=self._pid,
                producer_sequence=self._counts['offered'], dropped_before=self._counts['dropped'],
                write_errors_before=self._counts['write_errors'],
                settings_source=self._settings.get('source', 'unavailable'))
            try:
                self._queue.put_nowait(copied)
            except queue.Full:
                self._counts['dropped'] += 1
                return False
            self._counts['enqueued'] += 1
            return True

    def snapshot_settings(self):
        # Assignment replaces a complete small dict; callers never receive it.
        return dict(self._settings)

    def stats(self):
        with self._lock:
            return dict(self._counts, producer_id=self._producer_id, process_id=self._pid,
                producer_sequence=self._counts['offered'], queued=self._queue.qsize(),
                pending=self._queue.unfinished_tasks,
                capacity=self._queue.maxsize, stopped=self._stop.is_set())

    def close(self):
        """Never join or flush on the product shutdown path."""
        self._stop.set()

    def wait_ready(self, timeout=1.0):
        """Explicit/test readiness wait, never required before a product call."""
        return self._ready.wait(max(0.0, timeout))

    def wait_idle(self, timeout=1.0):
        """Bounded explicit/test wait; never called by product response handling."""
        deadline = time.monotonic() + max(0.0, timeout)
        with self._queue.all_tasks_done:
            while self._queue.unfinished_tasks:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._queue.all_tasks_done.wait(remaining)
        return True

    def _increment(self, name):
        with self._lock:
            self._counts[name] += 1

    def _run(self):
        store = None
        refresh_at = 0.0
        checkpoint_at = 0.0
        observed = False
        while not self._stop.is_set():
            if time.monotonic() >= refresh_at:
                try:
                    store = store or self._factory()
                    setting = store.monitoring()
                    if (type(setting) is not dict or setting.get('mode') not in {'off', 'basic', 'debug'}
                            or setting.get('status') not in {'AVAILABLE', 'UNAVAILABLE'}):
                        raise ValueError('INVALID_OBSERVATION_SETTING')
                    self._settings = {name: setting[name] for name in ('status', 'mode', 'source', 'run')
                                      if name in setting and type(setting[name]) is str and len(setting[name]) <= 64}
                except Exception:
                    self._settings = dict(status='UNAVAILABLE', mode='off', source='unavailable')
                    self._increment('settings_errors')
                self._ready.set()
                refresh_at = time.monotonic() + self._refresh_seconds
            if observed and time.monotonic() >= checkpoint_at:
                self._checkpoint(store, 'RUNNING')
                checkpoint_at = time.monotonic() + 5.0
            try:
                record = self._queue.get(timeout=min(.1, self._refresh_seconds))
            except queue.Empty:
                continue
            if not observed:
                # Mark pending work before a potentially blocked first write.
                self._checkpoint(store, 'RUNNING')
                checkpoint_at = time.monotonic() + 5.0
            observed = True
            try:
                if self._settings.get('status') != 'AVAILABLE':
                    self._increment('write_errors')
                    continue
                if self._settings.get('mode') == 'off':
                    self._increment('disabled')
                    continue
                if store is None:
                    self._increment('write_errors')
                    continue
                result = store.record_observation(record)
                status = result.get('status') if type(result) is dict else None
                self._increment('persisted' if status == 'RECORDED' else
                                'disabled' if status == 'DISABLED' else 'write_errors')
            except Exception:
                self._increment('write_errors')
            finally:
                self._queue.task_done()
        if observed:
            self._checkpoint(store, 'STOPPED')

    def _checkpoint(self, store, state):
        try:
            # Optional real stores only; no extra contract for embedded stores.
            from .context_cost import ContextCostStore
            from .collector_health import write_checkpoint
            if isinstance(store, ContextCostStore):
                write_checkpoint(store, self.stats(), state)
        except Exception:
            pass


_worker = None
_worker_lock = threading.Lock()


def get_worker():
    global _worker
    mode = os.getenv('SECURITY_RUNTIME_CONTEXT_MODE')
    if os.getenv('SECURITY_RUNTIME_CONTEXT_MONITOR') == '0' or (mode is not None and mode not in {'basic', 'debug'}):
        return None
    with _worker_lock:
        if _worker is None or _worker._pid != os.getpid() or _worker._stop.is_set():
            _worker = ObservationWorker().start()
        return _worker
