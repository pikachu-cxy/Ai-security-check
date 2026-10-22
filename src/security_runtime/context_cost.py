"""Local metadata for Runtime response cost and separately imported host usage.

Tool response bytes are not model tokens. This observer stores no source,
prompts, arguments, result bodies, workspace paths or host session identifiers.
All write/observation failures are contained so they cannot change tool behavior.
"""
from __future__ import annotations

from contextlib import closing
from functools import lru_cache
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import sys
import time

from ._version import __version__
from .closeout_state import readonly_uri
from .token_usage import normalized_usage
from .hook_state import no_links
from .storage import SQLiteStore

MAX_EVENTS = 10_000
RETENTION_SECONDS = 14 * 86400
MAX_HOST_IMPORTS = 1_000
MAX_MEASURE_BYTES = 64 * 1024 * 1024
MAX_OBSERVATION_TEXT_BYTES = 256 * 1024
MAX_OBSERVATION_RECORD_BYTES = 16_384
MONITOR_MODES = ('off', 'basic', 'debug')
RUN_PATTERN = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z')
TOOL_NAMES = frozenset('''start_usage_monitor scan_diff scan_project scan_files get_findings prepare_triage submit_triage
get_runtime_info get_runtime_guidance get_professional_guidance get_scan_preparation_status
get_security_summary prepare_task_triage get_triage begin_security_task finish_security_task
prepare_task_security_review get_task_review_plan get_task_review_method submit_task_review_batch
read_task_review_context submit_task_security_review get_task_security_review get_task_risk_ledger
prepare_task_risk_feedback submit_task_risk_feedback mark_task_risk_false_positive
set_task_risk_disposition revoke_task_risk_feedback get_task_risk_feedback prepare_finding_feedback
submit_finding_feedback mark_finding_false_positive set_finding_disposition revoke_finding_feedback
get_finding_feedback prepare_repair_impact read_repair_impact_context submit_repair_impact
get_repair_impact prepare_task_risk_fix cancel_task_risk_fix prepare_task_fix confirm_remediation
refresh_remediation_confirmation verify_task_fix generate_fix verify handle_hook_event
handle_readiness_event handle_stop_event prepare_closeout_check run_closeout_check
get_closeout_status runtime_scan run_triage normalized_host_event byok_request product_outcome'''.split())
TRANSPORTS = frozenset({'workspace', 'mcp', 'cli', 'hook', 'unknown'})
_FLAGS = ('scanner_run', 'cache_reused', 'cache_reuse', 'reused', 'full_project_reusable')
_USAGE_WARNINGS = frozenset({'INVALID_JSON_LINE_IGNORED', 'INVALID_USAGE_IGNORED',
                           'MIXED_FORMAT_CUMULATIVE_PREFERRED', 'THREAD_IDENTITY_UNAVAILABLE',
                           'SOURCE_OVERLAP_UNVERIFIABLE'})
_INCOMPLETE_USAGE = _USAGE_WARNINGS - {'MIXED_FORMAT_CUMULATIVE_PREFERRED'}


def run_label(value=None):
    label = value if value is not None else os.getenv('SECURITY_RUNTIME_CONTEXT_RUN', 'default')
    if not isinstance(label, str) or RUN_PATTERN.fullmatch(label) is None:
        raise ValueError('CONTEXT_COST_RUN_LABEL_INVALID')
    return label


@lru_cache(maxsize=1)
def _build_metadata():
    # Development mode deliberately avoids a tree hash/git subprocess per call.
    # The label permits comparisons; an unverified build id is never invented.
    build = dict(version=__version__, build_id=None, build_status='DEVELOPMENT')
    if not getattr(sys, 'frozen', False):
        from .managed_identity import managed_build_identity
        managed = managed_build_identity(Path(__file__).parent, version=__version__)
        if managed is not None:
            return dict(version=__version__, build_id=managed.get('build_id'),
                        build_status=managed['status'], source_commit=managed.get('source_commit'))
    if getattr(sys, 'frozen', False):
        try:
            path = Path(sys.executable).absolute().parent / 'version.json'
            no_links(path)
            if path.stat().st_size > 2_000_000:
                return build
            value = json.loads(path.read_bytes())
            identifier = value.get('build_id')
            if isinstance(identifier, str) and re.fullmatch('[a-f0-9]{64}', identifier):
                build.update(build_id=identifier, build_status='BUNDLE_METADATA')
        except (OSError, ValueError, TypeError, AttributeError):
            pass
    return build


def _encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), sort_keys=True).encode('utf-8')


def _size(value):
    total = 0
    for part in json.JSONEncoder(ensure_ascii=False, separators=(',', ':')).iterencode(value):
        total += len(part.encode('utf-8'))
        if total > MAX_MEASURE_BYTES:
            return MAX_MEASURE_BYTES, True
    return total, False


def _as_mapping(result):
    if isinstance(result, dict):
        return result
    dump = getattr(result, 'model_dump', None)
    if callable(dump):
        value = dump(mode='json', by_alias=True, exclude_none=True)
        if isinstance(value, dict):
            return value
    return {'content': result} if isinstance(result, list) else {'value': result}


def _measure(result):
    mapped = _as_mapping(result)
    wire, limited = _size(mapped)
    text = 0
    content = mapped.get('content')
    if isinstance(content, list):
        for item in content[:1000]:
            if isinstance(item, dict) and item.get('type') == 'text' and isinstance(item.get('text'), str):
                text += len(item['text'].encode('utf-8'))
        if text > MAX_MEASURE_BYTES or len(content) > 1000:
            limited = True
        text = min(text, MAX_MEASURE_BYTES)
    structured = mapped.get('structuredContent')
    if structured is None and 'content' not in mapped:
        structured = mapped
    structured_bytes, structured_limited = _size(structured) if structured is not None else (0, False)
    return mapped, dict(text_bytes=text, structured_bytes=structured_bytes, wire_bytes=wire,
                        measurement_limited=limited or structured_limited)


def _observation_input(mapped, tool_name):
    """Prefer one structured payload; decode only a bounded Runtime JSON reply.

    Bare ``dict`` SDK tools can return just one JSON TextContent block. Parsing
    that block is transient: neither it nor the decoded body enters storage.
    Ambiguous/malformed content stays unknown, rather than looking like zero.
    """
    if 'content' not in mapped:
        return mapped
    structured = mapped.get('structuredContent')
    if structured is not None:
        return structured if isinstance(structured, (dict, list)) else None
    content = mapped.get('content')
    if tool_name not in TOOL_NAMES or not isinstance(content, list) or len(content) != 1:
        return None
    item = content[0]
    if not isinstance(item, dict) or item.get('type') != 'text':
        return None
    value = item.get('text')
    if (not isinstance(value, str) or len(value) > MAX_OBSERVATION_TEXT_BYTES
            or len(value.encode('utf-8')) > MAX_OBSERVATION_TEXT_BYTES):
        return None
    try:
        decoded = json.loads(value)
    except (ValueError, TypeError, RecursionError):
        return None
    return decoded if isinstance(decoded, (dict, list)) else None


def _observations(mapped, digest, *, tool_name=None):
    """Extract only bounded typed counters and keyed evidence identities."""
    payload = _observation_input(mapped, tool_name)
    pending, visited = [payload] if payload is not None else [], 0
    limited = payload is None
    evidence, flags = set(), {}
    lines, duplicates = 0, 0
    while pending and visited < 20_000:
        node = pending.pop()
        visited += 1
        if isinstance(node, dict):
            limited |= len(node) > 2000
            if node.get('status') == 'ALREADY_DELIVERED':
                duplicates += 1
            for name in _FLAGS:
                if type(node.get(name)) is bool:
                    flags[name] = flags.get(name, False) or node[name]
            source_lines = node.get('lines')
            if isinstance(source_lines, list) and type(node.get('start_line')) is int:
                lines += len(source_lines)
            elif (isinstance(node.get('text'), str) and node.get('trust') == 'UNTRUSTED_CODE'
                  and type(node.get('start_line')) is int and type(node.get('end_line')) is int):
                lines += max(0, min(1_000_000, node['end_line'] - node['start_line'] + 1))
            ref = node.get('evidence_id')
            if isinstance(ref, str) and len(ref) <= 256 and len(evidence) < 64:
                evidence.add(digest('evidence', ref))
            elif (isinstance(node.get('text'), str) and node.get('trust') == 'UNTRUSTED_CODE'
                  and isinstance(node.get('file'), str) and len(evidence) < 64):
                evidence.add(digest('source_window', _encoded([node['file'], node.get('start_line'),
                                                               node.get('end_line'), node['text']]).decode()))
            pending.extend(value for key, value in list(node.items())[:2000]
                           if key not in {'lines', 'text', 'arguments'} and isinstance(value, (dict, list)))
        elif isinstance(node, list):
            limited |= len(node) > 2000
            pending.extend(node[:2000])
    limited |= bool(pending)
    return dict(source_lines_delivered=min(lines, 10_000_000), duplicate_receipts=duplicates,
                evidence_hashes=sorted(evidence), flags=flags, inspection_limited=limited,
                observation_status='UNKNOWN' if payload is None else 'PARTIAL' if limited else 'COMPLETE')


class ContextCostStore:
    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path is not None else SQLiteStore.default_path().parent / 'context-cost.sqlite3'
        self.key_path = self.path.with_suffix('.key')

    def _key(self, *, create=False):
        no_links(self.path)
        no_links(self.key_path)
        for path in (self.path, self.key_path):
            if path.exists():
                info = path.stat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink > 1:
                    raise ValueError('CONTEXT_COST_STORAGE_UNAVAILABLE')
                if path == self.key_path and info.st_size != 32:
                    raise ValueError('CONTEXT_COST_STORAGE_UNAVAILABLE')
        if create:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            no_links(self.path.parent)
            if self.path.exists() and not self.key_path.is_file():
                raise ValueError('CONTEXT_COST_STORAGE_UNAVAILABLE')
            try:
                fd = os.open(self.key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                pass
            else:
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(secrets.token_bytes(32))
        key = self.key_path.read_bytes()
        if len(key) != 32:
            raise ValueError('CONTEXT_COST_STORAGE_UNAVAILABLE')
        return key

    def _connect(self, *, write=False):
        key = self._key(create=write)
        if write:
            try:
                descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                pass
            else:
                os.close(descriptor)
        db = sqlite3.connect(self.path, timeout=0.2) if write else sqlite3.connect(
            readonly_uri(self.path), uri=True, timeout=0.2)
        try:
            db.execute('PRAGMA trusted_schema=OFF')
            if write:
                db.execute('CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, at REAL, run TEXT, record BLOB, mac TEXT)')
                db.execute('CREATE INDEX IF NOT EXISTS cost_events_run ON events(run,at)')
                db.execute('CREATE INDEX IF NOT EXISTS cost_events_at ON events(at)')
                db.execute('CREATE TABLE IF NOT EXISTS host_usage (source TEXT PRIMARY KEY, at REAL, run TEXT, record BLOB, mac TEXT)')
                db.execute('CREATE INDEX IF NOT EXISTS cost_host_usage_at ON host_usage(at)')
                db.execute('CREATE TABLE IF NOT EXISTS monitor_settings (id INTEGER PRIMARY KEY CHECK(id=1), record BLOB, mac TEXT)')
                db.commit()
                db.execute('BEGIN IMMEDIATE')
            else:
                db.execute('PRAGMA query_only=ON')
            return db, key
        except BaseException:
            db.close()
            raise

    @staticmethod
    def _digest(key, kind, value):
        return hmac.new(key, (kind + '\0' + str(value)).encode('utf-8'), hashlib.sha256).hexdigest()

    @staticmethod
    def _signed(key, record):
        encoded = _encoded(record)
        return encoded, hmac.new(key, encoded, hashlib.sha256).hexdigest()

    @staticmethod
    def _prune(db):
        cutoff = time.time() - RETENTION_SECONDS
        db.execute('DELETE FROM events WHERE at < ?', (cutoff,))
        # Delete only overflow keys. NOT IN visits every retained row per call.
        db.execute('DELETE FROM events WHERE id <= (SELECT id FROM events ORDER BY id DESC LIMIT 1 OFFSET ?)', (MAX_EVENTS,))
        db.execute('DELETE FROM host_usage WHERE at < ?', (cutoff,))
        db.execute('DELETE FROM host_usage WHERE source IN (SELECT source FROM host_usage ORDER BY at DESC LIMIT -1 OFFSET ?)', (MAX_HOST_IMPORTS,))

    def monitoring(self):
        """Read the live setting without initializing storage; environment wins."""
        if os.getenv('SECURITY_RUNTIME_CONTEXT_MONITOR') == '0':
            return dict(status='AVAILABLE', mode='off', source='environment')
        override = os.getenv('SECURITY_RUNTIME_CONTEXT_MODE')
        if override is not None:
            return dict(status='AVAILABLE' if override in MONITOR_MODES else 'UNAVAILABLE',
                        mode=override if override in MONITOR_MODES else 'off', source='environment')
        try:
            if not self.path.exists():
                return dict(status='AVAILABLE', mode='off', source='default', run=run_label())
            db, key = self._connect()
            with closing(db):
                exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='monitor_settings'").fetchone()
                row = db.execute('SELECT substr(record,1,16385),substr(mac,1,129) FROM monitor_settings WHERE id=1').fetchone() if exists else None
            if row is None:
                return dict(status='AVAILABLE', mode='off', source='default', run=run_label())
            records, invalid = self._verified([row], key)
            if invalid or records[0].get('mode') not in MONITOR_MODES:
                raise ValueError('INVALID_MONITOR_SETTING')
            label = run_label(os.getenv('SECURITY_RUNTIME_CONTEXT_RUN', records[0].get('run', 'default')))
            return dict(status='AVAILABLE', mode=records[0]['mode'], source='saved', run=label)
        except Exception:
            return dict(status='UNAVAILABLE', mode='off', source='unavailable')

    def set_monitoring(self, mode, run=None):
        if mode not in MONITOR_MODES:
            return dict(status='INVALID_MODE')
        try:
            label = run_label(run) if run is not None else self.monitoring().get('run', 'default')
            db, key = self._connect(write=True)
            with closing(db), db:
                encoded, mac = self._signed(key, dict(mode=mode, run=label))
                db.execute('INSERT OR REPLACE INTO monitor_settings VALUES(1,?,?)', (encoded, mac))
            return dict(status='AVAILABLE', saved_mode=mode, effective=self.monitoring(),
                        takes_effect='NEXT_CALL_WITH_SAME_DATABASE', historical_data_retained=True)
        except Exception:
            return dict(status='UNAVAILABLE', reason_code='CONTEXT_COST_OBSERVATION_UNAVAILABLE')

    def record_call(self, tool_name, result, *, elapsed_ms=0, transport='workspace',
                    connection_id='', workspace=None, run_label=None, succeeded=True,
                    started_at=None, finished_at=None, mode=None, chat_owner=None):
        try:
            setting = self.monitoring()
            if setting['status'] != 'AVAILABLE':
                return {'status': 'UNAVAILABLE', 'reason_code': 'CONTEXT_COST_OBSERVATION_UNAVAILABLE'}
            if setting['mode'] == 'off':
                return {'status': 'DISABLED'}
            # A call started in basic mode cannot acquire details after a switch.
            debug = setting['mode'] == 'debug' and mode in (None, 'debug')
            if not debug and chat_owner is not None:
                try:
                    from .monitoring.active import enabled
                    debug = enabled(self, chat_owner)
                except Exception:
                    pass
            observation_started = time.monotonic()
            label = globals()['run_label'](run_label if run_label is not None else setting.get('run'))
            mapped, sizes = _measure(result)
            db, key = self._connect(write=True)
            with closing(db), db:
                digest = lambda kind, value: self._digest(key, kind, value)
                elapsed = int(elapsed_ms) if isinstance(elapsed_ms, (int, float)) and math.isfinite(elapsed_ms) else 0
                record = dict(schema_version=2, tool=tool_name if tool_name in TOOL_NAMES else 'unknown',
                              transport=transport if transport in TRANSPORTS else 'unknown',
                              succeeded=succeeded is True, elapsed_ms=max(0, min(elapsed, 86_400_000)),
                              connection_hash=digest('connection', connection_id) if connection_id else None,
                              workspace_hash=digest('workspace', os.path.normcase(os.path.abspath(str(workspace)))) if workspace else None,
                              build=_build_metadata(), **sizes, **_observations(mapped, digest, tool_name=tool_name))
                record.update(run_label=label, mode='debug' if debug else 'basic')
                if chat_owner is not None:
                    from .task_ownership import valid_owner
                    if valid_owner(chat_owner) and chat_owner['host'] in {'codex', 'cursor'}:
                        record['chat_hash'] = digest('chat', chat_owner['host'] + ':' + chat_owner['session'])
                if debug:
                    valid_time = (type(started_at) in (int, float) and type(finished_at) in (int, float)
                                  and math.isfinite(started_at) and math.isfinite(finished_at)
                                  and 0 <= started_at <= finished_at <= 32_503_680_000)
                    record.update(call_id=secrets.token_hex(12),
                                  started_at=started_at if valid_time else None,
                                  finished_at=finished_at if valid_time else None,
                                  observation_prewrite_ms=round((time.monotonic() - observation_started) * 1000, 3))
                encoded, mac = self._signed(key, record)
                db.execute('INSERT INTO events(at,run,record,mac) VALUES(?,?,?,?)', (time.time(), label, encoded, mac))
                self._prune(db)
            return {'status': 'RECORDED'}
        except Exception:
            return {'status': 'UNAVAILABLE', 'reason_code': 'CONTEXT_COST_OBSERVATION_UNAVAILABLE'}

    def record_observation(self, observation):
        """Persist premeasured metadata from the optional collector only.

        Unlike ``record_call``, this path never receives a response object. All
        settings, lease and database work happens on the collector's thread.
        Existing v1/v2 rows and explicit synchronous import APIs stay readable.
        """
        try:
            from .context_cost_worker import bounded_record
            data = bounded_record(observation)
            if data is None:
                return {'status': 'UNAVAILABLE', 'reason_code': 'CONTEXT_COST_METADATA_INVALID'}
            setting = self.monitoring()
            if setting.get('status') != 'AVAILABLE':
                return {'status': 'UNAVAILABLE', 'reason_code': 'CONTEXT_COST_OBSERVATION_UNAVAILABLE'}
            if setting.get('mode') == 'off':
                return {'status': 'DISABLED'}
            label = run_label(data.get('run_label', setting.get('run')))
            owner = data.get('chat_owner')
            correlation = data.get('correlation', {})
            if correlation.get('chat_conflict'):
                owner = None
            debug = setting['mode'] == 'debug' and data.get('mode') in (None, 'debug')
            if not debug and owner is not None:
                try:
                    from .monitoring.active import enabled
                    debug = enabled(self, owner)
                except Exception:
                    pass
            measurements, observations = data['measurements'], data['observations']
            started, finished = data.get('started_at'), data.get('finished_at')
            valid_time = (started is not None and finished is not None and started <= finished)
            tool = data.get('tool', data.get('tool_name'))
            db, key = self._connect(write=True)
            with closing(db), db:
                digest = lambda kind, value: self._digest(key, kind, value)
                record = dict(schema_version=3, tool=tool if tool in TOOL_NAMES else 'unknown',
                    transport=data.get('transport') if data.get('transport') in TRANSPORTS else 'unknown',
                    succeeded=data.get('succeeded') is True, elapsed_ms=int(data.get('elapsed_ms', 0)),
                    connection_hash=digest('connection', data['connection_id']) if data.get('connection_id') else None,
                    workspace_hash=digest('workspace', os.path.normcase(os.path.abspath(data['workspace']))) if data.get('workspace') else None,
                    build=_build_metadata(), run_label=label, mode='debug' if debug else 'basic',
                    text_bytes=measurements.get('text_bytes', 0),
                    structured_bytes=measurements.get('structured_bytes', 0),
                    wire_bytes=measurements.get('wire_bytes', 0),
                    measurement_limited=measurements.get('measurement_limited', True),
                    source_lines_delivered=observations.get('source_lines_delivered', 0),
                    duplicate_receipts=observations.get('duplicate_receipts', 0),
                    evidence_hashes=[digest('evidence_observation', item) for item in observations.get('evidence_hashes', [])],
                    evidence_identity_scope='PRODUCER_PROCESS',
                    flags=observations.get('flags', {}),
                    inspection_limited=observations.get('inspection_limited', True),
                    observation_status=observations.get('observation_status', 'UNKNOWN'),
                    started_at=started if valid_time else None,
                    finished_at=finished if valid_time else None)
                if owner is not None:
                    record['chat_hash'] = digest('chat', owner['host'] + ':' + owner['session'])
                association = dict(limited=correlation.get('limited', False),
                    chat_conflict=correlation.get('chat_conflict', False), links=[])
                if correlation.get('call_id'):
                    record['call_id'] = association['call_id'] = correlation['call_id']
                if correlation.get('host'):
                    association['host'] = correlation['host']
                # Conflicting verified identities cannot become an attributed
                # session/turn through a second observational field.
                if not association['chat_conflict']:
                    host = correlation.get('host')
                    if host and correlation.get('session_binding'):
                        association['session_hash'] = digest('chat', host + ':' + correlation['session_binding'])
                    for source, target in (('trigger_invocation_binding', 'trigger_invocation_hash'),
                                           ('turn_binding', 'turn_hash')):
                        if correlation.get(source):
                            association[target] = digest('correlation:' + source, correlation[source])
                for link in correlation.get('links', []):
                    association['links'].append(dict(kind=link['kind'], relation=link['relation'],
                        reference_hash=digest('correlation:' + link['kind'], link['reference'])))
                record['correlation'] = association
                if 'product_fact' in data:
                    fact = data['product_fact']
                    record.update(schema_version=4, event_kind='product_fact')
                    record['product_fact'] = dict(fact,
                        reference=digest('product_scope', fact['reference']),
                        items=[dict(item, id=digest('finding', item['id']), **(
                            {'risk_key':digest('risk_identity',item['risk_key'])} if item.get('risk_key') else {}))
                            for item in fact['items']])
                if 'model_request' in data:
                    model = data['model_request']
                    record.update(schema_version=4, event_kind='model_request')
                    # The queue contains only keyed ephemeral fingerprints;
                    # key them again for the independent persistent store.
                    manifest = model['manifest']
                    record['model_request'] = dict(model, manifest=dict(manifest,
                        request_fingerprint=digest('model_input', manifest['request_fingerprint']),
                        components=[dict(item, fingerprint=digest('model_component', item['fingerprint']))
                                    for item in manifest['components']]),
                        response_fingerprint=digest('model_response', model['response_fingerprint'])
                            if model.get('response_fingerprint') else None)
                if 'collection' in data:
                    record['collection'] = data['collection']
                    record['settings_source'] = data['collection'].get('settings_source', 'unavailable')
                encoded, mac = self._signed(key, record)
                # Keep the call itself when optional evidence/link metadata
                # exceeds the row budget. Every omission remains observable.
                while len(encoded) > MAX_OBSERVATION_RECORD_BYTES and (
                        record['evidence_hashes'] or association['links']):
                    record['metadata_limited'] = True
                    if record['evidence_hashes']:
                        record['evidence_hashes'].pop()
                        record['evidence_hashes_omitted'] = record.get('evidence_hashes_omitted', 0) + 1
                        record.update(inspection_limited=True, observation_status='PARTIAL')
                    else:
                        association['links'].pop()
                        association['limited'] = True
                        association['links_omitted'] = association.get('links_omitted', 0) + 1
                    encoded, mac = self._signed(key, record)
                product = record.get('product_fact')
                while product and len(encoded) > MAX_OBSERVATION_RECORD_BYTES:
                    check = product.get('check') or {}
                    if product['items']:
                        product['items'].pop()
                        product['omitted'] += 1
                    elif check.get('languages'):
                        check['languages'].pop()
                    elif check.get('capabilities'):
                        check['capabilities'].pop()
                    else:
                        break
                    record['metadata_limited'] = True
                    if check:
                        check['limited'] = True
                        check['reason_codes'] = sorted(set(check['reason_codes']) | {'OBSERVATION_LIMIT'})
                    encoded, mac = self._signed(key, record)
                if len(encoded) > MAX_OBSERVATION_RECORD_BYTES:
                    return {'status': 'UNAVAILABLE', 'reason_code': 'CONTEXT_COST_METADATA_LIMIT'}
                db.execute('INSERT INTO events(at,run,record,mac) VALUES(?,?,?,?)',
                           (time.time(), label, encoded, mac))
                self._prune(db)
            return {'status': 'RECORDED'}
        except Exception:
            return {'status': 'UNAVAILABLE', 'reason_code': 'CONTEXT_COST_OBSERVATION_UNAVAILABLE'}

    def record_host_usage(self, run_label, report):
        try:
            label = globals()['run_label'](run_label)
            usage = normalized_usage(report.get('usage')) if isinstance(report, dict) else None
            if usage is None:
                return {'status': 'UNKNOWN'}
            source = report.get('import_key')
            streams = report.get('streams')
            if (not isinstance(source, str) or re.fullmatch('[a-f0-9]{64}', source) is None
                    or not isinstance(streams, list) or not 1 <= len(streams) <= 512):
                return {'status': 'UNKNOWN'}
            db, key = self._connect(write=True)
            with closing(db), db:
                changed, pending = 0, []
                warnings = sorted(set(report.get('warnings', [])) & _USAGE_WARNINGS)
                for stream in streams:
                    identity = stream.get('identity') if isinstance(stream, dict) else None
                    count = normalized_usage(stream.get('usage')) if isinstance(stream, dict) else None
                    origin = stream.get('source_identity') if isinstance(stream, dict) else None
                    basis = stream.get('basis') if isinstance(stream, dict) else None
                    if (not isinstance(identity, str) or re.fullmatch(r'(thread|source):[a-f0-9]{64}', identity) is None
                            or count is None or not isinstance(origin, str) or re.fullmatch('[a-f0-9]{64}', origin) is None
                            or basis not in {'cumulative', 'turn_sum'}):
                        return {'status': 'UNKNOWN'}
                    source_key = self._digest(key, 'host_stream', identity)
                    origin = self._digest(key, 'host_origin', origin)
                    old = db.execute('SELECT run,substr(record,1,16385),substr(mac,1,129) FROM host_usage WHERE source=?', (source_key,)).fetchone()
                    if old:
                        if old[0] != label:
                            return {'status': 'RUN_LABEL_CONFLICT'}
                        previous, invalid = self._verified([(old[1], old[2])], key)
                        if invalid or not previous:
                            return {'status': 'UNAVAILABLE', 'reason_code': 'CONTEXT_COST_OBSERVATION_UNAVAILABLE'}
                        if ((basis != 'cumulative' or previous[0]['basis'] != 'cumulative')
                                and previous[0]['source_origin'] != origin):
                            self._warn_host(db, key, source_key, previous[0], 'SOURCE_OVERLAP_UNVERIFIABLE')
                            return {'status': 'SOURCE_OVERLAP_UNVERIFIABLE'}
                        prior = previous[0]['usage']
                        if (count == prior and previous[0]['warnings'] == warnings) or (all(count[name] <= prior[name] for name in ('input_tokens', 'output_tokens'))
                                              and any(count[name] < prior[name] for name in ('input_tokens', 'output_tokens'))):
                            continue
                        if any(count[name] < prior[name] for name in ('input_tokens', 'output_tokens')):
                            self._warn_host(db, key, source_key, previous[0], 'SOURCE_OVERLAP_UNVERIFIABLE')
                            return {'status': 'SOURCE_OVERLAP_UNVERIFIABLE'}
                    record = dict(usage=count, identity_verified=identity.startswith('thread:'),
                                  source_origin=origin, basis=basis, warnings=warnings,
                                  format=report.get('format') if report.get('format') in
                                  {'codex_exec', 'codex_rollout', 'mixed'} else 'unknown')
                    encoded, mac = self._signed(key, record)
                    pending.append((source_key, time.time(), label, encoded, mac))
                    changed += 1
                db.executemany('INSERT OR REPLACE INTO host_usage VALUES(?,?,?,?,?)', pending)
                self._prune(db)
            return {'status': 'RECORDED' if changed else 'ALREADY_IMPORTED'}
        except Exception:
            return {'status': 'UNAVAILABLE', 'reason_code': 'CONTEXT_COST_OBSERVATION_UNAVAILABLE'}

    def _warn_host(self, db, key, source, previous, warning):
        record = dict(previous, warnings=sorted(set(previous['warnings']) | {warning}))
        encoded, mac = self._signed(key, record)
        db.execute('UPDATE host_usage SET record=?,mac=? WHERE source=?', (encoded, mac, source))

    @staticmethod
    def _verified(rows, key):
        result, invalid = [], 0
        for encoded, mac in rows:
            try:
                if not isinstance(encoded, bytes) or len(encoded) > 16_384 or not isinstance(mac, str):
                    raise ValueError()
                expected = hmac.new(key, encoded, hashlib.sha256).hexdigest()
                if not hmac.compare_digest(expected, mac):
                    raise ValueError()
                value = json.loads(encoded)
                if not isinstance(value, dict):
                    raise ValueError()
                result.append(value)
            except (ValueError, TypeError, UnicodeError):
                invalid += 1
        return result, invalid

    def snapshot(self, run_label=None):
        """Bounded, verified local records shared by summary and report readers."""
        try:
            label = globals()['run_label'](run_label) if run_label is not None else None
            if not self.path.exists():
                return dict(status='AVAILABLE', events=[], reports=[], label=label, invalid=0)
            db, key = self._connect()
            with closing(db):
                db.execute('BEGIN')
                where = ' WHERE at>=?' + (' AND run=?' if label is not None else '')
                params = (time.time() - RETENTION_SECONDS,) + ((label,) if label is not None else ())
                events, bad1 = self._verified(db.execute('SELECT substr(record,1,16385),substr(mac,1,129) FROM events' + where + ' ORDER BY id DESC LIMIT ?', (*params, MAX_EVENTS)).fetchall(), key)
                usage, bad2 = self._verified(db.execute('SELECT substr(record,1,16385),substr(mac,1,129) FROM host_usage' + where + ' ORDER BY at DESC LIMIT ?', (*params, MAX_HOST_IMPORTS)).fetchall(), key)
                from .collector_health import read_checkpoints
                checkpoints, bad3 = read_checkpoints(self, db, key)
            # v2 binds the label inside the MAC too. Legacy labels remain marked.
            valid = [item for item in events if item.get('schema_version') == 1 or
                     (RUN_PATTERN.fullmatch(str(item.get('run_label', ''))) and
                      (label is None or item['run_label'] == label))]
            models = [item for item in valid if item.get('event_kind') == 'model_request']
            return dict(status='AVAILABLE', events=[item for item in valid if item.get('event_kind') not in {'model_request','product_fact'}],
                        product_facts=[item for item in valid if item.get('event_kind') == 'product_fact'],
                        model_requests=models, collector_checkpoints=checkpoints, reports=usage, label=label,
                        invalid=bad1 + bad2 + bad3 + len(events) - len(valid))
        except Exception:
            return dict(status='UNAVAILABLE')

    def summary(self, run_label=None):
        snapshot = self.snapshot(run_label)
        if snapshot['status'] == 'UNAVAILABLE':
            return dict(status='UNAVAILABLE', reason_code='CONTEXT_COST_OBSERVATION_UNAVAILABLE',
                        actual_model_tokens=None, actual_model_tokens_status='UNKNOWN')
        try:
            result = self._summary(snapshot['events'], snapshot['reports'], snapshot['label'], snapshot['invalid'])
            result['monitoring'] = self.monitoring()
            return result
        except Exception:
            return dict(status='UNAVAILABLE', actual_model_tokens=None, actual_model_tokens_status='UNKNOWN')

    @staticmethod
    def _summary(events, reports, label, invalid):
        totals = {name: sum(item[name] for item in events) for name in
                  ('text_bytes', 'structured_bytes', 'wire_bytes', 'elapsed_ms', 'source_lines_delivered', 'duplicate_receipts')}
        tools, evidence, builds = {}, {}, {}
        for item in events:
            entry = tools.setdefault(item['tool'], dict(tool=item['tool'], calls=0, wire_bytes=0, elapsed_ms=0))
            entry['calls'] += 1
            entry['wire_bytes'] += item['wire_bytes']
            entry['elapsed_ms'] += item['elapsed_ms']
            for identifier in item['evidence_hashes']:
                evidence[identifier] = evidence.get(identifier, 0) + 1
            build = item['build']
            builds[(build['version'], build['build_id'], build['build_status'])] = build
        actual = None
        # A file without a host thread id might overlap another selected file.
        # Keep the measurements but refuse to silently sum unverifiable sources.
        usage_ambiguous = len(reports) > 1 and any(not item['identity_verified'] for item in reports)
        host_warnings = sorted({warning for report in reports for warning in report['warnings']})
        host_complete = bool(reports) and not usage_ambiguous and not bool(set(host_warnings) & _INCOMPLETE_USAGE)
        if reports and not usage_ambiguous:
            actual = {name: sum(item['usage'][name] for item in reports) for name in
                      ('input_tokens', 'cached_input_tokens', 'output_tokens', 'reasoning_output_tokens', 'total_tokens')}
        observed = sum(item.get('observation_status') == 'COMPLETE' for item in events)
        partially_observed = any(item.get('observation_status') == 'PARTIAL' for item in events)
        return dict(schema_version=1, status='PARTIAL' if invalid else 'AVAILABLE', run_label=label,
                    calls=len(events), failed_calls=sum(not item['succeeded'] for item in events), **totals,
                    observation_status='COMPLETE' if observed == len(events) else 'PARTIAL' if observed or partially_observed else 'UNKNOWN',
                    observation_incomplete_calls=len(events) - observed,
                    repeated_evidence_deliveries=sum(count - 1 for count in evidence.values()),
                    scanner_runs=sum(item['flags'].get('scanner_run', False) for item in events),
                    cache_reuse_calls=sum(any(item['flags'].get(name, False) for name in _FLAGS[1:]) for item in events),
                    limited_measurements=sum(item['measurement_limited'] or item['inspection_limited'] for item in events),
                    top_tools=sorted(tools.values(), key=lambda item: item['wire_bytes'], reverse=True)[:20],
                    builds=list(builds.values())[:20], invalid_records=invalid,
                    host_usage_imports=len(reports), actual_model_tokens=actual,
                    actual_model_tokens_status=('HOST_REPORTED' if host_complete else 'HOST_REPORTED_PARTIAL') if actual is not None else 'UNKNOWN',
                    host_usage_complete=host_complete, host_usage_warnings=host_warnings,
                    host_usage_warning='UNVERIFIED_SOURCES_NOT_AGGREGATED' if usage_ambiguous else None,
                    measurement='UTF8_RESPONSE_BYTES_NOT_MODEL_TOKENS',
                    measurement_scope='SERIALIZED_TOOL_RESULT_EXCLUDES_JSONRPC_ENVELOPE',
                    retention_days=14, event_limit=MAX_EVENTS)

    def compare(self, baseline, candidate):
        before, after = self.summary(baseline), self.summary(candidate)
        if before.get('status') == 'UNAVAILABLE' or after.get('status') == 'UNAVAILABLE':
            return dict(status='UNAVAILABLE', actual_token_reduction_percent=None)
        old_bytes, new_bytes = before['wire_bytes'], after['wire_bytes']
        old_tokens, new_tokens = before['actual_model_tokens'], after['actual_model_tokens']
        enough = (old_tokens is not None and new_tokens is not None and old_tokens['total_tokens'] > 0
                  and before['host_usage_complete'] and after['host_usage_complete']
                  and before['status'] == 'AVAILABLE' and after['status'] == 'AVAILABLE')
        return dict(schema_version=1, status='PARTIAL' if before['status'] == 'PARTIAL' or after['status'] == 'PARTIAL' else 'AVAILABLE', baseline=before, candidate=after,
                    response_byte_reduction_percent=round((old_bytes-new_bytes)*100/old_bytes, 2) if old_bytes else None,
                    actual_token_reduction_percent=round((old_tokens['total_tokens']-new_tokens['total_tokens'])*100/old_tokens['total_tokens'], 2) if enough else None,
                    actual_tokens_comparable=enough,
                    comparison_note='HOST_USAGE_COVERS_WHOLE_RUN_NOT_RUNTIME_ATTRIBUTION' if enough else 'HOST_USAGE_REQUIRED_FOR_ACTUAL_TOKEN_COMPARISON')
