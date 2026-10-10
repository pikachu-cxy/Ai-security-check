"""Host-neutral advisory quick checks; eq-v1 families are counted, not instances."""
from __future__ import annotations

import hmac
import hashlib
import json
import os
import re
import subprocess
import time
from contextlib import nullcontext
from time import perf_counter
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath

from .equivalence import equivalence_key
from .git import GitService
from .hook_state import HookStateStore, identity
from .hooks import HookEvent
from .models import RunStatus
from .target import TargetDetector, IGNORED
from .verification_policy import local_recheck
from .workspace import WorkspaceResolver
from .hook_timing import timings, elapsed, core_context, ExecutionTrigger

HOSTS = ('codex', 'cursor', 'kiro', 'workbuddy', 'codebuddy', 'qoder', 'generic')
MAX_FILES = 1000
MAX_BYTES = 20_000_000
MAX_FAMILIES = 2000
MAX_OCCURRENCES = 10000
MAX_PROOF_RULES = 1000


def safe_path(value):
    if not isinstance(value, str) or not value or len(value) > 1000 or any(ord(c) < 32 for c in value):
        raise ValueError('Invalid hook path')
    path = PurePosixPath(value)
    if path.is_absolute() or '..' in path.parts or ':' in value or '\\' in value:
        raise ValueError('Hook path is outside workspace')
    return path.as_posix()


def metadata(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_.:/+@-]{1,200}', value):
        raise ValueError('Invalid hook detector metadata')
    return value


def _validate_rule_versions(value):
    """Closed, bounded detector metadata; never scanner evidence or source."""
    if not isinstance(value, dict) or len(value) > MAX_PROOF_RULES:
        raise ValueError('Invalid hook rule version proof')
    for detector, version in value.items():
        metadata(detector); metadata(version)
    return value


@dataclass
class HookSnapshot:
    schema_version: str
    workspace_id: str
    host: str
    session_id: str
    change_digest: str
    changed_files: list[str]
    families: dict
    last_scan_id: str | None
    last_completed_at: float
    last_result: dict
    file_digests: dict | None = None


def validate_state(value):
    fields = set(HookSnapshot.__dataclass_fields__)
    if not isinstance(value, dict) or set(value) not in (fields, fields - {'file_digests'}) or value['schema_version'] != 'hook-v1':
        raise ValueError('Invalid hook snapshot')
    for key in ('workspace_id', 'session_id', 'change_digest'):
        if not re.fullmatch('[a-f0-9]{64}', value[key]):
            raise ValueError('Invalid hook snapshot identity')
    if value['host'] not in HOSTS or not isinstance(value['last_completed_at'], (int, float)) or not 0 <= value['last_completed_at'] <= 10**12:
        raise ValueError('Invalid hook snapshot scope')
    if value['last_scan_id'] is not None and not re.fullmatch(r'[A-Za-z0-9-]{1,100}', value['last_scan_id']):
        raise ValueError('Invalid hook scan identity')
    if not isinstance(value['changed_files'], list) or len(value['changed_files']) > MAX_FILES:
        raise ValueError('Hook snapshot budget exceeded')
    for name in value['changed_files']:
        safe_path(name)
    file_digests = value.get('file_digests')
    if file_digests is not None:
        if (not isinstance(file_digests, dict) or len(file_digests) > MAX_FILES
                or not set(value['changed_files']).issubset(file_digests)):
            raise ValueError('Invalid hook file digest inventory')
        for name, digest in file_digests.items():
            safe_path(name)
            if not isinstance(digest, str) or not re.fullmatch('[a-f0-9]{64}', digest):
                raise ValueError('Invalid hook file digest')
    families = value['families']
    if not isinstance(families, dict) or len(families) > MAX_FAMILIES:
        raise ValueError('Hook family budget exceeded')
    count = 0
    for key, family in families.items():
        if not isinstance(family, dict) or not re.fullmatch('eq-v1:[a-f0-9]{64}', key) or set(family) != {'equivalence_key', 'category', 'rule_id', 'file_path', 'scanner_sources', 'count', 'occurrences', 'proof', 'uncertain'} or family['equivalence_key'] != key:
            raise ValueError('Invalid hook family')
        safe_path(family['file_path'])
        metadata(family['category']); metadata(family['rule_id'])
        if not isinstance(family['scanner_sources'], list) or not family['scanner_sources']:
            raise ValueError('Invalid hook providers')
        for source in family['scanner_sources']:
            metadata(source)
        if not isinstance(family['occurrences'], list) or type(family['count']) is not int or not 0 < family['count'] <= MAX_OCCURRENCES or len(family['occurrences']) != family['count'] or type(family['uncertain']) is not bool:
            raise ValueError('Invalid hook occurrence count')
        count += family['count']
        for point in family['occurrences']:
            if not isinstance(point, dict) or set(point) != {'line_start', 'line_end'} or any(type(n) is not int or not 0 <= n <= 10**8 for n in point.values()):
                raise ValueError('Invalid hook coordinates')
        proof = family['proof']
        proof_fields = {'rule_pack_checksum', 'engine', 'rule_version'}
        if not isinstance(proof, dict) or set(proof) not in (proof_fields, proof_fields | {'rule_versions'}):
            raise ValueError('Invalid hook proof')
        for field in proof_fields:
            item = proof[field]
            if not isinstance(item, str):
                raise ValueError('Invalid hook proof metadata')
            if item:
                metadata(item)
        if 'rule_versions' in proof:
            _validate_rule_versions(proof['rule_versions'])
    if count > MAX_OCCURRENCES:
        raise ValueError('Hook occurrence budget exceeded')
    result = value['last_result']
    if not isinstance(result, dict) or set(result) != {'status', 'last_check_status', 'coverage', 'execution_state', 'capabilities', 'scanner_runs', 'delta'}:
        raise ValueError('Invalid hook result')
    for k in ('status', 'last_check_status', 'coverage', 'execution_state'):
        metadata(result[k])
    # The output serializer never reflects unknown state fields. Validate even
    # nested persisted output against the safe projection's closed schema.
    if not isinstance(result['capabilities'], dict) or any(k not in {'CODE_SAST','SECRET_SCAN','DEPENDENCY_VULN','IAC_MISCONFIG'} for k in result['capabilities']):
        raise ValueError('Invalid hook coverage')
    for v in result['capabilities'].values():
        metadata(v)
    if not isinstance(result['scanner_runs'], list):
        raise ValueError('Invalid hook scanner list')
    for run in result['scanner_runs']:
        if not isinstance(run, dict) or set(run) != {'scanner','status','version','duration_ms','error_code','coverage_contract'}:
            raise ValueError('Invalid hook scanner metadata')
        for k in ('scanner','status','coverage_contract'):
            metadata(run[k])
        if run['error_code']:
            metadata(run['error_code'])
        if run['version'] and not re.fullmatch(r'[0-9A-Za-z_.+-]{1,80}', run['version']):
            raise ValueError('Invalid hook scanner version')
        if type(run['duration_ms']) is not int or not 0 <= run['duration_ms'] <= 10**9:
            raise ValueError('Invalid hook duration')
    delta = result['delta']
    if not isinstance(delta, dict) or set(delta) != {'new','persisting','resolved','additional_occurrences','removed_occurrences','families'} or not isinstance(delta['families'], list) or len(delta['families']) > MAX_FAMILIES * 2:
        raise ValueError('Invalid hook delta')
    for k in ('new','persisting','resolved','additional_occurrences','removed_occurrences'):
        if type(delta[k]) is not int or not 0 <= delta[k] <= MAX_OCCURRENCES:
            raise ValueError('Invalid hook delta count')
    for row in delta['families']:
        if not isinstance(row, dict) or set(row) != {'equivalence_key','file_path','rule_id','category','status','previous_count','current_count','occurrence_delta','count_certainty'} or not re.fullmatch('eq-v1:[a-f0-9]{64}',row['equivalence_key']):
            raise ValueError('Invalid hook delta family')
        safe_path(row['file_path'])
        for k in ('rule_id','category','status','count_certainty'):
            metadata(row[k])
        for k in ('previous_count','current_count','occurrence_delta'):
            if type(row[k]) is not int or abs(row[k]) > MAX_OCCURRENCES:
                raise ValueError('Invalid hook delta multiplicity')
    return value


def _git(root, *args):
    with __import__('tempfile').TemporaryFile() as output:
        proc = subprocess.run(['git','-c',f'safe.directory={root.as_posix()}','-C',str(root),*args],
            stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL, timeout=10)
        if proc.returncode or output.tell() > 4_000_000:
            raise ValueError('Unable to read bounded Git hook snapshot')
        output.seek(0)
        return output.read()


class CapturedSnapshot(tuple):
    """Preserve the existing two-value capture protocol; hashes stay internal."""
    def __new__(cls, digest, paths, file_digests):
        value = super().__new__(cls, (digest, paths))
        value.file_digests = file_digests
        return value


def capture_snapshot(root: Path, key: bytes):
    paths = set()
    for args in (('diff','--name-only','-z','--no-renames'), ('diff','--cached','--name-only','-z','--no-renames'), ('ls-files','--others','--exclude-standard','-z')):
        paths.update(safe_path(v.decode('utf-8')) for v in _git(root,*args).split(b'\0') if v)
    paths = sorted(name for name in paths if not set(PurePosixPath(name).parts) & IGNORED)
    if len(paths) > MAX_FILES:
        raise ValueError('Hook snapshot file budget exceeded')
    digest = hmac.new(key, b'hook-snapshot-v1', hashlib.sha256)
    try:
        head = _git(root,'rev-parse','--verify','HEAD')
    except ValueError:
        head = b'UNBORN_HEAD'
    digest.update(head)
    index = {}
    for entry in _git(root,'ls-files','--stage','-z').split(b'\0'):
        if entry and b'\t' in entry:
            header,name = entry.split(b'\t',1)
            index.setdefault(name.decode('utf-8'),[]).append(header)
    total = 0
    file_digests = {}
    for name in paths:
        # Validate links and traversal even for removed files before reading.
        TargetDetector(max_files=MAX_FILES).detect(root,[name])
        source = root / name
        digest.update(json.dumps(name).encode())
        digest.update(json.dumps([v.decode('ascii') for v in index.get(name,[])]).encode())
        if not source.exists():
            digest.update(b'DELETED')
            file_digests[name] = hmac.new(key, b'hook-file-deleted-v1', hashlib.sha256).hexdigest()
            continue
        if not source.is_file():
            raise ValueError('Hook snapshot path is not a file')
        total += source.stat().st_size
        if total > MAX_BYTES:
            raise ValueError('Hook snapshot content budget exceeded')
        content_digest = hmac.new(key, b'hook-file-v1', hashlib.sha256)
        with source.open('rb') as stream:
            consumed = 0
            while chunk := stream.read(65536):
                consumed += len(chunk)
                if consumed > 1_000_000:
                    raise ValueError('Hook snapshot file budget exceeded')
                content_digest.update(chunk)
        digest.update(content_digest.digest())
        file_digests[name] = content_digest.hexdigest()
    # Git's dirty list can omit byte-only changes (e.g. autocrlf). Keep its
    # existing scope/digest contract, and separately compare the bounded tracked
    # inventory. This never adds unchanged tracked files to the scanner scope.
    inventory = sorted(set(paths) | {safe_path(name) for name in index
        if not set(PurePosixPath(name).parts) & IGNORED})
    if len(inventory) > MAX_FILES:
        raise ValueError('Hook comparison file budget exceeded')
    for name in inventory:
        if name in file_digests:
            continue
        TargetDetector(max_files=MAX_FILES).detect(root, [name])
        source = root / name
        if not source.exists():
            file_digests[name] = hmac.new(key, b'hook-file-deleted-v1', hashlib.sha256).hexdigest()
            continue
        if not source.is_file():
            raise ValueError('Hook comparison path is not a file')
        content_digest = hmac.new(key, b'hook-file-v1', hashlib.sha256)
        consumed = 0
        with source.open('rb') as stream:
            while chunk := stream.read(65536):
                consumed += len(chunk); total += len(chunk)
                if consumed > 1_000_000 or total > MAX_BYTES:
                    raise ValueError('Hook comparison content budget exceeded')
                content_digest.update(chunk)
        file_digests[name] = content_digest.hexdigest()
    return CapturedSnapshot(digest.hexdigest(), paths, file_digests)


def family_multiset(findings, runs, plans):
    families = {}
    succeeded = {r.scanner for r in runs if r.status == RunStatus.SUCCESS}
    for finding in findings:
        row = asdict(finding)
        key = equivalence_key(row)
        if not key or not set(row['scanner_sources']).issubset(succeeded):
            continue
        safe_path(row['file_path'])
        details = row['technical_details']
        plan = next((plans.get(name) for name in row['scanner_sources'] if plans.get(name)), None)
        family = families.setdefault(key, {'equivalence_key':key,'category':metadata(row['category']),
            'file_path':row['file_path'],'rule_id':metadata(details.get('capability_family_anchor',details['rule_id'])
                if row['category'] != 'secret' else details['rule_id']),
            'scanner_sources':[metadata(n) for n in row['scanner_sources']], 'count':0,'occurrences':[],
            'proof':{'rule_pack_checksum':plan.pack.checksum if plan else '',
                     'engine':metadata(details['engine']) if details.get('engine') else '',
                     'rule_version':metadata(details['rule_version']) if details.get('rule_version') else '',
                     'rule_versions':{}},
            'uncertain':False})
        detector = metadata(details['rule_id'])
        version = metadata(details['rule_version']) if details.get('rule_version') else ''
        engine = metadata(details['engine']) if details.get('engine') else ''
        proof = family['proof']
        versions = proof['rule_versions']
        selected = [rule for rule in plan.rules if rule.rule_id == detector] if plan else []
        # A family anchor is not an execution-rule version. Retain every actual
        # variant even when identical coordinates collapse to one occurrence.
        # Unknown/mixed provenance cannot be repaired by choosing the first row.
        if row['category'] == 'secret':
            # Secret occurrence counting is unchanged. These providers have no
            # rule execution proof and covered() continues to reject absence.
            pass
        elif (not version or not engine or not selected or
                any(rule.rule_version != version for rule in selected) or
                proof['engine'] != engine or proof['rule_pack_checksum'] != plan.pack.checksum or
                (detector in versions and versions[detector] != version)):
            family['uncertain'] = True
            versions.clear()
        elif not family['uncertain']:
            versions[detector] = version
            if len(versions) > MAX_PROOF_RULES:
                raise ValueError('Hook rule proof budget exceeded')
        point = {'line_start':int(row['line_start']), 'line_end':int(row['line_end'])}
        # Scanner repeats of the exact same coordinate do not invent another
        # occurrence; distinct coordinates survive historical fingerprint merge.
        if point not in family['occurrences']:
            family['occurrences'].append(point)
            family['count'] += 1
    if len(families) > MAX_FAMILIES or sum(f['count'] for f in families.values()) > MAX_OCCURRENCES:
        raise ValueError('Hook family budget exceeded')
    return families


def covered(family, runs, plans):
    # Only explicit first-party rule/file execution evidence proves absence.
    # Secret detector execution lists are not available: never false-resolve.
    for name in family['scanner_sources']:
        run = next((r for r in runs if r.scanner == name), None)
        plan = plans.get(name)
        if not run or run.status != RunStatus.SUCCESS or run.coverage_contract != 'FULL' or not plan:
            return False
        program = getattr(plan.pack, 'program', None)
        required = program.family_rules(family['rule_id']) if program else (family['rule_id'],)
        selected = {}
        for rule in plan.rules:
            if rule.rule_id not in required:
                continue
            if rule.rule_id in selected and selected[rule.rule_id] != rule.rule_version:
                return False
            selected[rule.rule_id] = rule.rule_version
        proof = family['proof']
        if not selected or (proof['rule_pack_checksum'] and proof['rule_pack_checksum'] != plan.pack.checksum):
            return False
        if proof['engine'] and proof['engine'] != run.provider:
            return False
        applicable = ({r.rule_id for r in plan.pack.catalog if r.rule_id in required and
            Path(family['file_path']).suffix.lower() in r.target_extensions} if program else set(required))
        if not applicable or not applicable.issubset(selected):
            return False
        if 'rule_versions' in proof:
            try:
                versions = _validate_rule_versions(proof['rule_versions'])
            except ValueError:
                return False
            if (not versions or not set(versions).issubset(applicable) or
                    any(selected[detector] != version for detector, version in versions.items())):
                return False
        else:
            # Legacy snapshots lost the original variant ID. Only a uniformly
            # versioned applicable family can prove absence without guessing.
            if not proof['rule_version'] or {selected[detector] for detector in applicable} != {proof['rule_version']}:
                return False
        if not applicable.issubset(plan.confirmed_rules) or family['file_path'] not in plan.scanned_files or family['file_path'] in plan.errored_files or plan.unscoped_error:
            return False
        if family['file_path'] in getattr(plan, 'skipped_files', {}):
            return False
    return True


def family_delta(previous, observed, can_cover):
    delta = {'new':0,'persisting':0,'resolved':0,'additional_occurrences':0,'removed_occurrences':0,'families':[]}
    current = dict(observed)
    for key in sorted(set(previous) | set(observed)):
        old, new = previous.get(key), observed.get(key)
        a, b = old['count'] if old else 0, new['count'] if new else 0
        reliable = can_cover(old or new)
        if old and b < a and not reliable:
            # Presence is useful. A lower Secret count is an observed lower
            # bound, not proof that the unseen occurrence has disappeared.
            current[key] = dict(new or old, uncertain=True)
        if not old:
            status = 'NEW_FAMILY'; delta['new'] += 1
        elif not new and reliable:
            status = 'RESOLVED_FAMILY'; delta['resolved'] += 1
        else:
            status = 'PERSISTING' if new else 'UNCONFIRMED_ABSENCE'
            delta['persisting'] += 1
        difference = b - a if new or reliable else 0
        if old and new:
            delta['additional_occurrences'] += max(0,difference)
            delta['removed_occurrences'] += max(0,-difference)
        family = new or old
        delta['families'].append({k:family[k] for k in ('equivalence_key','file_path','rule_id','category')} | {
            'status':status,'previous_count':a,'current_count':b,'occurrence_delta':difference,
            'count_certainty':'COMPLETE_RULE_FILE_SCOPE' if reliable else 'OBSERVED_LOWER_BOUND'})
    return current, delta


class HookCoordinator:
    def __init__(self, runtime=None, store=None, *, cooldown_ms=1000, clock=time.time, seeds=None,
                 workspace_resolver=None, snapshot_capture=None):
        self.runtime = runtime
        self.store = store or HookStateStore()
        self.cooldown_ms = cooldown_ms
        self.clock = clock
        self.seeds = seeds
        self.workspace_resolver = workspace_resolver
        self.snapshot_capture = snapshot_capture or capture_snapshot
        self._managed_registry = None

    def managed_registry(self):
        """Connection-local preparation reuse; no scanner results are retained."""
        if self.runtime is not None and getattr(self.runtime, 'registry', None) is not None:
            return self.runtime.registry
        if self._managed_registry is None:
            from .scanners import ScannerRegistry, SemgrepAdapter, GitleaksAdapter
            from .toolchain import ToolManager
            manager = ToolManager()
            self._managed_registry = ScannerRegistry([SemgrepAdapter(manager),GitleaksAdapter(manager)],
                tool_manager=manager,fallback_adapters=[])
        return self._managed_registry

    def _scan_scope(self, result, root, scope, *, baseline=False, attribution_candidate=False):
        """One quick provider/observer path for events and setup seeds."""
        observation = {'families': {}, 'runs': [], 'plans': {}}
        def observe(findings, runs, plans):
            observation.update(families=family_multiset(findings, runs, plans), runs=runs, plans=plans)
            # Fixed diagnostic only; candidate contents never enter Hook state.
            result['unattributed_risk_present'] = any(
                f.severity in {'HIGH', 'CRITICAL'} and f.confidence == 'HIGH' for f in findings)
        if not scope:
            result.update(status='NO_CHANGES', coverage='NONE', execution_state='NO_CHANGES')
            return observation
        from .runtime import SecurityRuntime
        runtime = self.runtime
        if runtime is None or (baseline and isinstance(runtime, SecurityRuntime)):
            # Baselines persist ONLY the safe Hook projection, never Finding DB
            # snippets. Event scans keep their normal remediation records.
            class ProjectionOnlyStore:
                def save(self, result):
                    pass
            runtime = SecurityRuntime(self.managed_registry(),store=ProjectionOnlyStore() if baseline else None)
        kwargs = {}
        if baseline:
            from .progress import NullProgressReporter, ScanCancelled
            class BaselineDeadline(NullProgressReporter):
                def checkpoint(self):
                    super().checkpoint()
                    if time.monotonic() - self.started >= 60:
                        raise ScanCancelled()
            kwargs['progress'] = BaselineDeadline()
        started = perf_counter()
        from .recent_hooks import observe as observe_recent_hook
        observe_recent_hook('SCANNER_TRIGGERED', scanner_trigger_reason='POST_TOOL_USE_MUTATION',
                            **{k:result[k] for k in ('scanner_invocation_count',) if k in result})
        try:
            from .first_scan_attribution import probe_scope
            with local_recheck() as ledger, (probe_scope() if attribution_candidate else nullcontext({})) as prepared:
                scan = runtime.scan(root, 'quick', _hook_scope=tuple(scope), _hook_observer=observe, **kwargs)
        finally:
            result.setdefault('timing_ms', timings())['scanner'] = elapsed(started)
            observe_recent_hook('SCANNER_TRIGGERED', scanner_run=locals().get('ledger', {}).get('engine_process_observed'))
        result.update(scan_id=scan.scan_id, coverage=scan.coverage, execution_state=scan.execution_state,
                      capabilities=dict(scan.capability_results))
        result['execution']['scanner_run'] = ledger['engine_process_observed']
        result['scanner_runs'] = [{k: getattr(r, k) for k in
            ('scanner', 'status', 'version', 'duration_ms', 'error_code', 'coverage_contract')} for r in scan.scanner_runs]
        result['scanner_diagnostics'] = scan.scanner_diagnostics
        result['status'] = 'SCANNED' if scan.status == 'COMPLETED' else 'FAILED' if scan.execution_state == 'FAILED' else 'PARTIAL'
        observe_recent_hook('SCANNER_COMPLETED', scanner_run=result['execution']['scanner_run'])
        if attribution_candidate and observation['families']:
            from .first_scan_attribution import capture_detector
            stamp = capture_detector(self.managed_registry(), observation, root)
            observation['attribution_detector'] = stamp if stamp is not None and prepared.get('semgrep') == stamp[0] else None
        return observation

    def handle_lifecycle(self, kind, workspace, host, session_id):
        """Explicit snapshot/activity/finalization dispatch, sharing one Core.

        Existing legacy callers retain their convergence contract. The bounded
        command transport opts into this lifecycle, never into a second scanner.
        """
        from .host_events import EventKind
        event = {EventKind.SESSION_START: HookEvent.SESSION_START,
                 EventKind.WORKSPACE_ACTIVITY: HookEvent.FILE_CHANGED,
                 EventKind.SESSION_STOP: HookEvent.AGENT_STOP}[EventKind(kind)]
        return self.handle(event, workspace, host, session_id, _lifecycle=True)

    def handle(self, event, workspace=None, host='generic', session_id=None, *, _baseline_only=False,
               _lifecycle=False):
        start = time.monotonic()
        event = HookEvent(event)
        if event not in {HookEvent.SESSION_START,HookEvent.FILE_CHANGED,HookEvent.AGENT_STOP} or host not in HOSTS:
            raise ValueError('Unsupported advisory hook event or host')
        if session_id is not None and (not isinstance(session_id,str) or len(session_id)>500):
            raise ValueError('Invalid hook session identity')
        root = (self.workspace_resolver(workspace) if self.workspace_resolver
                else WorkspaceResolver().resolve(workspace).path)
        result = {'schema_version':'hook-v1','event':event.value,'host':host,'status':'BUSY',
            'workspace':str(root),'workspace_id':identity(os.path.normcase(str(root))),
            'session_id':identity(session_id or 'default'),'change_digest':None,'scan_id':None,
            'policy':'ADVISORY','delta':{'new':0,'persisting':0,'resolved':0,'additional_occurrences':0,'removed_occurrences':0,'families':[]},
            'coverage':'UNKNOWN','execution_state':'NOT_EXECUTED','last_check_status':'NOT_EXECUTED','capabilities':{},'scanner_runs':[],
            'execution':{'scanner_run':False,'ai_called':False,'network_required':False,'source_modified':False,'target_build':False},
            'baseline_available':False,'state_recovered':False,'next_step':'Retry on the next event or agent stop.'}
        pending = None
        if _lifecycle:
            from .recent_hooks import observe
            route = {HookEvent.SESSION_START:'SESSION_BASELINE', HookEvent.FILE_CHANGED:'WORKSPACE_RECONCILIATION',
                     HookEvent.AGENT_STOP:'SESSION_FINALIZATION'}[event]
            before, recovered = self.store.load(self.store.path(root, host, session_id))
            result.update(event_dispatch_route=route, baseline_state_before='AVAILABLE' if before else 'INVALID' if recovered else 'MISSING',
                baseline_state_after='AVAILABLE' if before else 'INVALID' if recovered else 'MISSING',
                baseline_publish_status='NOT_ATTEMPTED', activity_waited_for_baseline=None,
                activity_wait_ms=0, busy_reason=None, mutation_event_dropped=False,
                pending_mutation=False, scanner_invocation_count=0)
            if event == HookEvent.FILE_CHANGED:
                pending = self.store.pending_activity(root, host, session_id, mark=True)
                result['pending_mutation'] = True
            observe('CLAIMS_VALID', **result)
        waiting = time.monotonic()
        with self.store.lock(root, wait_seconds=10 if _lifecycle else 2 if event == HookEvent.AGENT_STOP else 0) as locked:
            if _lifecycle and event == HookEvent.FILE_CHANGED:
                result['activity_wait_ms'] = round((time.monotonic()-waiting)*1000, 3)
                # A missing baseline at arrival plus publication while waiting is
                # the observable baseline wait; other lock owners remain unknown.
                current, _ = self.store.load(self.store.path(root, host, session_id))
                result['activity_waited_for_baseline'] = (True if not before and current else
                    False if result['activity_wait_ms'] < 20 else None)
            if locked:
                if _lifecycle and event == HookEvent.SESSION_START:
                    self._session_baseline_locked(result, root, host, session_id)
                elif _lifecycle and event == HookEvent.AGENT_STOP:
                    self._session_finalize_locked(result, root, host, session_id)
                else:
                    self._handle_locked(result,event,root,host,session_id,baseline_only=_baseline_only,
                                        lifecycle_activity=_lifecycle)
                if (pending is not None and result['status'] in {'SCANNED', 'NO_CHANGE', 'NO_CHANGES', 'BASELINE_ESTABLISHED'}
                        and result.get('first_scan_attribution_status') != 'FIRST_SCAN_ATTRIBUTION_INCONCLUSIVE'):
                    result['pending_mutation'] = self.store.pending_activity(root, host, session_id, completed=pending) is not None
            elif _lifecycle:
                result.update(status='INCONCLUSIVE', reason='WORKSPACE_SINGLE_FLIGHT_TIMEOUT',
                    busy_reason='WORKSPACE_SINGLE_FLIGHT_TIMEOUT',
                    next_step='Activity is pending. Retry a workspace activity after the current transaction finishes; Stop does not scan.')
            if _lifecycle:
                current, _ = self.store.load(self.store.path(root, host, session_id))
                result['baseline_state_after'] = 'AVAILABLE' if current else 'MISSING'
                observe('HANDLER_COMPLETED', **result)
        result['duration_ms'] = round((time.monotonic()-start)*1000)
        result.setdefault('timing_ms', timings())['hook_total'] = result['duration_ms']
        result['execution_context'] = core_context(ExecutionTrigger.STOP if event == HookEvent.AGENT_STOP else ExecutionTrigger.HOOK)
        from .scanner_cache import lifetime
        result.update(lifetime())
        return result

    def _session_baseline_locked(self, result, root, host, session_id):
        """Publish a comparison point only; it asserts no scanner coverage."""
        from .recent_hooks import observe
        path = self.store.path(root, host, session_id)
        previous, recovered = self.store.load(path)
        result['state_recovered'] = recovered
        if previous and any(previous[k] != result[k] for k in ('workspace_id','host','session_id')):
            result.update(status='INCONCLUSIVE', reason='BASELINE_REFERENCE_REJECTED', baseline_publish_status='FAILED')
            return
        if previous:
            result.update(status='BASELINE_ESTABLISHED', baseline_available=True,
                snapshot_available=True, baseline_publish_status='RETAINED',
                next_step='Existing session comparison point retained; no scanner was invoked.')
            return
        observe('BASELINE_CAPTURE_STARTED', **result)
        if self.store.pending_activity(root, host, session_id) is not None:
            result.update(status='INCONCLUSIVE', reason='BASELINE_ATTRIBUTION_UNAVAILABLE',
                baseline_publish_status='REJECTED_ACTIVITY_ORDER', pending_mutation=True)
            return
        try:
            key = self.store.key(root)
            captured = self.snapshot_capture(root, key)
            after = self.snapshot_capture(root, key)
            if (captured != after or getattr(captured,'file_digests',None) != getattr(after,'file_digests',None)
                    or self.store.pending_activity(root, host, session_id) is not None):
                result.update(status='INCONCLUSIVE', reason='BASELINE_ATTRIBUTION_UNAVAILABLE',
                    baseline_publish_status='REJECTED_ACTIVITY_ORDER')
                return
            digest, files = captured
            summary = {k:result[k] for k in ('status','last_check_status','coverage','execution_state','capabilities','scanner_runs','delta')}
            summary['status'] = 'COMPARISON_BASELINE'
            state = asdict(HookSnapshot('hook-v1', result['workspace_id'], host, result['session_id'],
                digest, files, {}, None, 0, summary, getattr(captured,'file_digests',None)))
            self.store.save(path, state)
        except (ValueError, OSError):
            result.update(status='INCONCLUSIVE', reason='BASELINE_CAPTURE_FAILED', baseline_publish_status='FAILED')
            return
        result.update(status='BASELINE_ESTABLISHED', baseline_available=True, snapshot_available=True,
            baseline_publish_status='PUBLISHED', snapshot_source='SESSION_BASELINE',
            snapshot_generation=identity(digest + json.dumps(state['file_digests'],sort_keys=True)),
            scanner_trigger_reason=None, scanner_skipped_reason='SESSION_BASELINE_ONLY',
            next_step='Filesystem comparison baseline published; security coverage is not asserted.')
        observe('BASELINE_PUBLISHED', **result)

    def _session_finalize_locked(self, result, root, host, session_id):
        from .recent_hooks import observe
        previous, recovered = self.store.load(self.store.path(root, host, session_id))
        if previous and any(previous[k] != result[k] for k in ('workspace_id','host','session_id')):
            previous = None
            recovered = True
        result.update(status='SESSION_FINALIZED' if previous else 'INCONCLUSIVE',
            reason='SESSION_STOP_WITHOUT_BASELINE' if previous is None else None,
            state_recovered=recovered, baseline_available=previous is not None,
            snapshot_available=previous is not None,
            pending_mutation=self.store.pending_activity(root, host, session_id) is not None,
            scanner_trigger_reason=None, scanner_skipped_reason='SESSION_FINALIZATION_ONLY',
            next_step='Session finalized without scanning or publishing a new baseline; pending changes require a workspace activity.')
        observe('SESSION_FINALIZED', **result)

    def _handle_locked(self,result,event,root,host,session_id,*,baseline_only=False,lifecycle_activity=False):
        from .first_scan_attribution import diagnostics, attribute
        result.update(diagnostics())
        path = self.store.path(root,host,session_id)
        previous,recovered = self.store.load(path)
        result['state_recovered'] = recovered
        if previous and any(previous[k] != result[k] for k in ('workspace_id','host','session_id')):
            previous = None
            result['state_recovered'] = True
        captured = self.snapshot_capture(root,self.store.key(root))
        digest,files = captured
        current_files = getattr(captured, 'file_digests', None)
        result['change_digest'] = digest
        # Count only the bounded snapshot identities; paths/content remain
        # internal and are never returned through the host transport.
        result['snapshot_file_count'] = len(files)
        seeded = False
        from .host_event_adapters import host_capabilities
        if previous is None and host_capabilities(host).supports_setup_seed:
            from .baseline_seed import WorkspaceBaselineSeeds
            seed, diagnostic = (self.seeds or WorkspaceBaselineSeeds()).load(root)
            result['baseline_seed_status'] = diagnostic
            if seed is not None:
                previous = seed
                seeded = True
                previous = {**seed, 'host': host, 'session_id': result['session_id'], 'last_completed_at': 0}
        result['baseline_source'] = 'SETUP_SEED' if seeded else 'SESSION' if previous else 'NONE'
        result['baseline_available'] = previous is not None
        old_files = previous.get('file_digests') if previous else None
        content_changed = ({name for name in set(old_files) | set(current_files)
                            if old_files.get(name) != current_files.get(name)}
                           if old_files is not None and current_files is not None else None)
        match = (digest == previous['change_digest'] and not content_changed) if previous else None
        count = len(content_changed) if content_changed is not None else 0 if match else None
        result.update(snapshot_available=previous is not None,
            snapshot_source='SETUP_SEED' if seeded else
                'SESSION_BASELINE' if previous and previous['last_result']['status'] in {'PRE_EXISTING_BASELINE','COMPARISON_BASELINE'} else
                'SESSION_PROCESSED' if previous else 'NONE',
            snapshot_generation=identity(previous['change_digest'] + json.dumps(old_files,sort_keys=True)) if previous else None,
            pre_snapshot_match=match, content_delta_detected=count > 0 if count is not None else None,
            changed_file_count=count, workspace_mutation_observed=not match if match is not None else None,
            reconciliation_reason='NO_TRUSTED_PRE_EDIT_SNAPSHOT' if previous is None else
                'DIGEST_MATCH' if match else 'CONTENT_DIGEST_DELTA' if count else 'SNAPSHOT_DIGEST_DELTA')
        from .recent_hooks import observe as observe_recent_hook
        observe_recent_hook('RECONCILIATION_COMPLETED', **{k:result[k] for k in (
            'changed_file_count', 'snapshot_file_count', 'workspace_mutation_observed', 'snapshot_available',
            'snapshot_source', 'snapshot_generation', 'pre_snapshot_match', 'content_delta_detected', 'reconciliation_reason')})
        if previous and not seeded and match:
            observe_recent_hook('MUTATION_NOT_OBSERVED', workspace_mutation_observed=False, scanner_run=False)
            result.update(previous['last_result'])
            result.update(status='REUSED_LAST_RESULT' if event == HookEvent.AGENT_STOP else 'NO_CHANGE',
                          scan_id=previous['last_scan_id'],next_step='Reuse the existing advisory result; coverage limits still apply.')
            return
        if not lifecycle_activity and previous and not seeded and event == HookEvent.FILE_CHANGED and 0 <= self.clock()-previous['last_completed_at'] < self.cooldown_ms/1000:
            result.update(status='DEBOUNCED',scan_id=previous['last_scan_id'],coverage=previous['last_result']['coverage'],
                          next_step='Pending changes will be checked on the next event or agent stop.')
            return
        # Include formerly dirty paths so a revert can be rechecked, while a
        # deletion/rename cannot imply family resolution without file coverage.
        # Seed inventories can include findings in tracked clean files. Recheck
        # those candidate paths, not the entire setup inventory, so they persist
        # without false NEW attribution or unproven disappearance.
        retained = set(previous['changed_files']) | {f['file_path'] for f in previous['families'].values()} if previous else set()
        scope = sorted(set(files) | retained | (content_changed or set()))
        if lifecycle_activity and previous is not None and content_changed is not None:
            scope = sorted(content_changed | {f['file_path'] for f in previous['families'].values()})
        scope = TargetDetector(max_files=MAX_FILES).detect(root,scope).files
        old = previous['families'] if previous else {}
        if lifecycle_activity:
            result['scanner_invocation_count'] = 1 if scope else 0
        comparison_only = previous is not None and previous['last_result']['status'] == 'COMPARISON_BASELINE'
        observation = self._scan_scope(result, root, scope, baseline=baseline_only,
                                      attribution_candidate=comparison_only)
        if not scope:
            result['scan_id'] = previous['last_scan_id'] if previous else None
        result['last_check_status'] = result['status']
        if lifecycle_activity and result['status'] in {'FAILED','PARTIAL'}:
            # Failed/incomplete processing must leave the earlier comparison
            # point and pending intent intact, so identical-byte retries scan.
            return
        after_capture = self.snapshot_capture(root,self.store.key(root))
        after,_ = after_capture
        if after != digest or getattr(after_capture, 'file_digests', None) != current_files:
            # Never attach a completed digest to moving source contents.
            result.update(status='PARTIAL',coverage='UNKNOWN',next_step='Workspace changed during the check; retry to converge.')
            return
        attribution_old = None
        if comparison_only and observation['families']:
            attribution_old = attribute(self, root, previous, content_changed,
                                        current_files or {}, observation, result)
            observe_recent_hook('SCANNER_COMPLETED', **result)
            if attribution_old is None:
                result.update(reason='FIRST_SCAN_UNATTRIBUTED_RISK_PRESENT',
                    next_step='Current candidates remain reviewable; pre-edit attribution is inconclusive. No NEW attribution or snapshot advancement is authorized.')
                return
            # A pre-edit scan cannot attach proof to bytes changed while it ran.
            final = self.snapshot_capture(root, self.store.key(root))
            if final != captured or getattr(final, 'file_digests', None) != current_files:
                result.update(first_scan_attribution_status='FIRST_SCAN_ATTRIBUTION_INCONCLUSIVE',
                    first_scan_attribution_reason='SOURCE_CHANGED_DURING_ATTRIBUTION',
                    pre_existing_risk_count=None, newly_attributed_risk_count=None,
                    reason='FIRST_SCAN_UNATTRIBUTED_RISK_PRESENT', status='PARTIAL', coverage='UNKNOWN')
                observe_recent_hook('SCANNER_COMPLETED', **result)
                return
            old = attribution_old
        elif comparison_only or previous is None:
            result['first_scan_attribution_status'] = ('FIRST_SCAN_ATTRIBUTION_INCONCLUSIVE'
                if observation['families'] else 'FIRST_SCAN_NO_RISK')
        can_cover = lambda family: covered(family,observation['runs'],observation['plans'])
        families,delta = family_delta(old,observation['families'],can_cover)
        if previous is None or comparison_only and attribution_old is None:
            delta = result['delta']
            if previous is None:
                result['status'] = 'BASELINE_ESTABLISHED'
            result['next_step'] = 'Baseline established for the current quick scope; existing candidates are not attributed to this edit.'
            if result.get('unattributed_risk_present'):
                result['reason'] = 'FIRST_SCAN_UNATTRIBUTED_RISK_PRESENT'
                result['next_step'] = ('High-confidence risk is present, but no valid earlier baseline proves edit attribution. '
                    'Review the existing candidates; automatic remediation is not authorized by this first scan.')
        else:
            result['next_step'] = 'Review new families and added occurrences through MCP; unconfirmed absence requires a reliable recheck.'
            if attribution_old is not None:
                result['reason'] = result['first_scan_attribution_status']
        result['delta'] = delta
        if any(f['uncertain'] for f in families.values()) and previous:
            result['status'] = 'PARTIAL'
            result['last_check_status'] = 'PARTIAL'
        summary = {k:result[k] for k in ('status','last_check_status','coverage','execution_state','capabilities','scanner_runs','delta')}
        state = asdict(HookSnapshot('hook-v1',result['workspace_id'],host,result['session_id'],digest,files,
            families,result['scan_id'],self.clock(),summary,current_files))
        self.store.save(path,state)
