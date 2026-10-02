"""Host-neutral advisory quick checks; eq-v1 families are counted, not instances."""
from __future__ import annotations

import hmac
import hashlib
import json
import os
import re
import subprocess
import time
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

HOSTS = ('codex', 'cursor', 'kiro', 'workbuddy', 'codebuddy', 'qoder', 'generic')
MAX_FILES = 1000
MAX_BYTES = 20_000_000
MAX_FAMILIES = 2000
MAX_OCCURRENCES = 10000


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


def validate_state(value):
    fields = set(HookSnapshot.__dataclass_fields__)
    if not isinstance(value, dict) or set(value) != fields or value['schema_version'] != 'hook-v1':
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
        if not isinstance(proof, dict) or set(proof) != {'rule_pack_checksum', 'engine', 'rule_version'}:
            raise ValueError('Invalid hook proof')
        for item in proof.values():
            if item:
                metadata(item)
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
    for name in paths:
        # Validate links and traversal even for removed files before reading.
        TargetDetector(max_files=MAX_FILES).detect(root,[name])
        source = root / name
        digest.update(json.dumps(name).encode())
        digest.update(json.dumps([v.decode('ascii') for v in index.get(name,[])]).encode())
        if not source.exists():
            digest.update(b'DELETED')
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
    return digest.hexdigest(), paths


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
            'file_path':row['file_path'],'rule_id':metadata(details['rule_id']),
            'scanner_sources':[metadata(n) for n in row['scanner_sources']], 'count':0,'occurrences':[],
            'proof':{'rule_pack_checksum':plan.pack.checksum if plan else '',
                     'engine':metadata(details['engine']) if details.get('engine') else '',
                     'rule_version':metadata(details['rule_version']) if details.get('rule_version') else ''},
            'uncertain':False})
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
        rule = next((r for r in plan.rules if r.rule_id == family['rule_id']), None)
        proof = family['proof']
        if not rule or (proof['rule_pack_checksum'] and proof['rule_pack_checksum'] != plan.pack.checksum) or (proof['rule_version'] and proof['rule_version'] != rule.rule_version):
            return False
        if proof['engine'] and proof['engine'] != run.provider:
            return False
        if family['rule_id'] not in plan.confirmed_rules or family['file_path'] not in plan.scanned_files or family['file_path'] in plan.errored_files or plan.unscoped_error:
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
    def __init__(self, runtime=None, store=None, *, cooldown_ms=1000, clock=time.time):
        self.runtime = runtime
        self.store = store or HookStateStore()
        self.cooldown_ms = cooldown_ms
        self.clock = clock

    def handle(self, event, workspace=None, host='generic', session_id=None):
        start = time.monotonic()
        event = HookEvent(event)
        if event not in {HookEvent.SESSION_START,HookEvent.FILE_CHANGED,HookEvent.AGENT_STOP} or host not in HOSTS:
            raise ValueError('Unsupported advisory hook event or host')
        if session_id is not None and (not isinstance(session_id,str) or len(session_id)>500):
            raise ValueError('Invalid hook session identity')
        root = WorkspaceResolver().resolve(workspace).path
        result = {'schema_version':'hook-v1','event':event.value,'host':host,'status':'BUSY',
            'workspace':str(root),'workspace_id':identity(os.path.normcase(str(root))),
            'session_id':identity(session_id or 'default'),'change_digest':None,'scan_id':None,
            'policy':'ADVISORY','delta':{'new':0,'persisting':0,'resolved':0,'additional_occurrences':0,'removed_occurrences':0,'families':[]},
            'coverage':'UNKNOWN','execution_state':'NOT_EXECUTED','last_check_status':'NOT_EXECUTED','capabilities':{},'scanner_runs':[],
            'execution':{'scanner_run':False,'ai_called':False,'network_required':False,'source_modified':False,'target_build':False},
            'baseline_available':False,'state_recovered':False,'next_step':'Retry on the next event or agent stop.'}
        with self.store.lock(root, wait_seconds=2 if event == HookEvent.AGENT_STOP else 0) as locked:
            if locked:
                self._handle_locked(result,event,root,host,session_id)
        result['duration_ms'] = round((time.monotonic()-start)*1000)
        return result

    def _handle_locked(self,result,event,root,host,session_id):
        path = self.store.path(root,host,session_id)
        previous,recovered = self.store.load(path)
        result['state_recovered'] = recovered
        if previous and any(previous[k] != result[k] for k in ('workspace_id','host','session_id')):
            previous = None
            result['state_recovered'] = True
        digest,files = capture_snapshot(root,self.store.key(root))
        result['change_digest'] = digest
        result['baseline_available'] = previous is not None
        if previous and digest == previous['change_digest']:
            result.update(previous['last_result'])
            result.update(status='REUSED_LAST_RESULT' if event == HookEvent.AGENT_STOP else 'NO_CHANGE',
                          scan_id=previous['last_scan_id'],next_step='Reuse the existing advisory result; coverage limits still apply.')
            return
        if previous and event == HookEvent.FILE_CHANGED and 0 <= self.clock()-previous['last_completed_at'] < self.cooldown_ms/1000:
            result.update(status='DEBOUNCED',scan_id=previous['last_scan_id'],coverage=previous['last_result']['coverage'],
                          next_step='Pending changes will be checked on the next event or agent stop.')
            return
        # Include formerly dirty paths so a revert can be rechecked, while a
        # deletion/rename cannot imply family resolution without file coverage.
        scope = sorted(set(files) | set(previous['changed_files'] if previous else []))
        scope = TargetDetector(max_files=MAX_FILES).detect(root,scope).files
        old = previous['families'] if previous else {}
        observation = {'families':{},'runs':[],'plans':{}}
        def observe(findings,runs,plans):
            observation.update(families=family_multiset(findings,runs,plans),runs=runs,plans=plans)
        if scope:
            from .runtime import SecurityRuntime
            runtime = self.runtime
            if runtime is None:
                # Hooks never discover/import third-party scanner plugins:
                # quick here is the two existing bounded local providers.
                from .scanners import ScannerRegistry, SemgrepAdapter, GitleaksAdapter
                from .toolchain import ToolManager
                manager = ToolManager()
                runtime = SecurityRuntime(ScannerRegistry([SemgrepAdapter(manager),GitleaksAdapter(manager)],
                    tool_manager=manager,fallback_adapters=[]))
            with local_recheck() as ledger:
                scan = runtime.scan(root,'quick',_hook_scope=tuple(scope),_hook_observer=observe)
            result.update(scan_id=scan.scan_id,coverage=scan.coverage,execution_state=scan.execution_state,
                          capabilities=dict(scan.capability_results))
            result['execution']['scanner_run'] = ledger['engine_process_observed']
            result['scanner_runs'] = [{k:getattr(r,k) for k in ('scanner','status','version','duration_ms','error_code','coverage_contract')} for r in scan.scanner_runs]
            result['status'] = 'SCANNED' if scan.status == 'COMPLETED' else 'FAILED' if scan.execution_state == 'FAILED' else 'PARTIAL'
        else:
            result.update(status='NO_CHANGES',coverage='NONE',execution_state='NO_CHANGES',
                          scan_id=previous['last_scan_id'] if previous else None)
        result['last_check_status'] = result['status']
        after,_ = capture_snapshot(root,self.store.key(root))
        if after != digest:
            # Never attach a completed digest to moving source contents.
            result.update(status='PARTIAL',coverage='UNKNOWN',next_step='Workspace changed during the check; retry to converge.')
            return
        can_cover = lambda family: covered(family,observation['runs'],observation['plans'])
        families,delta = family_delta(old,observation['families'],can_cover)
        if previous is None:
            delta = result['delta']
            result['status'] = 'BASELINE_ESTABLISHED'
            result['next_step'] = 'Baseline established for the current quick scope; existing candidates are not attributed to this edit.'
        else:
            result['next_step'] = 'Review new families and added occurrences through MCP; unconfirmed absence requires a reliable recheck.'
        result['delta'] = delta
        if any(f['uncertain'] for f in families.values()) and previous:
            result['status'] = 'PARTIAL'
            result['last_check_status'] = 'PARTIAL'
        summary = {k:result[k] for k in ('status','last_check_status','coverage','execution_state','capabilities','scanner_runs','delta')}
        state = asdict(HookSnapshot('hook-v1',result['workspace_id'],host,result['session_id'],digest,files,
            families,result['scan_id'],self.clock(),summary))
        self.store.save(path,state)
