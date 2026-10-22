"""Host-neutral advisory quick checks; eq-v1 families are counted, not instances."""
from __future__ import annotations

import hmac
import hashlib
import json
import os
import re
import subprocess
import time
import copy
from contextlib import nullcontext
from time import perf_counter
from dataclasses import asdict, replace, dataclass
from pathlib import Path, PurePosixPath

from .equivalence import equivalence_key
from .git import GitService
from .hook_state import HookStateStore, identity
from .hooks import HookEvent
from .models import RunStatus
from .target import TargetDetector
from .verification_policy import local_recheck
from .workspace import WorkspaceResolver
from .hook_timing import timings, elapsed, core_context, ExecutionTrigger
from .host_lifecycle import HOSTS

MAX_FILES = 1000
MAX_BYTES = 20_000_000
MAX_FAMILIES = 2000
MAX_OCCURRENCES = 10000
MAX_PROOF_RULES = 1000
_UNBOUND_TASK = object()


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
    unproven_sast_files: list[str] | None = None


def captured_input_matches(view, captured, key):
    """Compare actual final mirror bytes with the original Hook inventory.

    The two input contracts use different keyed identities. Comparing their
    digest strings would not establish that Providers received these bytes.
    """
    from .scan_input import _read_file
    expected = getattr(captured, 'file_digests', None)
    if not isinstance(expected, dict):
        return False
    for entry in view.manifest:
        if entry.role == 'RULES':
            continue
        if entry.role == 'ABSENT':
            actual = hmac.new(key, b'hook-file-deleted-v1', hashlib.sha256).hexdigest()
        else:
            raw = _read_file(view.execution_root / entry.path, 1_000_000)
            actual = hmac.new(key, b'hook-file-v1' + raw, hashlib.sha256).hexdigest()
        if entry.path not in expected or not hmac.compare_digest(actual, expected[entry.path]):
            return False
    return True


def capture_recheck_expectation(root, captured, key, scope):
    """Bind known recheck inputs even when Git no longer lists their names.

    An add followed by removal before HEAD can disappear from both index and
    dirty inventory. Its retained recheck scope still requires an actual,
    bounded presence/absence observation before Runtime captures its input.
    Never overwrite the original snapshot or accept arbitrary mirror entries.
    """
    from .hook_state import no_links
    from .scan_input import _read_file
    from .progress import checkpoint
    expected = getattr(captured, 'file_digests', None)
    if not isinstance(expected, dict):
        raise ValueError('Hook input expectation unavailable')
    expected = dict(expected)
    names = sorted({safe_path(name) for name in scope} - set(expected))
    if len(expected) + len(names) > MAX_FILES:
        raise ValueError('Hook input expectation file count budget exceeded')
    consumed = 0
    for name in names:
        checkpoint()
        path = root / name
        no_links(path)
        try:
            raw = _read_file(path, 1_000_000)
        except FileNotFoundError:
            expected[name] = hmac.new(key, b'hook-file-deleted-v1', hashlib.sha256).hexdigest()
        else:
            consumed += len(raw)
            if consumed > MAX_BYTES:
                raise ValueError('Hook input expectation byte budget exceeded')
            expected[name] = hmac.new(key, b'hook-file-v1' + raw, hashlib.sha256).hexdigest()
    return CapturedSnapshot(captured[0], captured[1], expected,
                            getattr(captured, 'target_selection', None))


def incremental_scope(previous, dirty_files, content_changed, *, checked_files=()):
    """Prefer measured byte changes over the cumulative Git dirty inventory.

    Retain original findings for their existing proof-based recheck. Failed,
    partial, deferred and legacy observations keep the conservative inventory;
    this optimization must not forget an unfinished provider's input files.
    checked_files is the preceding real scan's scope for a closeout, not a
    claim that those files or the whole project are safe.
    """
    families = {f['file_path'] for f in previous['families'].values()} if previous else set()
    changed = set(content_changed or ())
    if (previous is None or content_changed is None or
            previous['last_result']['status'] in {'FAILED', 'PARTIAL'} or
            previous['last_result'].get('deferred_code_providers')):
        retained = set(previous['changed_files']) if previous else set()
        return sorted(set(dirty_files) | retained | families | changed | set(checked_files))
    return sorted(changed | families | set(checked_files))


def validate_state(value):
    fields = set(HookSnapshot.__dataclass_fields__)
    if (not isinstance(value, dict) or not fields - {'file_digests', 'unproven_sast_files'} <= set(value) <= fields
            or value['schema_version'] != 'hook-v1'):
        raise ValueError('Invalid hook snapshot')
    gaps = value.get('unproven_sast_files')
    if gaps is not None:
        if not isinstance(gaps, list) or len(gaps) > MAX_FILES:
            raise ValueError('Invalid baseline code gaps')
        for name in gaps:
            safe_path(name)
        if len(set(gaps)) != len(gaps):
            raise ValueError('Invalid baseline code gaps')
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
    result_fields = {'status', 'last_check_status', 'coverage', 'execution_state', 'capabilities', 'scanner_runs', 'delta'}
    if (not isinstance(result, dict) or not result_fields <= set(result) <=
            result_fields | {'baseline_comparison_usable', 'deferred_code_providers'}
            or 'baseline_comparison_usable' in result and type(result['baseline_comparison_usable']) is not bool):
        raise ValueError('Invalid hook result')
    deferred = result.get('deferred_code_providers', [])
    if not isinstance(deferred, list) or len(deferred) > 20 or len(set(deferred)) != len(deferred):
        raise ValueError('Invalid deferred provider scope')
    for provider in deferred:
        metadata(provider)
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
    def __new__(cls, digest, paths, file_digests, target_selection=None):
        value = super().__new__(cls, (digest, paths))
        value.file_digests = file_digests
        value.target_selection = target_selection
        return value


def capture_snapshot(root: Path, key: bytes):
    detector = TargetDetector(max_files=max(1, MAX_FILES))
    paths = set()
    for args in (('diff','--name-only','-z','--no-renames'), ('diff','--cached','--name-only','-z','--no-renames'), ('ls-files','--others','--exclude-standard','-z')):
        paths.update(safe_path(v.decode('utf-8')) for v in _git(root,*args).split(b'\0') if v)
    paths = sorted(name for name in paths if not set(PurePosixPath(name).parts) & detector.ignored)
    if len(paths) > MAX_FILES:
        raise ValueError('Hook snapshot file count budget exceeded')
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
    inventory = sorted(set(paths) | {safe_path(name) for name in index
        if not set(PurePosixPath(name).parts) & detector.ignored})
    if len(inventory) > MAX_FILES:
        raise ValueError('Hook comparison file budget exceeded')
    # Use the same extension + magic-byte policy as scans, including boundary
    # validation before exclusion. A document renamed to text becomes eligible
    # on the next capture and therefore produces a content delta.
    profile = detector.detect(root, inventory, select_scan_targets=True)
    excluded = {row['path'] for row in profile.skipped_files}
    paths = [name for name in paths if name not in excluded]
    inventory = [name for name in inventory if name not in excluded]
    total = 0
    file_digests = {}
    for name in paths:
        # Validate links and traversal even for removed files before reading.
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
    for name in inventory:
        if name in file_digests:
            continue
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
    from .target import selection_summary
    return CapturedSnapshot(digest.hexdigest(), paths, file_digests, selection_summary(profile))


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
            # Count presence independently; only the bound default-detector
            # identity can later be paired with a fresh rule/file receipt.
            checksum = details.get('rule_pack_checksum', '')
            if engine == 'gitleaks' and version and checksum:
                proof['rule_pack_checksum'] = metadata(checksum)
                versions[detector] = version
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
    # A success/zero count alone never proves absence. Secret receipts also
    # bind unchanged default detector configuration and reject observed skips.
    for name in family['scanner_sources']:
        run = next((r for r in runs if r.scanner == name), None)
        if name == 'gitleaks':
            from .secret_coverage import covers
            proof = family['proof']
            if not run or not covers(run, {'rule_id': family['rule_id'],
                    'engine': proof.get('engine'), 'rule_version': proof.get('rule_version'),
                    'rule_pack_checksum': proof.get('rule_pack_checksum')}, family['file_path']):
                return False
            continue
        plan = plans.get(name)
        if not run or run.status != RunStatus.SUCCESS or run.coverage_contract != 'FULL' or not plan:
            return False
        if Path(family['file_path']).suffix.lower() == '.vue':
            # Inline-script findings are useful, but partial SFC coverage is
            # not a proof that an earlier occurrence has been removed.
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
                 workspace_resolver=None, snapshot_capture=None, activity_wait_seconds=0):
        if type(activity_wait_seconds) not in (int, float) or not 0 <= activity_wait_seconds <= 10:
            raise ValueError('Invalid activity wait budget')
        self.runtime = runtime
        self.store = store or HookStateStore()
        self.cooldown_ms = cooldown_ms
        self.clock = clock
        self.seeds = seeds
        self.workspace_resolver = workspace_resolver
        self.snapshot_capture = snapshot_capture or capture_snapshot
        self.activity_wait_seconds = activity_wait_seconds
        self._managed_registry = None

    def managed_registry(self):
        """Connection-local preparation reuse; no scanner results are retained."""
        if self.runtime is not None and getattr(self.runtime, 'registry', None) is not None:
            return self.runtime.registry
        if self._managed_registry is None:
            from .scanners import ScannerRegistry, SemgrepAdapter, GitleaksAdapter, TrivyAdapter
            from .dynamic_function import NativeFunctionScanner
            from .osv import OSVDependencyAdapter
            from .toolchain import ToolManager
            manager = ToolManager()
            self._managed_registry = ScannerRegistry([SemgrepAdapter(manager),NativeFunctionScanner(),GitleaksAdapter(manager),TrivyAdapter(manager)],
                tool_manager=manager,fallback_adapters=[OSVDependencyAdapter(manager)])
        return self._managed_registry

    def _scan_scope(self, result, root, scope, *, baseline=False, attribution_candidate=False,
                    dependency_changes=None, previous_families=None, execution=None):
        """One quick provider/observer path for events and setup seeds."""
        result['hook_scope_files'] = sorted(scope)
        result['hook_recheck_files'] = sorted({f['file_path'] for f in (previous_families or {}).values()})
        observation = {'families': {}, 'runs': [], 'plans': {}}
        def observe(findings, runs, plans):
            # Dependency presence is reviewable even when graph/data coverage
            # is partial. It does not establish a SAST rule/file delta proof.
            observation.update(families=family_multiset([f for f in findings if f.category != 'dependency'], runs, plans),
                               runs=runs, plans=plans)
            succeeded = {r.scanner for r in runs if r.status == RunStatus.SUCCESS
                         and 'DEPENDENCY_VULN' in r.capabilities}
            result['current_dependency_finding_ids'] = sorted({f.id for f in findings
                if f.category == 'dependency' and set(f.scanner_sources).intersection(succeeded)})[:50]
            result['hook_current_dependency_files'] = sorted({safe_path(f.file_path) for f in findings
                if f.category == 'dependency' and set(f.scanner_sources).intersection(succeeded)})
            result['hook_recheck_files'] = sorted(set(result['hook_recheck_files']) |
                {f['file_path'] for f in observation['families'].values()} |
                set(result['hook_current_dependency_files']))
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
        # Only retained provider facts cross the adapter boundary. Eligibility
        # reads run later against Runtime's captured bytes.
        code_preference, recheck_native = 'FULL', False
        if not baseline and isinstance(runtime, SecurityRuntime):
            from .dynamic_function import NativeFunctionScanner
            from .scanners import SemgrepAdapter
            from .capabilities import Capability
            prior = list((previous_families or {}).values())
            native = any(type(a) is NativeFunctionScanner for a in runtime.registry.adapters)
            other_code = any(Capability.CODE_SAST in a.capabilities and
                type(a) not in {NativeFunctionScanner, SemgrepAdapter} for a in runtime.registry.adapters)
            other_family = any(any(source != NativeFunctionScanner.scanner_id for source in f['scanner_sources'])
                and f['category'] != 'secret' for f in prior)
            if native and not other_code and not other_family:
                code_preference = 'CANONICAL_DYNAMIC_WHEN_ELIGIBLE'
                recheck_native = any(NativeFunctionScanner.scanner_id in f['scanner_sources'] for f in prior)
        kwargs = {}
        if baseline:
            # Setup/session seeds establish SAST rule/file comparison evidence.
            # Dependency presence has a separate advisory contract and must not
            # turn an otherwise usable connection into a failed SAST baseline.
            dependency_changes = ()
        if baseline:
            from .progress import NullProgressReporter, ScanCancelled
            class BaselineDeadline(NullProgressReporter):
                def checkpoint(self):
                    super().checkpoint()
                    if time.monotonic() - self.started >= 60:
                        raise ScanCancelled()
            kwargs['progress'] = BaselineDeadline()
        if execution is not None:
            if 'progress' in kwargs:
                execution.progress = kwargs.pop('progress')
            # Retain only the bounded risk-bearing immutable bytes needed for
            # optional pre-edit attribution. Never reopen live source later.
            def captured_result(view, scan):
                observation['input_current'] = execution.applicability(view).state == 'CURRENT'
                if attribution_candidate:
                    from .first_scan_attribution import capture_detector, detector_observed
                    stamp = capture_detector(self.managed_registry(), observation, root)
                    observation['attribution_detector'] = stamp if detector_observed(stamp, observation, prepared) else None
                    plan = observation['plans'].get('semgrep')
                    if observation['attribution_detector'] is not None and plan is not None:
                        # Retain the verified provenance pack for the later
                        # pre-edit scan, not a path to a soon-disposed mirror.
                        from .scanners import SemgrepAdapter
                        adapter = next(a for a in self.managed_registry().adapters if type(a) is SemgrepAdapter)
                        observation['plans']['semgrep'] = replace(plan, pack=adapter.rule_packs.resolve())
                    from .scan_input import _read_file
                    from .first_scan_attribution import MAX_TARGETS, MAX_TOTAL, MAX_FILE
                    names = sorted({f['file_path'] for f in observation['families'].values()})
                    if len(names) <= MAX_TARGETS:
                        available = {e.path for e in view.manifest if e.role in {'TARGET', 'CONTEXT'}}
                        if set(names).issubset(available):
                            values = {name:_read_file(view.execution_root/name, MAX_FILE) for name in names}
                            if sum(map(len, values.values())) <= MAX_TOTAL:
                                observation['current_bytes'] = values
            execution._after_scan = captured_result
            kwargs['execution'] = execution
        started = perf_counter()
        from .recent_hooks import observe as observe_recent_hook
        observe_recent_hook('SCANNER_TRIGGERED', scanner_trigger_reason='POST_TOOL_USE_MUTATION',
                            **{k:result[k] for k in ('scanner_invocation_count',) if k in result})
        try:
            from .first_scan_attribution import probe_scope
            from .scanners import baseline_sast_batches
            with local_recheck() as ledger, baseline_sast_batches(baseline), (probe_scope() if attribution_candidate else nullcontext({})) as prepared:
                from .scan_input import scoped_request
                request = replace(scoped_request(root, scope, dependency_changes=dependency_changes),
                    code_preference=code_preference, recheck_native=recheck_native)
                scan = runtime.scan(root, 'quick', request=request, observer=observe, **kwargs)
        finally:
            result.setdefault('timing_ms', timings())['scanner'] = elapsed(started)
            observe_recent_hook('SCANNER_TRIGGERED', scanner_run=locals().get('ledger', {}).get('engine_process_observed'))
        selection = scan.scanner_diagnostics.get('code_selection', {})
        if selection.get('applied'):
            result.update(scan_scope_notice=selection['notice'],
                code_check_scope='CANONICAL_DYNAMIC_CODE_ONLY', deferred_code_providers=['semgrep'])
        result.update(scan_id=scan.scan_id, coverage=scan.coverage, execution_state=scan.execution_state,
                      capabilities=dict(scan.capability_results))
        result['execution']['engine_process_observed'] = ledger['engine_process_observed']
        result['execution']['scanner_run'] = ledger['engine_process_observed'] or any(
            r.status == RunStatus.SUCCESS and r.scanner_diagnostics.get('local_read_observed') is True
            for r in scan.scanner_runs)
        result['scanner_runs'] = [{k: getattr(r, k) for k in
            ('scanner', 'status', 'version', 'duration_ms', 'error_code', 'coverage_contract')} for r in scan.scanner_runs]
        result['dependency_inventory'] = [
            {key: run.dependency_inventory[key] for key in
             ('planned_manifests', 'confirmed_manifests', 'unconfirmed_manifests', 'per_manifest',
              'package_occurrences', 'python_declarations', 'vulnerability_db_freshness')
             if key in run.dependency_inventory}
            for run in scan.scanner_runs
            if run.status == RunStatus.SUCCESS and 'DEPENDENCY_VULN' in run.capabilities]
        result['scanner_diagnostics'] = scan.scanner_diagnostics
        result['status'] = 'SCANNED' if scan.status == 'COMPLETED' else 'FAILED' if scan.execution_state == 'FAILED' else 'PARTIAL'
        from .baseline_coverage import comparison_usable, unproven_files
        result['baseline_comparison_usable'] = comparison_usable(result, observation)
        if baseline:
            result['baseline_unproven_sast_files'] = unproven_files(observation)
        elif scan.findings and hasattr(getattr(runtime, 'store', None), 'finding_review_history'):
            # Retain scanner findings and family comparison exactly as observed.
            # Reminder choices remain independent of raw findings and proofs.
            try:
                from .finding_feedback import FindingFeedbackService
                projection = FindingFeedbackService(runtime.store, root).hook_projection(scan.scan_id)
                result['finding_feedback_projection'] = projection
            except (OSError, ValueError):
                from .risk_decision_guidance import HANDLING_UNAVAILABLE_MESSAGE
                result.update(handling_unavailable=True, handling_status='UNAVAILABLE', risk_choices=[],
                    handling_user_feedback=dict(version='security-user-feedback-v1', choices=[],
                        message=HANDLING_UNAVAILABLE_MESSAGE))
        for run in scan.scanner_runs:
            if run.status == RunStatus.SUCCESS and 'DEPENDENCY_VULN' in run.capabilities:
                fresh = run.dependency_inventory.get('vulnerability_db_freshness')
                if fresh == 'STALE':
                    result['dependency_check_reason'] = 'VULNERABILITY_DB_STALE'
                    break
                if fresh in {'UNKNOWN', 'MISSING'}:
                    result['dependency_check_reason'] = 'VULNERABILITY_DB_FRESHNESS_UNKNOWN'
        dependency_ids = set(result.get('current_dependency_finding_ids', []))
        folded_ids = set((result.get('finding_feedback_projection') or {}).get('folded_finding_ids', []))
        active_ids = {finding.id for finding in scan.findings if finding.id not in folded_ids}
        if result.get('handling_unavailable'):
            active_ids = set()
        result['active_dependency_finding_ids'] = sorted(dependency_ids & active_ids)
        candidates = sorted((f for f in scan.findings if f.id in (dependency_ids & active_ids)),
                            key=lambda f: ({'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3}.get(f.severity,4), f.id))
        if candidates:
            from .hook_user_feedback import issue_feedback, dependency_status_message, combine_feedback, render_feedback
            from .reply_plan import Notice
            items = [issue_feedback(asdict(finding), action='ADVISE') for finding in candidates[:3]]
            if len(candidates) == 1:
                feedback = items[0]
            else:
                feedback = combine_feedback(items, total_count=len(candidates))
            note = (dependency_status_message(result) or '已检查本次读取的依赖版本，但完整依赖关系或漏洞数据的新鲜程度尚未确认。'
                    if scan.capability_results.get('DEPENDENCY_VULN') != 'EXECUTED' else
                    '本次依赖版本检查发现风险；实际安装情况和应用能否被利用尚未确认。')
            render_feedback(feedback, (Notice('CHECK_GAP', note),))
            feedback['finding_count'] = len(candidates)
            if len(candidates) > len(items):
                render_feedback(feedback, (Notice('SCOPE', '本次检查还检出了其他依赖风险；请查看问题列表后逐项选择处理。'),))
            result['dependency_review_finding_ids'] = [finding.id for finding in candidates[:3]]
            result['dependency_user_feedback'] = feedback
        observe_recent_hook('SCANNER_COMPLETED', scanner_run=result['execution']['scanner_run'])
        if attribution_candidate and observation['families']:
            from .first_scan_attribution import capture_detector, detector_observed
            stamp = capture_detector(self.managed_registry(), observation, root)
            if 'attribution_detector' not in observation:
                observation['attribution_detector'] = stamp if detector_observed(stamp, observation, prepared) else None
            elif stamp != observation['attribution_detector']:
                observation['attribution_detector'] = None
        return observation

    def handle_lifecycle(self, kind, workspace, host, session_id, *, expected_task_ref=_UNBOUND_TASK):
        """Explicit snapshot/activity/finalization dispatch, sharing one Core.

        Existing legacy callers retain their convergence contract. The bounded
        command transport opts into this lifecycle, never into a second scanner.
        """
        from .host_events import EventKind
        event = {EventKind.SESSION_START: HookEvent.SESSION_START,
                 EventKind.WORKSPACE_ACTIVITY: HookEvent.FILE_CHANGED,
                 EventKind.SESSION_STOP: HookEvent.AGENT_STOP}[EventKind(kind)]
        return self.handle(event, workspace, host, session_id, _lifecycle=True,
                           expected_task_ref=expected_task_ref)

    def handle(self, event, workspace=None, host='generic', session_id=None, *, _baseline_only=False,
               _lifecycle=False, expected_task_ref=_UNBOUND_TASK):
        start = time.monotonic()
        event = HookEvent(event)
        if event not in {HookEvent.SESSION_START,HookEvent.FILE_CHANGED,HookEvent.AGENT_STOP} or host not in HOSTS:
            raise ValueError('Unsupported advisory hook event or host')
        if session_id is not None and (not isinstance(session_id,str) or len(session_id)>500):
            raise ValueError('Invalid hook session identity')
        if expected_task_ref is not _UNBOUND_TASK and expected_task_ref is not None:
            from .task_security_state import REF
            if not isinstance(expected_task_ref, str) or REF.fullmatch(expected_task_ref) is None:
                raise ValueError('Invalid expected Hook task reference')
        root = (self.workspace_resolver(workspace) if self.workspace_resolver
                else WorkspaceResolver().resolve(workspace).path)
        result = {'schema_version':'hook-v1','event':event.value,'host':host,'status':'BUSY',
            'workspace':str(root),'workspace_id':identity(os.path.normcase(str(root))),
            'session_id':identity(session_id or 'default'),'change_digest':None,'scan_id':None,
            'policy':'ADVISORY','delta':{'new':0,'persisting':0,'resolved':0,'additional_occurrences':0,'removed_occurrences':0,'families':[]},
            'coverage':'UNKNOWN','execution_state':'NOT_EXECUTED','last_check_status':'NOT_EXECUTED','capabilities':{},'scanner_runs':[],
            'execution':{'scanner_run':False,'ai_called':False,'network_required':False,'source_modified':False,'target_build':False},
            'baseline_available':False,'state_recovered':False,'next_step':'Retry on the next event or agent stop.'}
        if not (_lifecycle and event == HookEvent.AGENT_STOP):
            # Consume completed facts before this new event can advance the
            # pending sequence. This never invokes a provider or moves source.
            recovered_publication = self.recover_publications(root, host, session_id)
            if recovered_publication is not None:
                result['publication_recovery'] = {k:v for k,v in recovered_publication.items()
                                                  if k != 'recovered_result'}
        from .background_preparation import current_preparation, preparation_message, ACTIVE
        preparation = current_preparation()
        if preparation['status'] in ACTIVE and not preparation.get('ready'):
            result['background_preparation'] = preparation | {'message': preparation_message(preparation)}
        pending = None
        if not _lifecycle and event == HookEvent.FILE_CHANGED:
            # MCP transport registers arrival before reconciliation so a busy
            # or failed check cannot lose it. Clear only this observed sequence
            # after a completed byte comparison/check; newer arrivals survive.
            pending = self.store.pending_activity(root, host, session_id)
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
        if not (_lifecycle and event == HookEvent.AGENT_STOP):
            from .scan_attempt import ScanAttemptStore
            ScanAttemptStore(self.store, root).recover_cleanup(limit=2)
        waiting = time.monotonic()
        wait_seconds = (10 if _lifecycle else 2 if event == HookEvent.AGENT_STOP else
                        self.activity_wait_seconds if event == HookEvent.FILE_CHANGED else 0)
        transaction = None
        with self.store.lock(root, wait_seconds=wait_seconds) as locked:
            result.update(activity_wait_ms=round((time.monotonic()-waiting)*1000, 3),
                          pending_mutation=pending is not None)
            if _lifecycle and event == HookEvent.FILE_CHANGED:
                current, _ = self.store.load(self.store.path(root, host, session_id))
                result['activity_waited_for_baseline'] = (True if not before and current else
                    False if result['activity_wait_ms'] < 20 else None)
            if locked and _lifecycle and event == HookEvent.AGENT_STOP:
                self._session_finalize_locked(result, root, host, session_id)
            elif locked:
                transaction = self._claim(result, root, host, session_id, pending, expected_task_ref)
            else:
                self._attempt_unavailable(result, lifecycle=_lifecycle)
        if (not _lifecycle and event == HookEvent.AGENT_STOP and transaction is None
                and result.get('busy_reason') == 'WORKSPACE_SCAN_ATTEMPT_BUSY'):
            # Preserve the bounded legacy convergence wait. Normalized Stop
            # above never enters this path and never claims a scanner lane.
            deadline = time.monotonic() + 2
            while transaction is None and time.monotonic() < deadline:
                time.sleep(.025)
                with self.store.lock(root) as locked:
                    if locked:
                        transaction = self._claim(result, root, host, session_id, pending, expected_task_ref)
        # Source inventory, immutable input capture, Providers and attribution
        # run without the workspace state lock. The signed lane remains owned.
        if transaction is not None:
            from .progress import ScanCancelled, progress_context
            try:
                with progress_context(transaction['execution']):
                    if _lifecycle and event == HookEvent.SESSION_START:
                        self._session_baseline(result, root, host, session_id, transaction=transaction)
                    else:
                        self._reconcile(result, event, root, host, session_id,
                            baseline_only=_baseline_only, lifecycle_activity=_lifecycle, transaction=transaction)
                if _lifecycle and event == HookEvent.SESSION_START and result.get('baseline_publish_status') == 'FAILED':
                    self._abandon(result, root, transaction, 'FAILED', reason=result['reason'])
                else:
                    self._stage_publication(result, root, host, session_id, transaction)
                    self._publish(result, root, host, session_id, transaction)
            except (ScanCancelled, KeyboardInterrupt) as error:
                self._abandon(result, root, transaction, 'CANCELLED')
                if isinstance(error, KeyboardInterrupt):
                    raise
            except BaseException:
                if transaction.get('publication') is None:
                    self._abandon(result, root, transaction, 'FAILED')
                raise
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

    @staticmethod
    def _attempt_unavailable(result, *, lifecycle=False, reason='WORKSPACE_SINGLE_FLIGHT_TIMEOUT'):
        result.update(status='INCONCLUSIVE' if lifecycle else 'BUSY', reason=reason,
            busy_reason=reason, next_step='Activity remains pending; the security check did not run. Stop does not scan.')

    def _claim(self, result, root, host, session_id, pending, expected_task_ref=_UNBOUND_TASK):
        from .scan_attempt import ScanAttemptStore, ScanAttemptExecution, source_binding
        from .task_security_state import TaskSecurityStore
        from .task_ownership import record_owner
        path = self.store.path(root, host, session_id)
        previous, recovered = self.store.load(path)
        key = self.store.key(root)
        task = (TaskSecurityStore(self.store, root).for_hook(host, result['session_id'])
                if result['event'] == HookEvent.FILE_CHANGED.value else None)
        if expected_task_ref is not _UNBOUND_TASK and (task['task_ref'] if task else None) != expected_task_ref:
            result.update(status='INCONCLUSIVE', reason='EVENT_TASK_BINDING_CHANGED', pending_mutation=True,
                next_step='The original event task changed; no scan or association with later work was performed.')
            if expected_task_ref is not None:
                result['security_task_ref'] = expected_task_ref
            return None
        attempts = ScanAttemptStore(self.store, root)
        from .scan_publication import ScanPublications
        ScanPublications(self.store, root).collect(attempts)
        lease = attempts.claim('HOOK', identity(host+'\0'+(session_id or 'default')),
            source_binding(dict(previous=previous, pending=pending, task_ref=task['task_ref'] if task else None)),
            owner=record_owner(task) if task else None)
        if lease is None:
            self._attempt_unavailable(result, lifecycle='event_dispatch_route' in result,
                                      reason='WORKSPACE_SCAN_ATTEMPT_BUSY')
            return None
        result.pop('busy_reason', None)
        execution = ScanAttemptExecution(attempts, lease)
        result['scan_attempt'] = lease.receipt | {'publication':'PENDING'}
        return dict(path=path, previous=previous, recovered=recovered, key=key, task=task,
                    pending=pending, attempts=attempts, lease=lease, execution=execution, state=None)

    def _abandon(self, result, root, transaction, outcome, *, reason=None):
        execution = transaction['execution']
        with self.store.lock(root, wait_seconds=2) as acquired:
            if acquired:
                transaction['attempts'].finish(transaction['lease'], input_id=execution.input_id,
                    scan_id=result.get('scan_id'), outcome=outcome)
        result.update(status='INCONCLUSIVE', coverage='UNKNOWN', reason=reason or 'SCAN_ATTEMPT_'+outcome,
            pending_mutation=True, next_step='The captured result is not published; original comparison point and pending changes are retained.')
        if result.get('baseline_publish_status') == 'PUBLISHED':
            result['baseline_publish_status'] = 'FAILED'
        result['scan_attempt'] = execution.receipt | {'publication':'NOT_PUBLISHED'}

    @staticmethod
    def _publication_snapshot(captured):
        return dict(digest=captured[0], paths=list(captured[1]),
                    file_digests=getattr(captured, 'file_digests', None))

    def _stage_publication(self, result, root, host, session_id, transaction):
        from .scan_publication import ScanPublications
        source = transaction.get('publication_snapshot')
        if source is None:
            source = self._publication_snapshot(self.snapshot_capture(root, transaction['key']))
        task = transaction['task']
        transaction['publication'] = ScanPublications(self.store, root).stage('HOOK',
            identity(host+'\0'+(session_id or 'default')), transaction['lease'], dict(
                host=host, session_binding=result['session_id'], result=result,
                previous=transaction['previous'], state=transaction['state'],
                pending=transaction['pending'], task_ref=task['task_ref'] if task else None,
                input_current=transaction.get('input_current'), snapshot=source,
                execution=transaction['execution'].receipt))

    def recover_publications(self, root, host, session_id):
        """Recover only this Hook's original signed facts; no scan or baseline."""
        from types import SimpleNamespace
        from .scan_attempt import AttemptLease, ScanAttemptStore
        from .scan_publication import ScanPublications
        scope = identity(host+'\0'+(session_id or 'default'))
        publications = ScanPublications(self.store, root)
        rows = publications.pending('HOOK', scope)
        for pending in rows:
            payload = pending['payload']
            if payload['host'] != host or payload['session_binding'] != identity(session_id or 'default'):
                raise ValueError('Hook publication owner cannot be verified')
            key = self.store.key(root)
            try:
                fresh = self._publication_snapshot(self.snapshot_capture(root, key)) == payload['snapshot']
            except (OSError, ValueError):
                fresh = False
            attempts = ScanAttemptStore(self.store, root)
            execution = SimpleNamespace(receipt=payload['execution'], input_id=payload['execution'].get('input_id'))
            result = copy.deepcopy(payload['result'])
            transaction = dict(path=self.store.path(root, host, session_id), previous=payload['previous'],
                key=key, task={'task_ref':payload['task_ref']} if payload['task_ref'] else None,
                pending=payload['pending'], attempts=attempts, lease=AttemptLease(**pending['lease']),
                execution=execution, state=payload['state'], input_current=payload['input_current'],
                publication=pending, publication_current=fresh)
            self._publish(result, root, host, session_id, transaction)
            return dict(publication=result['scan_attempt']['publication'],
                reason=result.get('reason'), scanner_run=False, original_attempt=pending['lease']['attempt_id'],
                recovered_result=result if result['scan_attempt']['publication'] in {'PUBLISHED','NO_STATE_CHANGE'} else None)
        return None

    def _publish(self, result, root, host, session_id, transaction):
        from .task_security_state import TaskSecurityStore
        execution, attempts, lease = (transaction[k] for k in ('execution','attempts','lease'))
        from .scan_publication import ScanPublications
        publications = ScanPublications(self.store, root)
        publication = transaction.get('publication')
        # All expensive byte comparisons have completed outside this lock.
        with self.store.lock(root, wait_seconds=2) as acquired:
            if not acquired:
                self._attempt_unavailable(result, lifecycle=True, reason='SCAN_ATTEMPT_PUBLICATION_PENDING')
                if result.get('baseline_publish_status') == 'PUBLISHED':
                    result['baseline_publish_status'] = 'FAILED'
                result['scan_attempt'] = execution.receipt | {'publication':'NOT_PUBLISHED'}
                result['publication_pending'] = publication is not None
                result['source_result_saved'] = publication is not None
                result['next_step'] = 'Completed facts await their original publication fence; retry restores them without another scan.'
                return
            current, _ = self.store.load(transaction['path'])
            lane = attempts.read()['lane']
            if (publication is not None and transaction['state'] is not None
                    and current == transaction['state'] and attempts._matches(lane, lease)
                    and transaction.get('publication_current', True)):
                if lane['state'] == 'ACTIVE' and attempts.is_current(lease, execution.input_id):
                    attempts.finish(lease, input_id=execution.input_id,
                                    scan_id=result.get('scan_id'), outcome='COMPLETED')
                elif lane['state'] != 'COMPLETED':
                    attempts.retire(lease, outcome='STALE')
                    publications.acknowledge(publication)
                    result.update(status='INCONCLUSIVE', coverage='UNKNOWN',
                                  reason='SCAN_ATTEMPT_PUBLICATION_STALE')
                    result['scan_attempt'] = execution.receipt | {'publication':'NOT_PUBLISHED'}
                    return
                publications.acknowledge(publication)
                result['scan_attempt'] = execution.receipt | {'publication':'PUBLISHED'}
                return
            pending = self.store.pending_activity(root, host, session_id)
            task = (TaskSecurityStore(self.store, root).for_hook(host, result['session_id'])
                    if result['event'] == HookEvent.FILE_CHANGED.value else None)
            task_ref = lambda value: value['task_ref'] if value else None
            valid = (attempts.is_current(lease, execution.input_id)
                     and transaction.get('publication_current', True)
                     and current == transaction['previous'] and pending == transaction['pending']
                     and task_ref(task) == task_ref(transaction['task'])
                     and self.store.key(root) == transaction['key'])
            if result.get('hook_scope_files'):
                valid = valid and execution.input_id is not None and transaction.get('input_current') is True
            if not valid:
                attempts.retire(lease, outcome='STALE')
                if publication is not None:
                    publications.acknowledge(publication)
                reason = ('BASELINE_ATTRIBUTION_UNAVAILABLE' if result.get('reason') == 'BASELINE_ATTRIBUTION_UNAVAILABLE'
                          else 'SCAN_ATTEMPT_PUBLICATION_STALE')
                result.update(status='INCONCLUSIVE', coverage='UNKNOWN', reason=reason,
                    pending_mutation=True, next_step='Source, pending sequence or original task changed; the old comparison point is retained.')
                if result.get('baseline_publish_status') == 'PUBLISHED':
                    result['baseline_publish_status'] = 'REJECTED_ACTIVITY_ORDER'
                result['scan_attempt'] = execution.receipt | {'publication':'NOT_PUBLISHED'}
                return
            if transaction['state'] is not None:
                self.store.save(transaction['path'], transaction['state'])
            if (transaction['pending'] is not None and result['status'] in
                    {'SCANNED','NO_CHANGE','NO_CHANGES','BASELINE_ESTABLISHED'} and
                    result.get('first_scan_attribution_status') != 'FIRST_SCAN_ATTRIBUTION_INCONCLUSIVE'):
                result['pending_mutation'] = self.store.pending_activity(root, host, session_id,
                    completed=transaction['pending']) is not None
            attempts.finish(lease, input_id=execution.input_id, scan_id=result.get('scan_id'), outcome='COMPLETED')
            if publication is not None:
                publications.acknowledge(publication)
            result['scan_attempt'] = execution.receipt | {'publication':'PUBLISHED' if transaction['state'] is not None else 'NO_STATE_CHANGE'}

    def _session_baseline(self, result, root, host, session_id, *, transaction):
        """Publish a comparison point only; it asserts no scanner coverage."""
        from .recent_hooks import observe
        path = self.store.path(root, host, session_id)
        previous, recovered = transaction['previous'], transaction['recovered']
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
            key = transaction['key']
            captured = self.snapshot_capture(root, key)
            transaction['publication_snapshot'] = self._publication_snapshot(captured)
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
            transaction['state'] = state
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

    def _reconcile(self,result,event,root,host,session_id,*,baseline_only=False,lifecycle_activity=False,transaction):
        from .first_scan_attribution import diagnostics, attribute
        result.update(diagnostics())
        # A verified task snapshot makes each observed source revision a check
        # boundary. The unchanged-byte reuse guard below still applies; only
        # the legacy time-based debounce is bypassed during actual development.
        task = transaction['task']
        if task:
            result.update(security_task_ref=task['task_ref'], task_edit_check_policy='EVERY_OBSERVED_MUTATION')
        path = self.store.path(root,host,session_id)
        previous,recovered = copy.deepcopy(transaction['previous']), transaction['recovered']
        result['state_recovered'] = recovered
        if previous and any(previous[k] != result[k] for k in ('workspace_id','host','session_id')):
            previous = None
            result['state_recovered'] = True
        captured = self.snapshot_capture(root, transaction['key'])
        transaction['publication_snapshot'] = self._publication_snapshot(captured)
        execution = transaction['execution']
        if getattr(captured, 'target_selection', None) is not None:
            result['target_selection'] = captured.target_selection
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
        if previous:
            from .risk_closure import RiskClosureService
            previous['families'], previous['last_result']['delta'] = RiskClosureService(self.store).overlay(
                root, previous['families'], previous['last_result']['delta'])
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
            from .closeout_state import CloseoutStateStore
            jobs = CloseoutStateStore(self.store.workspace_directory(root) / 'closeout.db', lambda: self.store.key(root))
            job = jobs.latest(result['workspace_id'], identity(host + '\0' + (session_id or 'default')))
            awaiting_proof = any(r['status'] == 'UNCONFIRMED_ABSENCE' for r in result['delta']['families'])
            if ((self.store.pending_activity(root, host, session_id) is not None and
                    (content_changed is None or previous['last_result']['status'] in {'FAILED', 'PARTIAL'})) or awaiting_proof or
                    result.get('deferred_code_providers') or
                    job and job['status'] != 'COMPLETED'):
                result.update(status='CLOSEOUT_PENDING', next_step='Continue the existing Runtime closeout plan through MCP.')
                if job:
                    result['closeout_ref'] = job['closeout_ref']
            return
        if not task and not lifecycle_activity and previous and not seeded and event == HookEvent.FILE_CHANGED and 0 <= self.clock()-previous['last_completed_at'] < self.cooldown_ms/1000:
            result.update(status='DEBOUNCED',scan_id=previous['last_scan_id'],coverage=previous['last_result']['coverage'],
                          next_step='Pending changes will be checked on the next event or agent stop.')
            return
        # Include formerly dirty paths so a revert can be rechecked, while a
        # deletion/rename cannot imply family resolution without file coverage.
        # Seed inventories can include findings in tracked clean files. Recheck
        # those candidate paths, not the entire setup inventory, so they persist
        # without false NEW attribution or unproven disappearance.
        scope = incremental_scope(previous, files, content_changed)
        from .dependency_inputs import is_dependency_input
        detector = TargetDetector(max_files=MAX_FILES)
        existing_scope = detector.detect(root,scope,select_scan_targets=True).files
        dependency_changes = sorted(name for name in (content_changed if content_changed is not None else scope)
                                    if is_dependency_input(name) and not set(Path(name).parts) & detector.ignored)
        # Keep validated removed input names for selection. Providers still see
        # only existing files in the bounded mirror, never resurrected bytes.
        scope = sorted(set(existing_scope) | set(dependency_changes))
        input_expected = capture_recheck_expectation(root, captured, transaction['key'], scope)
        execution.validator = lambda view: captured_input_matches(view, input_expected, transaction['key'])
        old = previous['families'] if previous else {}
        if lifecycle_activity:
            result['scanner_invocation_count'] = 1 if scope else 0
        comparison_only = previous is not None and previous['last_result']['status'] == 'COMPARISON_BASELINE'
        observation = self._scan_scope(result, root, scope, baseline=baseline_only,
                                      attribution_candidate=comparison_only,
                                      dependency_changes=dependency_changes, previous_families=old,
                                      execution=execution)
        transaction['input_current'] = observation.get('input_current')
        if not scope:
            result['scan_id'] = previous['last_scan_id'] if previous else None
        result['last_check_status'] = result['status']
        after_capture = self.snapshot_capture(root,self.store.key(root))
        after,_ = after_capture
        if after != digest or getattr(after_capture, 'file_digests', None) != current_files:
            # Never attach a completed digest to moving source contents.
            result.update(status='PARTIAL',coverage='UNKNOWN',next_step='Workspace changed during the check; retry to converge.')
            result.pop('current_dependency_finding_ids', None)
            result.pop('dependency_user_feedback', None)
            result.pop('dependency_review_finding_ids', None)
            return
        if lifecycle_activity and result['status'] in {'FAILED','PARTIAL'}:
            # Presence can be reviewed, but incomplete processing must retain
            # the previous comparison point and pending intent for a retry.
            return
        attribution_old = None
        if comparison_only and observation['families']:
            attribution_old = attribute(self, root, previous, content_changed,
                                        current_files or {}, observation, result,
                                        current_bytes=observation.get('current_bytes'), execution=execution)
            observe_recent_hook('SCANNER_COMPLETED', **result)
            if attribution_old is None:
                checked = self.snapshot_capture(root, self.store.key(root))
                if checked != captured or getattr(checked, 'file_digests', None) != current_files:
                    result.pop('current_dependency_finding_ids', None)
                    result.pop('dependency_user_feedback', None)
                    result.pop('dependency_review_finding_ids', None)
                result.update(reason='FIRST_SCAN_UNATTRIBUTED_RISK_PRESENT',
                    next_step='Current candidates remain reviewable; pre-edit attribution is inconclusive. No NEW attribution or snapshot advancement is authorized.')
                return
            # A pre-edit scan cannot attach proof to bytes changed while it ran.
            final = self.snapshot_capture(root, self.store.key(root))
            if final != captured or getattr(final, 'file_digests', None) != current_files:
                result.pop('current_dependency_finding_ids', None)
                result.pop('dependency_user_feedback', None)
                result.pop('dependency_review_finding_ids', None)
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
        result['hook_recheck_files'] = sorted({f['file_path'] for f in families.values()} |
                                            set(result.get('hook_current_dependency_files', ())))
        # Partial pre-edit parsing/unsupported code cannot prove NEW attribution
        # even if a later edit makes that file parseable. Keep presence reviewable
        # without an automatic-repair trigger. Secret coverage is independent.
        gaps = set(previous.get('unproven_sast_files') or []) if previous else set()
        unattributed = 0
        for row in delta['families']:
            if row['file_path'] in gaps and row['category'] != 'secret':
                row['count_certainty'] = 'OBSERVED_LOWER_BOUND'
                if row['status'] == 'NEW_FAMILY':
                    row['status'] = 'UNATTRIBUTED_FAMILY'
                    delta['new'] -= 1
                    unattributed += 1
                elif row['previous_count'] and row['current_count'] > row['previous_count']:
                    delta['additional_occurrences'] -= row['current_count'] - row['previous_count']
        if unattributed:
            result.update(status='PARTIAL', last_check_status='PARTIAL',
                          reason='BASELINE_CODE_COVERAGE_GAP', unattributed_code_risk_count=unattributed)
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
        if unattributed:
            result['next_step'] = 'Review current risks; incomplete pre-edit code coverage cannot prove these risks were introduced by this edit.'
        if any(f['uncertain'] for f in families.values()) and previous:
            result['status'] = 'PARTIAL'
            result['last_check_status'] = 'PARTIAL'
        summary = {k:result[k] for k in ('status','last_check_status','coverage','execution_state','capabilities','scanner_runs','delta')}
        if 'baseline_comparison_usable' in result:
            summary['baseline_comparison_usable'] = result['baseline_comparison_usable']
        if 'deferred_code_providers' in result:
            summary['deferred_code_providers'] = result['deferred_code_providers']
        state = asdict(HookSnapshot('hook-v1',result['workspace_id'],host,result['session_id'],digest,files,
            families,result['scan_id'],self.clock(),summary,current_files,
            result.get('baseline_unproven_sast_files') if baseline_only else sorted(gaps) if previous else None))
        transaction['state'] = state
