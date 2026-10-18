"""Bounded keyed source freshness. Summary never creates keys or runs scanners."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import re
from pathlib import Path

from .build_identity import build_identity
from .git import GitService
from .hook_state import no_links
from .target import TargetDetector

CONTRACT = 'scan-source-context-v1'


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def source_revision(root, key, *, identity_root=None, files=None, skipped_files=()):
    no_links(root)
    explicit = files is not None
    git = GitService(root) if (root / '.git').exists() else None
    names = files if files is not None else git.changed_files('release') if git else None
    profile = TargetDetector().detect(root, names, select_scan_targets=True)
    files = profile.files
    digest = hmac.new(key, b'whole-project-source-v1' + os.path.normcase(str(identity_root or root)).encode(), hashlib.sha256)
    digest.update(encode(files))
    digest.update(encode(list(skipped_files) if explicit else profile.skipped_files))
    total = 0
    for name in files:
        path = root / name
        no_links(path)
        before = path.stat()
        if before.st_size > 1_000_000:
            raise ValueError('SOURCE_FRESHNESS_FILE_BUDGET')
        total += before.st_size
        if total > 128_000_000:
            raise ValueError('SOURCE_FRESHNESS_BYTE_BUDGET')
        raw = path.read_bytes()
        after = path.stat()
        if (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns) or len(raw) != before.st_size:
            raise ValueError('SOURCE_MOVING')
        digest.update(hmac.new(key, raw, hashlib.sha256).digest())
    # Detect added files during capture as well as byte changes during reading.
    after = TargetDetector().detect(root, files if explicit else git.changed_files('release') if git else None, select_scan_targets=True)
    if after.files != files or after.skipped_files != profile.skipped_files:
        raise ValueError('SOURCE_INVENTORY_MOVING')
    return digest.hexdigest(), len(files)


def capture(root, store, *, mode, staged, rules_path, hook_scope, logical_root=None, selection=None):
    value = {'contract': CONTRACT, 'mode': str(mode), 'source_kind': 'INDEX' if staged else 'WORKTREE',
             'requested_scope': 'PROJECT' if str(mode) == 'release' else 'SELECTED_FILES',
             'started_at': time.time(), 'custom_rules': bool(rules_path),
             'hook_scope': hook_scope is not None, 'build': build_identity(),
             'exclusions': sorted(TargetDetector().ignored), 'source_revision': None}
    try:
        if str(mode) == 'release' and not staged:
            value['source_revision'], value['inventory_count'] = source_revision(root, store.evidence_key(),
                identity_root=logical_root, files=selection.files if selection else None,
                skipped_files=selection.skipped_files if selection else ())
    except (ValueError, OSError, AttributeError, RuntimeError):
        value['capture_reason'] = 'SOURCE_REVISION_UNVERIFIABLE'
    return value


def complete(value, root, store, *, input_view=None):
    value = dict(value, finished_at=time.time(), source_consistent=False)
    if input_view is not None:
        applicability = input_view.check_current()
        value['fixed_input'] = dict(contract=input_view.contract, input_id=input_view.input_id,
            source_kind=str(input_view.request.source_kind), source_revision=input_view.source_revision,
            input_count=len(input_view.manifest), applicability=applicability.state,
            applicability_reason=applicability.reason_code, scope=applicability.scope)
        value['source_consistent'] = applicability.state == 'CURRENT'
    try:
        key = store.evidence_key()
        if input_view is None and value['source_revision'] is not None:
            value['source_consistent'] = source_revision(root, key)[0] == value['source_revision']
        value['signature'] = hmac.new(key, encode(value), hashlib.sha256).hexdigest()
    except (ValueError, OSError, AttributeError, RuntimeError):
        value['capture_reason'] = 'SOURCE_REVISION_UNVERIFIABLE'
    return value


def summary(scan, store, root):
    context = dict(scan.get('scan_context', {}))
    value = {'mode': scan.get('mode', 'UNKNOWN'), 'requested_scope': context.get('requested_scope', 'UNKNOWN'),
             'started_at': context.get('started_at'), 'finished_at': context.get('finished_at'),
             'actual_files': len(scan.get('target_profile', {}).get('files', [])),
             'languages': sorted(set(scan.get('target_profile', {}).get('languages', [])) &
                                 {'Python', 'Java', 'JavaScript', 'TypeScript', 'Go', 'PHP'}),
             'execution_state': scan.get('execution_state', 'UNKNOWN'),
             'status': scan.get('status', 'UNKNOWN'), 'coverage_scope': scan.get('coverage_scope', 'UNKNOWN'),
             'source_freshness': 'UNKNOWN', 'full_project_reusable': False,
             'reuse_reason': 'SCAN_CONTEXT_UNVERIFIABLE',
             'provider_freshness': 'NOT_REVALIDATED_READ_ONLY',
              'task_publication': 'NOT_DERIVED_FROM_SCAN_HISTORY',
              'current_task_or_hook_state': 'NOT_QUERIED',
             'scanners': [{'scanner': r.get('scanner') if r.get('scanner') in
                          {'semgrep','gitleaks','trivy','trivy-misconfig','trivy-vuln','osv-scanner'} else 'OTHER',
                          'status': r.get('status') if r.get('status') in
                          {'SUCCESS','FAILED','SKIPPED','UNAVAILABLE','TIMEOUT','NOT_APPLICABLE','NOT_COVERED'} else 'UNKNOWN',
                          'version': r.get('version') if isinstance(r.get('version'), str) and
                          re.fullmatch(r'[0-9]+(?:\.[0-9]+){0,3}', r['version']) else 'UNKNOWN'}
                          for r in scan.get('scanner_runs', [])]}
    try:
        signature = context.pop('signature')
        key = store.evidence_key()
        if context.get('contract') != CONTRACT or not hmac.compare_digest(signature, hmac.new(key, encode(context), hashlib.sha256).hexdigest()):
            raise ValueError()
        if context.get('execution_attempt'):
            value['execution_attempt'] = dict(scope='HISTORICAL_EXECUTION_ONLY',
                publication='CHECK_ORIGINAL_TASK_OR_HOOK_AUTHORITY',
                provider_freshness='EXECUTION_TIME_ONLY', current_check_proof=False)
        if context['mode'] != 'release' or context['source_kind'] != 'WORKTREE':
            value['reuse_reason'] = 'NOT_WHOLE_PROJECT_SCAN'
            return value
        if context['build'] != build_identity() or context['exclusions'] != sorted(TargetDetector().ignored):
            value['reuse_reason'] = 'BUILD_RULES_OR_SCOPE_CHANGED'
            return value
        if not context.get('source_consistent') or context.get('source_revision') is None:
            value['reuse_reason'] = 'SOURCE_CHANGED_OR_UNVERIFIABLE_AT_SCAN'
            return value
        fresh = source_revision(root, key)[0] == context['source_revision']
        value.update(source_freshness='CURRENT' if fresh else 'STALE',
                     reuse_reason='CURRENT_PROVIDER_PROOF_NOT_REVALIDATED' if fresh else 'SOURCE_CHANGED')
        # Read-only summary intentionally does not execute engines to re-prove
        # provider/DB identity. Fresh source alone cannot authorize scan reuse.
        # A whole-project request therefore conservatively performs a new scan.
    except (ValueError, OSError, KeyError, TypeError, RuntimeError):
        pass
    return value
