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


def source_revision(root, key):
    no_links(root)
    git = GitService(root) if (root / '.git').exists() else None
    names = git.changed_files('release') if git else None
    files = TargetDetector().detect(root, names).files
    digest = hmac.new(key, b'whole-project-source-v1' + os.path.normcase(str(root)).encode(), hashlib.sha256)
    digest.update(encode(files))
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
    if TargetDetector().detect(root, git.changed_files('release') if git else None).files != files:
        raise ValueError('SOURCE_INVENTORY_MOVING')
    return digest.hexdigest(), len(files)


def capture(root, store, *, mode, staged, rules_path, hook_scope):
    value = {'contract': CONTRACT, 'mode': str(mode), 'source_kind': 'INDEX' if staged else 'WORKTREE',
             'requested_scope': 'PROJECT' if str(mode) == 'release' else 'SELECTED_FILES',
             'started_at': time.time(), 'custom_rules': bool(rules_path),
             'hook_scope': hook_scope is not None, 'build': build_identity(),
             'exclusions': sorted(TargetDetector().ignored), 'source_revision': None}
    try:
        if str(mode) == 'release' and not staged:
            value['source_revision'], value['inventory_count'] = source_revision(root, store.evidence_key())
    except (ValueError, OSError, AttributeError, RuntimeError):
        value['capture_reason'] = 'SOURCE_REVISION_UNVERIFIABLE'
    return value


def complete(value, root, store):
    value = dict(value, finished_at=time.time(), source_consistent=False)
    try:
        key = store.evidence_key()
        if value['source_revision'] is not None:
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
