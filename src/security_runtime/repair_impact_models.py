"""Closed, bounded contracts for host impact reasoning; never repair authority."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import PurePosixPath

from .local_evidence import _relative, safe_source

CONTRACT = 'repair-impact-v1'
KINDS = {'EXPECTED_SECURITY_RESTRICTION', 'NO_ADDITIONAL_CHANGE_IDENTIFIED',
         'BUSINESS_BEHAVIOR_CHANGE', 'UNDETERMINED'}
SOURCE_KINDS = {'SCANNER_TASK_GROUP', 'HOST_TASK_RISK'}
RESPONSE_BYTES = 16_000
WINDOW_LINES = 80
ACTIVITY_SECONDS = 900
MATERIAL_SECONDS = 86_400
MAX_FILES = 64
MAX_RECORD_BYTES = 1_000_000
HARD_BYTES = dict(source=4_000_000, navigation=1_000_000, control=2_000_000)
SOURCE_SUFFIXES = frozenset({'.py', '.pyi', '.java', '.js', '.jsx', '.ts', '.tsx',
    '.mjs', '.cjs', '.c', '.h', '.cc', '.cpp', '.hpp', '.cs', '.go', '.rs', '.rb',
    '.php', '.kt', '.kts', '.swift', '.scala', '.vue', '.svelte', '.html', '.css',
    '.scss', '.sql', '.graphql', '.json', '.toml', '.yaml', '.yml', '.xml', '.ini',
    '.conf', '.config', '.properties', '.gradle', '.lock', '.sh', '.ps1'})
BLOCKED_DIRECTORIES = frozenset({'node_modules', '__pycache__', 'build', 'dist',
    'vendor', 'target', 'coverage', 'site-packages', 'venv', 'env', 'bin', 'obj'})


class RepairImpactError(ValueError):
    def __init__(self, reason_code, message=None):
        self.reason_code = reason_code
        super().__init__(message or reason_code)

    def response(self):
        return dict(status='REPAIR_IMPACT_UNAVAILABLE', reason_code=self.reason_code,
                    repair_authorized=False, automatic_execution=False,
                    scanner_run=False, source_modified=False)


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def wire_bytes(value):
    """Include ordinary JSON framing whitespace in the public packet ceiling."""
    return len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode('utf-8'))


def require(condition, reason='REPAIR_IMPACT_INPUT_INVALID'):
    if not condition:
        raise RepairImpactError(reason)


def text(value, maximum=800):
    require(isinstance(value, str) and bool(value.strip()) and len(value) <= maximum)
    # The same literal/credential scrub as source delivery applies before any
    # host prose is saved. Analysis is untrusted, not an instruction channel.
    return '\n'.join(safe_source(value)).strip()[:maximum]


def path(value, *, documentation=False):
    require(isinstance(value, str), 'REPAIR_IMPACT_PATH_REJECTED')
    try:
        name = _relative(value)
    except ValueError:
        raise RepairImpactError('REPAIR_IMPACT_PATH_REJECTED') from None
    parts = PurePosixPath(name).parts
    require(not any(p.startswith('.') or p.lower() in BLOCKED_DIRECTORIES
                    for p in parts), 'REPAIR_IMPACT_PATH_REJECTED')
    require(not any(re.search(r'(?i)(?:^|\.)env(?:\.|$)', p) for p in parts),
            'REPAIR_IMPACT_PATH_REJECTED')
    require(not name.lower().endswith(('.pem', '.key', '.p12', '.pfx', '.crt')),
            'REPAIR_IMPACT_PATH_REJECTED')
    require(documentation or not name.lower().endswith(('.md', '.rst', '.txt')),
            'REPAIR_IMPACT_DOCUMENT_REASON_REQUIRED')
    require(PurePosixPath(name).suffix.lower() in SOURCE_SUFFIXES or
            PurePosixPath(name).name.lower() in {'dockerfile', 'makefile', 'requirements.txt',
                                                'gemfile', 'cargo.lock'} or
            (documentation and PurePosixPath(name).suffix.lower() in {'.md', '.rst', '.txt'}),
            'REPAIR_IMPACT_PATH_REJECTED')
    return name


def source(value):
    require(isinstance(value, dict) and isinstance(value.get('kind'), str) and value['kind'] in SOURCE_KINDS)
    require(isinstance(value.get('task_ref'), str) and 0 < len(value['task_ref']) <= 4096)
    allowed = {'kind', 'task_ref', 'finding_id', 'origin_review_revision'}
    require(set(value) <= allowed)
    if value['kind'] == 'SCANNER_TASK_GROUP':
        require(set(value) <= {'kind', 'task_ref'})
    if value['kind'] == 'HOST_TASK_RISK':
        require(isinstance(value.get('finding_id'), str) and 0 < len(value['finding_id']) <= 160)
    if 'origin_review_revision' in value:
        require(type(value['origin_review_revision']) is int and value['origin_review_revision'] >= 1)
    return dict(value)


def proposal(value):
    require(isinstance(value, dict) and set(value) <= {'security_goal', 'summary', 'changes', 'preserve'})
    changes = value.get('changes')
    require(isinstance(changes, list) and 1 <= len(changes) <= 1024,
            'REPAIR_IMPACT_CAPACITY_REQUIRED')
    out = dict(security_goal=text(value.get('security_goal')), summary=text(value.get('summary')),
               changes=[], preserve=[])
    for change in changes:
        require(isinstance(change, dict) and set(change) == {'file_path', 'start_line', 'end_line', 'reason'})
        low, high = change['start_line'], change['end_line']
        require(type(low) is int and type(high) is int and 1 <= low <= high <= 2_147_483_647)
        reason = text(change['reason'], 240)
        out['changes'].append(dict(file_path=path(change['file_path'], documentation=bool(reason)),
                                   start_line=low, end_line=high, reason=reason))
    preserve = value.get('preserve', [])
    require(isinstance(preserve, list) and len(preserve) <= 10)
    out['preserve'] = [text(item, 200) for item in preserve]
    require(len(encoded(out)) <= 128_000, 'REPAIR_IMPACT_CAPACITY_REQUIRED')
    return out


def reasoning(impacts, unknowns, evidence):
    require(isinstance(impacts, list) and len(impacts) <= 20)
    require(isinstance(unknowns, list) and len(unknowns) <= 20)
    result, missing = [], []
    optional = {'affected_roles', 'affected_operations', 'affected_modules',
                'interfaces', 'alternatives', 'counterevidence'}
    for item in impacts:
        require(isinstance(item, dict) and set(item) <= {'kind', 'summary', 'evidence_refs'} | optional)
        require(isinstance(item.get('kind'), str) and item['kind'] in KINDS)
        refs = item.get('evidence_refs')
        require(isinstance(refs, list) and 1 <= len(refs) <= 12 and
                all(isinstance(ref, str) and ref in evidence for ref in refs),
                'REPAIR_IMPACT_EVIDENCE_INVALID')
        row = dict(kind=item['kind'], summary=text(item.get('summary')),
                   evidence_refs=list(dict.fromkeys(refs)))
        for field in optional & set(item):
            require(isinstance(item[field], list) and len(item[field]) <= 5)
            row[field] = [text(v, 240) for v in item[field]]
        result.append(row)
    for item in unknowns:
        require(isinstance(item, dict) and set(item) <= {'summary', 'critical', 'evidence_refs'})
        require(type(item.get('critical')) is bool)
        refs = item.get('evidence_refs', [])
        require(isinstance(refs, list) and len(refs) <= 12 and
                all(isinstance(ref, str) and ref in evidence for ref in refs),
                'REPAIR_IMPACT_EVIDENCE_INVALID')
        missing.append(dict(summary=text(item.get('summary')), critical=item['critical'],
                            evidence_refs=list(dict.fromkeys(refs))))
    require(len(encoded([result, missing])) <= 64_000)
    return result, missing


def merge(spans):
    out = []
    for low, high in sorted(spans):
        if out and low <= out[-1][1] + 1:
            out[-1][1] = max(high, out[-1][1])
        else:
            out.append([low, high])
    return out


def uncovered(low, high, spans):
    cursor, out = low, []
    for left, right in merge(spans):
        if right < cursor or left > high:
            continue
        if cursor < left:
            out.append([cursor, min(high, left - 1)])
        cursor = max(cursor, right + 1)
    if cursor <= high:
        out.append([cursor, high])
    return out
