"""On-demand, bounded workspace evidence. No source is written to scan storage."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat

from .finding_quality import relative_file
from .redactor import SecretRedactor

MAX_FILE_BYTES = 1_000_000
MAX_LINES = 80
MAX_CONTEXT_LINES = 20
MAX_LINE_CHARS = 600
MAX_EXCERPT_CHARS = 24_000


class EvidenceUnavailable(ValueError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def _relative(name):
    try:
        name = relative_file(name)
    except ValueError:
        raise EvidenceUnavailable('UNSAFE_PATH') from None
    # Also exclude Windows alternate streams, device paths and ambiguous names.
    if any(':' in part or '\0' in part or part.endswith((' ', '.')) for part in name.split('/')):
        raise EvidenceUnavailable('UNSAFE_PATH')
    return name


def _no_links(path):
    if any(p.is_symlink() or p.is_junction() for p in (path, *path.parents)):
        raise EvidenceUnavailable('LINK_NOT_ALLOWED')


def _revision(info):
    # Windows path stat exposes creation time while descriptor stat can expose
    # change time as ctime. They cannot be compared across those two APIs.
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns if os.name != 'nt' else None)


class WorkspaceReader:
    def __init__(self, workspace):
        self.root = Path(workspace).absolute()
        _no_links(self.root)
        self.root = self.root.resolve(strict=True)

    def read(self, name):
        """Check the opened inode before reading; recheck boundaries/revision after."""
        name = _relative(name)
        candidate = self.root / name
        _no_links(candidate)
        if not candidate.resolve(strict=True).is_relative_to(self.root):
            raise EvidenceUnavailable('WORKSPACE_ESCAPE')
        before = candidate.stat()
        if not stat.S_ISREG(before.st_mode):
            raise EvidenceUnavailable('NOT_REGULAR_FILE')
        if before.st_size > MAX_FILE_BYTES:
            raise EvidenceUnavailable('FILE_TOO_LARGE')
        flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
        with os.fdopen(os.open(candidate, flags), 'rb') as stream:
            _no_links(candidate)
            if (not candidate.resolve(strict=True).is_relative_to(self.root)
                    or _revision(os.fstat(stream.fileno())) != _revision(before)):
                raise EvidenceUnavailable('FILE_CHANGED_DURING_READ')
            raw = stream.read(MAX_FILE_BYTES + 1)
            after = os.fstat(stream.fileno())
        _no_links(candidate)
        if (not candidate.resolve(strict=True).is_relative_to(self.root)
                or _revision(before) != _revision(after)
                or _revision(after) != _revision(candidate.stat())):
            raise EvidenceUnavailable('FILE_CHANGED_DURING_READ')
        if len(raw) > MAX_FILE_BYTES:
            raise EvidenceUnavailable('FILE_TOO_LARGE')
        if any(byte < 32 and byte not in (9, 10, 12, 13) for byte in raw):
            raise EvidenceUnavailable('BINARY_FILE')
        try:
            text = raw.decode('utf-8-sig', errors='strict')
        except UnicodeDecodeError:
            raise EvidenceUnavailable('DECODE_FAILED_UTF8') from None
        return raw, text


def snapshot_fingerprint(workspace, name):
    """Auxiliary evidence failure never changes scanner success or findings."""
    try:
        raw, _ = WorkspaceReader(workspace).read(name)
        return dict(file_sha256=hashlib.sha256(raw).hexdigest(), reason=None)
    except (OSError, ValueError) as exc:
        return dict(file_sha256=None, reason=getattr(exc, 'reason', 'FILE_UNAVAILABLE'))


def safe_source(text, secret_ranges=()):
    """Scrub literals over the whole bounded file before selecting nearby lines.

    Preserve line counts, including multiline literals and private-key blocks;
    a context window cutting through such a block must not reveal its middle.
    """
    def mask(match):
        return '[REDACTED_LITERAL]' + '\n' * match.group(0).count('\n')
    text = re.sub(r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)', mask, text)
    text = re.sub(r'\x22\x22\x22[\s\S]*?(?:\x22\x22\x22|\Z)|\x27\x27\x27[\s\S]*?(?:\x27\x27\x27|\Z)', mask, text)
    text = re.sub(r'\x22(?:\\[\s\S]|[^\x22\\])*?(?:\x22|\Z)|\x27(?:\\[\s\S]|[^\x27\\])*?(?:\x27|\Z)|`[^`]*(?:`|\Z)', mask, text)
    # Per-line redaction preserves line numbering. Scrub even short unquoted
    # credential assignments and comments, not just scanner-identified secrets.
    lines = text.splitlines()
    for index, line in enumerate(lines, 1):
        if any(start <= index <= end for start, end in secret_ranges):
            lines[index-1] = '[REDACTED_SECRET]'
        else:
            line = re.sub(r'(?i)\b(?:password|passwd|token|api[_-]?key|secret)\s*[:=].*', '[REDACTED_SECRET]', line)
            line = SecretRedactor().redact(line)
            line = re.sub(r'\b[A-Za-z0-9+/=_-]{32,}\b', '[REDACTED_SECRET]', line)
            lines[index-1] = line[:MAX_LINE_CHARS]
    return lines


def evidence_locator(finding):
    stored = finding.get('technical_details', {}).get('evidence_locator', {})
    return dict(relative_path=_relative(finding['file_path']), start_line=finding['line_start'],
        end_line=finding.get('line_end', finding['line_start']),
        start_column=stored.get('start_column'), end_column=stored.get('end_column'),
        rule_id=finding.get('technical_details', {}).get('rule_id', ''),
        scanner=finding.get('scanner_sources', []), finding_fingerprint=finding.get('fingerprint'),
        scanner_fingerprint=stored.get('scanner_fingerprint'), file_sha256=stored.get('file_sha256'),
        snapshot_reason=stored.get('snapshot_reason'))


def scanner_evidence_metadata(extra, workspace):
    """Retain actual trace/metavariable structure, never persist matched source.

    Scanner-provided locations are data, not proof of path authorization. Text
    payloads are omitted; detail requests rehydrate only the finding's own file.
    """
    import json
    selected = {key: extra[key] for key in ('metavars', 'dataflow_trace') if key in extra}
    if len(json.dumps(selected).encode('utf-8')) > 16_000:
        return {'availability': 'SCANNER_METADATA_BUDGET_EXCEEDED'}
    def clean(value, key='', depth=0):
        if depth > 20:
            return '[DEPTH_LIMIT]'
        if isinstance(value, dict):
            return {k: clean(v, k, depth+1) for k, v in value.items()}
        if isinstance(value, list):
            return [clean(v, key, depth+1) for v in value]
        if isinstance(value, str):
            if key == 'path':
                path = Path(value)
                if path.is_absolute():
                    try:
                        value = path.resolve().relative_to(Path(workspace).resolve()).as_posix()
                    except ValueError:
                        return '[OUTSIDE_WORKSPACE]'
                try:
                    return _relative(value)
                except EvidenceUnavailable:
                    return '[UNSAFE_PATH]'
            return value if value in ('CliLoc', 'CliCall', 'CliVar') else '[OMITTED_SCANNER_TEXT]'
        return value
    return clean(selected)


class LocalEvidenceService:
    def __init__(self, scan):
        self.scan = scan
        self.secret_ranges = {}
        for finding in scan['findings']:
            if finding['category'] == 'secret':
                try:
                    name = _relative(finding['file_path'])
                except EvidenceUnavailable:
                    continue
                self.secret_ranges.setdefault(name, []).append((finding['line_start'], finding['line_end']))

    def detail(self, finding, context_lines=5):
        if type(context_lines) is not int or not 0 <= context_lines <= MAX_CONTEXT_LINES:
            raise ValueError('Context lines must be between 0 and 20')
        output = dict(evidence_status='UNAVAILABLE', reason=None, locator=None,
            original_evidence=None, current_context=None, trust='UNTRUSTED_CODE',
            redaction='Known secret ranges, credential patterns and all string literals')
        try:
            locator = evidence_locator(finding)
            output['locator'] = locator
            if finding['category'] == 'secret':
                output.update(reason='SECRET_REDACTED', original_evidence=dict(matched_code='[REDACTED_SECRET]'))
                return output  # Never read secret findings back into MCP evidence.
            raw, text = WorkspaceReader(self.scan['target_profile']['path']).read(locator['relative_path'])
            current_hash = hashlib.sha256(raw).hexdigest()
            expected = locator['file_sha256']
            status = 'UNAVAILABLE' if not expected else 'EXACT' if current_hash == expected else 'STALE'
            reason = 'SNAPSHOT_FINGERPRINT_MISSING' if not expected else 'FILE_CHANGED_SINCE_SCAN' if status == 'STALE' else None
            output.update(evidence_status=status, reason=reason, current_file_sha256=current_hash)
            lines = safe_source(text, self.secret_ranges.get(locator['relative_path'], []))
            start, end = locator['start_line'], locator['end_line']
            if type(start) is not int or type(end) is not int or not 1 <= start <= end <= len(lines):
                output.update(evidence_status='STALE' if status == 'STALE' else 'UNAVAILABLE', reason='LINE_RANGE_UNAVAILABLE')
                return output
            if end - start + 1 + 2 * context_lines > MAX_LINES:
                raise EvidenceUnavailable('LINE_BUDGET_EXCEEDED')
            low, high = max(1, start-context_lines), min(len(lines), end+context_lines)
            excerpt = dict(relative_path=locator['relative_path'], start_line=start, end_line=end,
                context_start_line=low, context_end_line=high,
                matched_code='\n'.join(lines[start-1:end]),
                context_before=lines[low-1:start-1], context_after=lines[end:high])
            if sum(len(line) for line in lines[low-1:high]) > MAX_EXCERPT_CHARS:
                raise EvidenceUnavailable('CONTEXT_BYTE_BUDGET_EXCEEDED')
            output['original_evidence' if status == 'EXACT' else 'current_context'] = excerpt
        except FileNotFoundError:
            output.update(evidence_status='MISSING', reason='FILE_MISSING')
        except (OSError, ValueError) as exc:
            output.update(evidence_status='UNAVAILABLE', reason=getattr(exc, 'reason', 'LOCAL_READ_FAILED'))
        return output


def attach_local_evidence(dataset, scan):
    """Derived presentation only: review observation hashes and stored scans stay intact."""
    service = LocalEvidenceService(scan)
    originals = {f['id']: f for f in scan['findings']}
    for row in dataset['findings']:
        row['local_evidence'] = service.detail(originals[row['scanner_finding_id']])
    return dataset
