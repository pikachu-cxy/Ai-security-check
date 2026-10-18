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

    def read(self, name, maximum=MAX_FILE_BYTES):
        """Check the opened inode before reading; recheck boundaries/revision after."""
        if type(maximum) is not int or not 1 <= maximum <= MAX_FILE_BYTES:
            raise ValueError('Invalid local read budget')
        name = _relative(name)
        candidate = self.root / name
        _no_links(candidate)
        if not candidate.resolve(strict=True).is_relative_to(self.root):
            raise EvidenceUnavailable('WORKSPACE_ESCAPE')
        before = candidate.stat()
        if not stat.S_ISREG(before.st_mode):
            raise EvidenceUnavailable('NOT_REGULAR_FILE')
        if before.st_size > maximum:
            raise EvidenceUnavailable('FILE_TOO_LARGE')
        flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
        with os.fdopen(os.open(candidate, flags), 'rb') as stream:
            _no_links(candidate)
            if (not candidate.resolve(strict=True).is_relative_to(self.root)
                    or _revision(os.fstat(stream.fileno())) != _revision(before)):
                raise EvidenceUnavailable('FILE_CHANGED_DURING_READ')
            raw = stream.read(maximum + 1)
            after = os.fstat(stream.fileno())
        _no_links(candidate)
        if (not candidate.resolve(strict=True).is_relative_to(self.root)
                or _revision(before) != _revision(after)
                or _revision(after) != _revision(candidate.stat())):
            raise EvidenceUnavailable('FILE_CHANGED_DURING_READ')
        if len(raw) > maximum:
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


PUBLIC_LITERALS = frozenset({'MD5', 'SHA-1', 'SHA-256', 'SHA-512', 'TLS', 'SSL',
    'HTTPS', 'http', 'https', 'UTF-8', 'UTF8', 'GET', 'POST', ''})

# One left-to-right scan gives an earlier comment or string ownership of all
# of its contents. Quotes in comments cannot open strings; comment markers in
# strings cannot hide their closing delimiter. Unterminated strings still own
# the rest of the file, so multiline secrets remain closed to evidence output.
_SOURCE_STRINGS = (
    r'\x22{3}(?:\\[\s\S]|(?!\x22{3})[\s\S])*(?:\x22{3}|\Z)'
    r'|\x27{3}(?:\\[\s\S]|(?!\x27{3})[\s\S])*(?:\x27{3}|\Z)'
    r'|\x22(?:\\[\s\S]|[^\x22\\])*(?:\x22|\Z)'
    r'|\x27(?:\\[\s\S]|[^\x27\\])*(?:\x27|\Z)'
    r'|`(?:\\[\s\S]|[^`\\])*(?:`|\Z)')
_OTHER_COMMENTS = r'//[^\r\n]*|/\*[\s\S]*?(?:\*/|\Z)'
_SOURCE_TOKENS = re.compile(r'(?P<comment>\#(?=[ \t\r\n]|\Z)[^\r\n]*|'
    + _OTHER_COMMENTS + ')|(?:' + _SOURCE_STRINGS + ')')
_HASH_SOURCE_TOKENS = re.compile(r'(?P<comment>\#[^\r\n]*|'
    + _OTHER_COMMENTS + ')|(?:' + _SOURCE_STRINGS + ')')
_HASH_COMMENT_SUFFIXES = frozenset({'.py', '.pyi', '.toml', '.yaml', '.yml',
    '.sh', '.bash', '.zsh', '.ps1', '.psm1', '.rb', '.r', '.pl', '.ini', '.conf'})
_EMPTY_LITERALS = frozenset({'""', "''", '``', '""""""', "''''''"})
# Only an entire safe value may bypass credential masking. Matching the safe
# alternative consumes just that value, so a later assignment on the same line
# is still checked. Unknown expressions retain the conservative tail mask.
_SAFE_CREDENTIAL_VALUE = (
    r'(?:\[REDACTED_(?:LITERAL|SECRET|COMMENT)\]|\x22{6}|\x27{6}|\x22{2}|\x27{2}|`{2})'
    r'(?=[ \t]*(?:$|[;,)}\]]|\[REDACTED_COMMENT\][ \t]*$))')
_SHORT_CREDENTIAL_ASSIGNMENTS = re.compile(
    r'(?i)\b(?:password|passwd|token|api[_-]?key|secret)[ \t]*[:=][ \t]*'
    r'(?:(?P<safe>' + _SAFE_CREDENTIAL_VALUE + r')|[^\r\n]*)')


def safe_source(text, secret_ranges=(), source_path=None, *, truncation_lines=None):
    """Scrub literals over the whole bounded file before selecting nearby lines.

    Preserve line counts, including multiline literals and private-key blocks;
    a context window cutting through such a block must not reveal its middle.
    """
    def mask(match):
        value = match.group(0)
        if match.lastgroup != 'comment' and value in _EMPTY_LITERALS:
            return value
        public_api = re.search(r'\b(?:MessageDigest|SSLContext)\.getInstance\(\s*$', text[max(0,match.start()-80):match.start()])
        if (public_api and value[:1] in ('"', "'") and value[-1:] == value[:1]
                and value[1:-1] in PUBLIC_LITERALS):
            return value
        marker = '[REDACTED_COMMENT]' if match.lastgroup == 'comment' else '[REDACTED_LITERAL]'
        # Keep every physical line, including a closing delimiter at EOF and
        # CR-only files. A newline-only replacement could lose the final line.
        return re.sub(r'[^\r\n\v\f\x1c-\x1e\x85\u2028\u2029]+', marker, value)
    text = re.sub(r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)', mask, text)
    path = Path(source_path) if source_path is not None else None
    tokens = (_HASH_SOURCE_TOKENS if path is not None and
        (path.suffix.lower() in _HASH_COMMENT_SUFFIXES or path.name.lower() == 'dockerfile')
        else _SOURCE_TOKENS)
    text = tokens.sub(mask, text)
    # Per-line redaction preserves line numbering. Scrub even short unquoted
    # credential assignments and comments, not just scanner-identified secrets.
    lines = text.splitlines()
    for index, line in enumerate(lines, 1):
        if any(start <= index <= end for start, end in secret_ranges):
            lines[index-1] = '[REDACTED_SECRET]'
        else:
            line = _SHORT_CREDENTIAL_ASSIGNMENTS.sub(
                lambda match: match.group(0) if match.group('safe') else '[REDACTED_SECRET]', line)
            line = SecretRedactor().redact(line)
            line = re.sub(r'\b[A-Za-z0-9+/=_-]{32,}\b', '[REDACTED_SECRET]', line)
            if truncation_lines is not None and len(line) > MAX_LINE_CHARS:
                truncation_lines.append(index)
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
            redaction='Known secret ranges, credential patterns and literals except fixed public constants')
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
            lines = safe_source(text, self.secret_ranges.get(locator['relative_path'], []),
                source_path=locator['relative_path'])
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
