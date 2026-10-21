"""Private sparse semantic fingerprints; never model-readable source evidence.

Only the shared sanitizer's hidden semantic lines are keyed. Comments use the
same tokenizer as source delivery, so a comment marker inside a string remains
part of that string. Neither raw source nor this private comparison proof may be
placed in task control records, review plans or MCP responses.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
import re

from .local_evidence import (MAX_LINE_CHARS, _HASH_COMMENT_SUFFIXES,
                             _HASH_SOURCE_TOKENS, _SOURCE_TOKENS, safe_source)
from .source_redaction import VERSION

CONTRACT = 'task-preimage-semantics-v1'
MAX_FILE_PROOF_BYTES = 2_000_000
MAX_TASK_PROOF_BYTES = 8_000_000
MAX_WORKSPACE_PROOF_BYTES = 16_000_000
ROW_FRAMING_BYTES = 256
_SEPARATORS = r'[^\r\n\v\f\x1c-\x1e\x85\u2028\u2029]+'
_PRIVATE_KEY = r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)'
_DIRECTIVE = re.compile(
    r'^[\t ]*(?:(?:/{1,3}|/\*+|\*+|#+)[\t ]*)*(?:'
    r'!|(?:-\*-\s*)?coding\s*[:=]|noqa\b|nosec\b|nosemgrep\b|gitleaks\b|'
    r'pragma\b|type\s*:\s*ignore\b|@ts[-:]|<reference\b|'
    r'go\s*:\s*(?:build|generate|embed|linkname|noescape|nosplit|norace|uintptrescapes)\b|\+build\b|'
    r'(?:eslint|tslint|pylint|ruff|flake8|shellcheck|prettier|istanbul|coverage|c8)\b|'
    r'webpack\w*\s*:|(?:@|#)__PURE__\b|@(?:vite|rollup|jsx|jsxImportSource|jsxRuntime)\b|'
    r'@(?:type|typedef|satisfies|implements|extends|this|param|return|returns|template|import)\b|'
    r'[@#]?\s*source(?:Mapping)?URL\s*=)', re.IGNORECASE | re.MULTILINE)
_JS_SUFFIXES = frozenset({'.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.mts', '.cts'})
_REGEX_PREFIX = re.compile(r'(?:^|[=(:,!&|?;{}\[]|\b(?:return|throw|case|yield))\s*/(?:\\.|[^/\r\n])*$')


def _semantic_comment(match, text, source_path):
    if _DIRECTIVE.search(match.group(0)):
        return True
    if source_path.suffix.lower() not in _JS_SUFFIXES:
        return False
    # The shared sanitizer intentionally has no JavaScript parser. A // or /*
    # token inside an apparent open regex/character class is uncertain source,
    # not proof that the rest of that physical line is an inert comment.
    start = max(text.rfind('\n', 0, match.start()), text.rfind('\r', 0, match.start())) + 1
    return _REGEX_PREFIX.search(text[start:match.start()]) is not None


def incomplete(line_count):
    return dict(version=1, complete=False, line_count=line_count, semantic_lines={})


def opaque_semantic_lines(lines, truncation_lines=()):
    """Conservative classification when an older snapshot has no private proof."""
    truncated = set(truncation_lines)
    return {number for number, line in enumerate(lines, 1)
            if number in truncated or len(line) >= MAX_LINE_CHARS
            or '[REDACTED_LITERAL]' in line or '[REDACTED_SECRET]' in line
            or '[REDACTED_COMMENT]' in line}


def make_proof(key, workspace_id, task_ref, path, raw_bytes, *, sanitized_lines=None, redaction_version=VERSION):
    text = raw_bytes.decode('utf-8-sig', errors='strict')
    original_lines = (safe_source(text, source_path=path, redaction_version=redaction_version,
                                  max_line_chars=None)
                      if sanitized_lines is None else sanitized_lines)
    source_path = Path(path)
    tokens = (_HASH_SOURCE_TOKENS if source_path.suffix.lower() in _HASH_COMMENT_SUFFIXES
              or source_path.name.lower() == 'dockerfile' else _SOURCE_TOKENS)
    # safe_source treats private-key blocks before its ordinary tokenizer.
    # Preserve that ownership here too, including a base64 line containing //.
    semantic_tokens = re.compile('(?:' + _PRIVATE_KEY + ')|' + tokens.pattern)
    semantic_text = semantic_tokens.sub(lambda match: re.sub(_SEPARATORS, ' ', match.group(0))
        if match.lastgroup == 'comment' and not _semantic_comment(match, text, source_path)
        else match.group(0), text)
    private_lines = semantic_text.splitlines()
    sanitized = original_lines if semantic_text == text else safe_source(semantic_text,
        source_path=path, redaction_version=redaction_version, max_line_chars=None)
    if len(private_lines) != len(original_lines) or len(sanitized) != len(original_lines):
        return incomplete(len(original_lines))
    domain = json.dumps([CONTRACT, workspace_id, task_ref, path],
                        ensure_ascii=True, separators=(',', ':')).encode('utf-8')
    derived = hmac.new(key, domain, hashlib.sha256).digest()
    fingerprints, size = {}, 128
    for number, (private, public) in enumerate(zip(private_lines, sanitized), 1):
        if private == public:
            continue
        # No line number or file hash in this MAC: identical hidden semantic
        # lines can align after insertion. The private row envelope separately
        # binds this exact raw file hash and its immutable source reference.
        fingerprints[number] = hmac.new(derived, private.encode('utf-8'), hashlib.sha256).hexdigest()
        size += len(str(number)) + 70
        if size > MAX_FILE_PROOF_BYTES:
            return incomplete(len(original_lines))
    return dict(version=1, complete=True, line_count=len(original_lines), semantic_lines=fingerprints)


def encode_proof(proof):
    return json.dumps(proof, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode('ascii')


def decode_proof(body, expected_count):
    proof = json.loads(body)
    if (not isinstance(proof, dict) or set(proof) != {'version', 'complete', 'line_count', 'semantic_lines'}
            or type(proof['version']) is not int or proof['version'] != 1
            or type(proof['complete']) is not bool or type(proof['line_count']) is not int
            or proof['line_count'] != expected_count or not isinstance(proof['semantic_lines'], dict)):
        raise ValueError('Invalid private semantic proof')
    converted = {}
    for number, fingerprint in proof['semantic_lines'].items():
        if (not isinstance(number, str) or not number.isascii() or not number.isdecimal()
                or str(int(number)) != number or not 1 <= int(number) <= expected_count
                or not isinstance(fingerprint, str) or re.fullmatch(r'[a-f0-9]{64}', fingerprint) is None):
            raise ValueError('Invalid private semantic line binding')
        converted[int(number)] = fingerprint
    if not proof['complete'] and converted:
        raise ValueError('Incomplete private proof cannot claim semantic lines')
    proof['semantic_lines'] = converted
    return proof
