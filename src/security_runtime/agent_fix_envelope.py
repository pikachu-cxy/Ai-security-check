"""Exact, source-free byte contracts for the one authorized TLS statement.

Only signed, pre-enumerated results are accepted. No normalization, editor,
scanner, source persistence or semantic matching is implemented here.
"""
from __future__ import annotations

from .fast_fix import sha

VERSION = 'tls-remove-envelope-v1'


def byte_modes(content):
    crlf = content.count(b'\r\n')
    lf = content.count(b'\n') - crlf
    cr = content.count(b'\r') - crlf
    mode = 'MIXED' if sum(n > 0 for n in (crlf, lf, cr)) > 1 else (
        'CRLF' if crlf else 'LF' if lf else 'CR' if cr else 'NONE')
    bom = next((name for marker, name in ((b'\xef\xbb\xbf','UTF8_BOM'), (b'\xff\xfe\0\0','UTF32_LE'),
        (b'\0\0\xfe\xff','UTF32_BE'), (b'\xff\xfe','UTF16_LE'), (b'\xfe\xff','UTF16_BE'))
        if content.startswith(marker)), 'NONE')
    try:
        content.decode('utf-8')
        encoding = 'UTF8'
    except UnicodeDecodeError:
        encoding = 'INVALID_UTF8'
    return {'line_ending_mode': mode, 'bom_mode': bom, 'encoding_mode': encoding}


def build_envelope(content, edit):
    """Corroborated original removal range; use only this exact raw pre-image."""
    left, end = edit['byte_range']['start'], edit['byte_range']['end']
    if (type(left) is not int or type(end) is not int or not 0 <= left < end <= len(content)
            or sha(content) != edit['expected_file_sha256']
            or sha(content[left:end]) != edit['expected_segment_sha256']
            or sha(content[:left] + content[end:]) != edit['expected_result_sha256']):
        raise ValueError('INLINE_PREPARATION_STALE')
    line = content[left:end]
    eol = b'\r\n' if line.endswith(b'\r\n') else b'\n' if line.endswith(b'\n') else b''
    body = line[:-len(eol)] if eol else line
    text = body.decode('utf-8')  # No universal-newline or BOM conversion.
    statement = text.strip().encode('utf-8')
    leading = text[:len(text) - len(text.lstrip())].encode('utf-8')
    trailing = body[len(leading) + len(statement):]
    if not statement or b'\r' in body or b'\n' in body:
        raise ValueError('INLINE_PREPARATION_STALE')
    # One truly empty following physical line, never comments/code/indentation.
    blank = b'\r\n' if eol and content[end:end+2] == b'\r\n' else (
        b'\n' if eol and content[end:end+1] == b'\n' else b'')
    right = end + len(blank)
    prefix, suffix = content[:left], content[right:]
    results = [('REMOVE_LINE', blank), ('REMOVE_STATEMENT', leading + trailing + eol + blank)]
    if blank:
        results.append(('REMOVE_LINE_AND_EMPTY_LINE', b''))
    seen, variants = set(), []
    for name, segment in results:
        if segment in seen:
            continue
        seen.add(segment)
        variants.append({'id': name, 'length': len(segment), 'sha256': sha(segment),
                         'result_sha256': sha(prefix + segment + suffix)})
    modes = byte_modes(content)
    return {'version': VERSION, 'operation': 'REMOVE_AUTHORIZED_STATEMENT',
            'byte_range': {'start': left, 'end': right, 'unit': 'UTF8_BYTES_END_EXCLUSIVE'},
            'statement_byte_range': {'start': left + len(leading), 'end': left + len(leading) + len(statement)},
            'expected_segment_sha256': sha(content[left:right]),
            'expected_statement_sha256': sha(statement), 'original_size_bytes': len(content),
            'prefix_sha256': sha(prefix), 'suffix_sha256': sha(suffix),
            'line_ending_mode': modes['line_ending_mode'], 'bom_mode': modes['bom_mode'],
            'following_empty_line_bytes': len(blank), 'variants': variants}


def verify_envelope(content, envelope, *, original_sha256, canonical_result_sha256):
    """No source/byte diff leaves this function. Caller validates ticket signature."""
    actual_sha = sha(content)
    modes = byte_modes(content)
    left, right = envelope['byte_range']['start'], envelope['byte_range']['end']
    suffix_length = envelope['original_size_bytes'] - right
    room = len(content) >= left + suffix_length
    suffix_at = len(content) - suffix_length
    prefix_ok = room and sha(content[:left]) == envelope['prefix_sha256']
    suffix_ok = room and sha(content[suffix_at:]) == envelope['suffix_sha256']
    outside = not (prefix_ok and suffix_ok)
    segment = content[left:suffix_at] if room else b''
    diagnostics = {'version': VERSION, 'status': 'REJECTED', 'subreason': None,
        'expected_preimage_sha256': original_sha256, 'actual_current_sha256': actual_sha,
        'expected_canonical_result_sha256': canonical_result_sha256,
        'expected_range_length': right - left,
        'actual_result_range_length': len(segment) if room else None,
        'actual_deleted_bytes': envelope['original_size_bytes'] - len(content),
        'outside_envelope_changed': outside, 'prefix_preserved': bool(prefix_ok), 'suffix_preserved': bool(suffix_ok),
        'expected_line_ending_mode': envelope['line_ending_mode'], 'actual_line_ending_mode': modes['line_ending_mode'],
        'expected_bom_mode': envelope['bom_mode'], 'actual_bom_mode': modes['bom_mode'],
        'actual_encoding_mode': modes['encoding_mode'],
        'accepted_variant': None, 'source_persisted': False}
    if envelope['variants'][0]['result_sha256'] != canonical_result_sha256:
        reason = 'RESULT_HASH_MISMATCH'
    elif modes['encoding_mode'] != 'UTF8':
        reason = 'ENCODING_IDENTITY_MISMATCH'
    elif outside:
        reason = ('ENCODING_IDENTITY_MISMATCH' if modes['bom_mode'] != envelope['bom_mode'] else
                  'LINE_ENDING_IDENTITY_MISMATCH' if modes['line_ending_mode'] != 'NONE' and modes['line_ending_mode'] != envelope['line_ending_mode'] else
                  'TARGET_RANGE_DRIFT' if not room else
                  'OUTSIDE_EDIT_ENVELOPE_CHANGED')
    elif actual_sha == original_sha256:
        reason = 'TARGET_PREIMAGE_NOT_REMOVED'
    else:
        variant = next((v for v in envelope['variants'] if len(segment) == v['length'] and sha(segment) == v['sha256']), None)
        if variant is None:
            reason = 'TARGET_RESULT_MISMATCH'
        elif actual_sha != variant['result_sha256']:
            reason = 'RESULT_HASH_MISMATCH'
        else:
            diagnostics.update(status='MATCHED', accepted_variant=variant['id'])
            return diagnostics
    diagnostics['subreason'] = reason
    return diagnostics
