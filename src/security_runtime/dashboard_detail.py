"""On-demand code for an existing signed risk; never creates evidence or scans."""
from contextlib import closing
from pathlib import Path
import ast
import hashlib
import re

from .dashboard_records import locate
from .risk_management import revision
from .local_evidence import WorkspaceReader, _relative, safe_source
from .redactor import SecretRedactor


def code_lines(text, start, risk_start, risk_end, *, secret=False):
    redact = SecretRedactor().redact
    result, used = [], 0
    for index, raw in enumerate(text.splitlines()[:80], start):
        # Historical scanner text and current code receive the same display policy.
        value = redact(raw)
        value = re.sub(r'(?i)\b(?:password|passwd|token|api[_-]?key|secret)\s*[:=].*',
                       '[REDACTED_SECRET]', value)
        if secret and risk_start <= index <= risk_end:
            value = '[REDACTED_SECRET]'
        if used + len(value[:600]) > 24000:
            break
        result.append(dict(number=index, text=value[:600], truncated=len(value) > 600,
                           highlight=risk_start <= index <= risk_end))
        used += len(value[:600])
    return result


def detail(identifier, expected_revision, *, context=5, catalog=None):
    if type(context) is not int or not 0 <= context <= 20:
        raise ValueError('DETAIL_CONTEXT_INVALID')
    if catalog:
        from .dashboard_entities import VISIBLE
        with closing(catalog.connect()) as db:
            if not db.execute('SELECT 1 FROM risks WHERE id=? AND '+VISIBLE, (identifier,)).fetchone():
                raise ValueError('DETAIL_NOT_VISIBLE')
    _, row, rid = locate(identifier)
    risk = row['risks'][rid]
    if revision(risk) != expected_revision:
        raise ValueError('DETAIL_VERSION_CONFLICT')
    finding = risk['finding']
    name = _relative(finding['file_path'])
    first, last = finding['line_start'], finding['line_end']
    if type(first) is not int or type(last) is not int or not 1 <= first <= last:
        raise ValueError('DETAIL_LOCATION_INVALID')
    secret = any(w in str(finding.get('category', '')).lower() for w in ('secret', 'credential'))
    originals = [o['finding'] for o in risk.get('observations', []) if o.get('source') == 'SCANNER'
                 and o['finding'].get('file_path') == name and o['finding'].get('line_start') == first]
    original = originals[-1] if originals else None
    historical = None
    if original and original.get('evidence'):
        snippet = '\n'.join(safe_source(original['evidence'], source_path=name,
                                        redaction_version=2, max_line_chars=None))
        # Only assign line numbers when the saved scanner range actually fits.
        if len(snippet.splitlines()) == original['line_end'] - original['line_start'] + 1:
            historical = dict(label='历史扫描代码（未重新核验）',
                lines=code_lines(snippet, first, first, last, secret=secret))
            historical['truncated'] = len(historical['lines']) < len(snippet.splitlines())
    result = dict(file_path=name, absolute_path=str(Path(row['workspace']) / name),
                  line_start=first, line_end=last, function=None, historical=historical,
                  current=None, scanner_run=False, source_modified=False)
    try:
        raw, source = WorkspaceReader(row['workspace']).read(name)
        expected = (risk.get('assessment') or {}).get('source_hashes', {}).get(name)
        if not expected and original:
            expected = original.get('technical_details', {}).get('evidence_locator', {}).get('file_sha256')
        matches = bool(expected and hashlib.sha256(raw).hexdigest() == expected)
        # Scrub the whole bounded file before slicing so windows inside a
        # multiline credential cannot expose its middle. Reuse source policy 2.
        lines = safe_source(source, source_path=name, redaction_version=2, max_line_chars=None)
        start = max(1, first - context)
        end = min(len(lines), last + context, start + 79)
        current = dict(label='当前代码（与记录版本一致）' if matches else
                       '文件已变化，以下为当前代码' if expected else '当前代码（缺少历史摘要，版本未核验）',
                       matches_record=matches, lines=code_lines('\n'.join(lines[start-1:end]), start,
                       first, last, secret=secret), truncated=end < min(len(lines), last + context))
        current['truncated'] = current['truncated'] or len(current['lines']) < max(0, end-start+1)
        if first > len(lines):
            current['label'] = '当前文件已变化，原风险行号不再存在'
        if name.endswith('.py') and matches:
            try:
                functions = [n for n in ast.walk(ast.parse(source)) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                             and n.lineno <= first <= (n.end_lineno or n.lineno)]
                if functions:
                    result['function'] = max(functions, key=lambda n:n.lineno).name
            except (SyntaxError, RecursionError):
                pass
        result['current'] = current
    except (OSError, ValueError):
        result['unavailable'] = '当前文件不可读取；保留已保存的位置和报告。'
    if historical is None:
        result['history_note'] = '未保存可定位的历史代码片段。'
    return result
