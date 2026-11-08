"""Conservative cross-source linking from already validated source evidence."""
import ast
import re


def sql_category(value):
    return re.sub('[^a-z]', '', value.lower()) in {'sqlinjection', 'sqlinjectionrisk'}


def confirmed_sql_target(check, row, value, evidence):
    # This narrow rule only joins two current confirmations at one unambiguous
    # Python SQL execution sink. Other categories/ambiguous locations stay separate.
    if value.decision != 'CONFIRMED' or not sql_category(value.category) or not value.file_path.endswith('.py'):
        return None
    source = next((e for e in evidence if e['file_path'] == value.file_path and '_source' in e), None)
    if source is None:
        return None
    lines = source['_source'].splitlines()
    if value.line_end > len(lines) or len(lines[value.line_end-1]) > 8000:
        return None
    try:
        tree = ast.parse(lines[value.line_end-1].strip())
    except (SyntaxError, ValueError, RecursionError):
        return None
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
    if len(calls) != 1 or not isinstance(calls[0].func, ast.Attribute) or calls[0].func.attr not in {'execute', 'executemany'}:
        return None
    matches = []
    for risk in row['risks'].values():
        finding, assessment = risk['finding'], risk.get('assessment') or {}
        if (assessment.get('decision') == 'CONFIRMED' and not assessment.get('stream_batch_id')
                and assessment.get('dirty_seq') == check['dirty_seq']
                and assessment.get('scan_id') == check.get('scan_id')
                and finding['file_path'] == value.file_path and sql_category(finding['category'])
                and finding['line_start'] == finding['line_end'] == value.line_end
                and assessment.get('source_hashes', {}).get(value.file_path) == source['sha256']
                and any(o.get('source') == 'SCANNER' and o.get('scan_id') == check.get('scan_id')
                        for o in risk['observations'])):
            matches.append(risk['id'])
    return matches[0] if len(matches) == 1 else None
