"""Explicit downloads of the same filtered, redacted read model as the UI."""
import csv
import io
import json
from urllib.parse import quote


def render(result, format):
    if result.get('status') != 'AVAILABLE' or result.get('partial'):
        raise ValueError('EXPORT_SOURCE_INCOMPLETE')
    rows = result['risks']
    if format == 'json':
        return 'application/json', json.dumps(dict(schema='ai-security-risks-v1', **result), ensure_ascii=False).encode()
    if format == 'csv':
        output = io.StringIO(newline='')
        writer = csv.writer(output)
        fields = ('id','editor','project','workspace','session_id','check_id','title','severity','status',
                  'category','location','description','impact','advice','unknowns')
        writer.writerow(fields)
        for row in rows:
            values = [str(row.get(k, '')) for k in fields]
            writer.writerow(["'"+v if v.lstrip().startswith(('=', '+', '-', '@', '\t', '\r')) else v for v in values])
        return 'text/csv; charset=utf-8', ('\ufeff'+output.getvalue()).encode()
    if format != 'sarif':
        raise ValueError('EXPORT_FORMAT_INVALID')
    results = []
    for row in rows:
        value = dict(ruleId=row.get('rule_id') or row['category'],
            level={'严重':'error','高':'error','中':'warning','低':'note','信息':'note'}.get(row['severity'], 'warning'),
            message=dict(text=row['title']+'\n'+row['description']+'\n修复建议：'+row['advice']),
            partialFingerprints={'runtimeRiskId/v1':row['id']},
            properties={k:row.get(k) for k in ('editor','project_id','workspace_id','session_id','check_id','status','decision','scan_ids','management','source_freshness')})
        if row.get('file_path') and row.get('line_start'):
            value['locations'] = [dict(physicalLocation=dict(
                artifactLocation=dict(uri=quote(row['file_path'].replace('\\','/'), safe='/'), uriBaseId='%SRCROOT%'),
                region=dict(startLine=row['line_start'], endLine=row.get('line_end') or row['line_start'])))]
        results.append(value)
    sarif = dict(version='2.1.0', runs=[dict(tool=dict(driver=dict(name='AI Security Runtime')), results=results)])
    sarif['$schema'] = 'https://json.schemastore.org/sarif-2.1.0.json'
    return 'application/sarif+json', json.dumps(sarif, ensure_ascii=False).encode()
