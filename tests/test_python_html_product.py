"""Response proof is applied only by the bundled product rule path."""
from dataclasses import replace
import json

from security_runtime.findings import FindingNormalizer
from security_runtime.models import ScanContext, ScanMode
from security_runtime.processes import ProcessResult
from test_scanner_hot_path import engine  # noqa: F401


def test_builtin_html_proof_keeps_tainted_branch_and_custom_rules(engine, monkeypatch):
    root, _, pack, adapter, _, _ = engine
    text = '''from flask import request
@app.route('/')
def route():
    value=request.form.get('value')
    number=86
    if 7*42-number>200:
        response='fixed'
    else:
        response=value
    return f'<p>{response}</p>'
'''
    file = root/'app.py'
    file.write_text(text, encoding='utf-8')
    raw = {'check_id': 'ai-security.python.flask-html-response', 'path': 'app.py',
           'start': {'line': 10}, 'end': {'line': 10},
           'extra': {'message': 'HTML response', 'severity': 'ERROR', 'metadata': {'category': 'xss'}}}

    def execute(*_args):
        return ProcessResult(0, json.dumps({'results': [raw], 'paths': {'scanned': ['app.py']}, 'errors': []}), '', 1)

    monkeypatch.setattr('security_runtime.scanners._execute', execute)
    context = ScanContext(str(root), ScanMode.RELEASE, ('app.py',))
    found, run = adapter.scan(context, FindingNormalizer(root))
    assert run.status == 'SUCCESS' and not found
    assert run.scanner_diagnostics['constant_proof']['suppressed_count'] == 1

    # A user's rule with the same identifier retains the original raw finding.
    found, run = adapter.scan(replace(context, rules_path=str(pack)), FindingNormalizer(root))
    assert len(found) == 1 and run.scanner_diagnostics['constant_proof']['suppressed_count'] == 0

    for changed in ('number=106', 'number=request.form.get("number")'):
        file.write_text(text.replace('number=86', changed), encoding='utf-8')
        found, run = adapter.scan(context, FindingNormalizer(root))
        assert len(found) == 1 and run.scanner_diagnostics['constant_proof']['suppressed_count'] == 0


def test_annotation_only_statement_does_not_abort_product_findings(engine, monkeypatch):
    root, _, _, adapter, _, _ = engine
    (root/'app.py').write_text('''from flask import request
@app.route('/')
def route():
    value: str
    value=request.args.get('value')
    return f'<p>{value}</p>'
''', encoding='utf-8')
    raw = {'check_id': 'ai-security.python.flask-html-response', 'path': 'app.py',
           'start': {'line': 6}, 'end': {'line': 6},
           'extra': {'message': 'HTML response', 'severity': 'ERROR', 'metadata': {'category': 'xss'}}}
    monkeypatch.setattr('security_runtime.scanners._execute', lambda *_args:
                        ProcessResult(0, json.dumps({'results': [raw], 'paths': {'scanned': ['app.py']}, 'errors': []}), '', 1))
    found, run = adapter.scan(ScanContext(str(root), ScanMode.RELEASE, ('app.py',)), FindingNormalizer(root))
    assert run.status == 'SUCCESS' and len(found) == 1
    assert run.scanner_diagnostics['constant_proof']['suppressed_count'] == 0
