"""Authored independent call-chain examples; target code is never imported or run."""
from dataclasses import replace
from pathlib import Path

import pytest

from security_runtime.dataflow import BoundedDataflowScanner
from security_runtime.findings import FindingNormalizer
from security_runtime.findings import deduplicate
from security_runtime.flow_core import Analysis, Limit
from security_runtime.models import ScanContext, ScanMode


def scan(root, files, targets=None, *, experimental=False):
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
    context = ScanContext(str(root), ScanMode.RELEASE, tuple(targets or files))
    return BoundedDataflowScanner(experimental=experimental).scan(context, FindingNormalizer(root))


PY_ROUTE = '''from flask import request
import sqlite3
from helpers import transform, send
def route():
    value = transform(request.args.get('term'))
    send(sqlite3.connect(':memory:').cursor(), value)
'''
PY_HELPERS = '''def transform(value):
    return 'SELECT * FROM things WHERE name = ' + value
def send(db, sql):
    db.execute(sql)
'''
JAVA_ROUTE = '''import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
class Entry {
  void handle(HttpServletRequest req, Connection con) {
    String query = Helper.transform(req.getParameter("term"));
    Helper.send(con, query);
  }
}'''
JAVA_HELPERS = '''import java.sql.Connection;
class Helper {
  static String transform(String value) { return "select * from things where name = " + value; }
  static void send(Connection con, String query) { con.prepareStatement(query); }
}'''


@pytest.mark.parametrize('files,target', [
    ({'route.py': PY_ROUTE, 'helpers.py': PY_HELPERS}, 'route.py'),
    ({'Entry.java': JAVA_ROUTE, 'Helper.java': JAVA_HELPERS}, 'Entry.java')])
def test_cross_file_argument_return_and_sink_have_bound_evidence(tmp_path, files, target):
    findings, run = scan(tmp_path, files, [target])
    assert run.status == 'SUCCESS'
    assert len(findings) == 1 and findings[0].category == 'sql-injection'
    details = findings[0].technical_details
    assert {s['kind'] for s in details['dataflow_trace']} == {'SOURCE', 'RESOLVED_CALL', 'SINK'}
    assert {s['file'] for s in details['dataflow_trace']} == set(files)
    assert details['context_hashes'].keys() == files.keys()
    assert details['verification_scope_complete'] is False
    assert run.coverage_contract == 'PARTIAL'
    assert findings[0].file_path == target


@pytest.mark.parametrize('safe', ['return "SELECT 1"', 'return unknown(value)'])
def test_constant_return_and_unresolved_call_do_not_taint_python(tmp_path, safe):
    found, _ = scan(tmp_path, {'route.py': PY_ROUTE, 'helpers.py': PY_HELPERS.replace(
        "return 'SELECT * FROM things WHERE name = ' + value", safe)}, ['route.py'])
    assert not found


def test_constant_return_does_not_taint_java(tmp_path):
    found, _ = scan(tmp_path, {'Entry.java': JAVA_ROUTE, 'Helper.java': JAVA_HELPERS.replace(
        'return "select * from things where name = " + value;', 'return "SELECT 1";')}, ['Entry.java'])
    assert not found


def test_parameterized_query_and_no_shell_are_negative(tmp_path):
    found, _ = scan(tmp_path, {'route.py': '''from flask import request
import sqlite3, subprocess
def route():
    term = request.form.get('q')
    sqlite3.connect(':memory:').cursor().execute('SELECT * FROM things WHERE name = ?', (term,))
    subprocess.run(['echo', term], shell=False)
'''})
    assert not found


@pytest.mark.parametrize('suffix,source', [('.py', '''from flask import request
from helper import wrap
def route():
    open(wrap(request.headers.get('filename')))
'''), ('.java', '''import javax.servlet.http.HttpServletRequest;
class Entry { void route(HttpServletRequest req) { new java.io.FileReader(Helper.wrap(req.getParameter("name"))); } }
''')])
def test_path_cross_file_positive(tmp_path, suffix, source):
    helper = 'def wrap(value):\n    return "data/" + value\n' if suffix == '.py' else 'class Helper { static String wrap(String s) { return "data/" + s; } }'
    entry = 'entry.py' if suffix == '.py' else 'Entry.java'
    files = {entry: source, 'helper.py' if suffix == '.py' else 'Helper.java': helper}
    found, _ = scan(tmp_path, files, [entry], experimental=True)
    assert [f.category for f in found] == ['path-traversal']


def test_python_instance_field_wrapper_and_shell(tmp_path):
    found, _ = scan(tmp_path, {'entry.py': '''from flask import request
from helper import Box
import subprocess
def route():
    box = Box(request)
    subprocess.run('echo ' + box.value(), shell=True)
''', 'helper.py': '''class Box:
    def __init__(self, source):
        self.source = source
    def value(self):
        return self.source.cookies.get('name')
'''}, ['entry.py'], experimental=True)
    assert [f.category for f in found] == ['command-injection']


def test_local_shadow_and_parameter_names_are_not_sdk_proof(tmp_path):
    found, _ = scan(tmp_path, {'entry.py': '''from flask import request
class Safe:
    def get(self, key): return 'ok'
def route(request):
    open(request.args.get('filename'))
''', 'Entry.java': '''class HttpServletRequest { String getParameter(String n) { return "ok"; } }
class Entry { void route(HttpServletRequest req) { new java.io.FileReader(req.getParameter("name")); } }
'''})
    assert not found


def test_overloaded_java_method_is_unknown(tmp_path):
    found, run = scan(tmp_path, {'Entry.java': JAVA_ROUTE, 'Helper.java': JAVA_HELPERS.replace(
        'static String transform(String value)', 'static String transform(Object value) { return "SELECT 1"; }\n static String transform(String value)')}, ['Entry.java'])
    assert not found
    assert any(g['reason'] == 'CALL_UNRESOLVED_OR_OVERLOADED' for g in run.scanner_diagnostics['context_gaps'])


@pytest.mark.parametrize('name,text', [('bad.py', 'def :'), ('Bad.java', 'record Bad(int value) {}')])
def test_parse_failure_is_partial(tmp_path, name, text):
    found, run = scan(tmp_path, {name: text})
    assert not found and run.status == 'PARTIAL'
    assert run.rule_coverage['failed_files'] == [name]


def test_quick_hook_does_not_enable_additional_analysis(tmp_path):
    context = ScanContext(str(tmp_path), ScanMode.QUICK, ('entry.py',))
    assert not BoundedDataflowScanner().supports(None, context)
    assert BoundedDataflowScanner().supports(None, replace(context, mode=ScanMode.FEATURE))


def test_default_policy_keeps_intraprocedural_path_candidate_experimental(tmp_path):
    found, run = scan(tmp_path, {'entry.py': '''from flask import request
def route():
    open(request.args.get('name'))
'''})
    assert not found
    assert run.rule_coverage['per_language']['python']['available_rules'] == 3
    assert run.rule_coverage['per_language']['python']['selected_rules'] == 2
    assert run.rule_coverage['experimental_disabled_categories'] == ['command-injection']
    assert run.rule_coverage['python_path_scope'] == 'RESOLVED_CROSS_FILE_CALLS_OR_IO_CODECS_OPEN'


@pytest.mark.parametrize('safe', [False, True])
def test_python_relative_import_keyword_only_path_flow(tmp_path, safe):
    found, run = scan(tmp_path, {'app/__init__.py': '', 'app/route.py': '''from flask import request
from .helper import make_path
def route():
    open(make_path(value=request.args.get('file')))
''', 'app/helper.py': 'def make_path(*, value):\n    return ' + ('"fixed.txt"' if safe else '"files/" + value') + '\n'}, ['app/route.py'])
    assert run.status == 'SUCCESS'
    assert len(found) == (0 if safe else 1)
    if found:
        trace = found[0].technical_details['dataflow_trace']
        assert any(s['file'] == 'app/helper.py' and s['kind'] == 'RESOLVED_CALL' for s in trace)


@pytest.mark.parametrize('arguments', ['value=source, unexpected=True', 'value=source, required_missing=True'])
def test_invalid_local_keyword_binding_cannot_fabricate_flow(tmp_path, arguments):
    found, run = scan(tmp_path, {'route.py': '''from flask import request
from helper import make_path
def route():
    source = request.args.get('file')
    open(make_path(''' + arguments + '''))
''', 'helper.py': 'def make_path(*, value):\n    return value\n'}, ['route.py'])
    assert not found
    assert any(g['reason'] == 'ARGUMENT_BINDING_UNRESOLVED' for g in run.scanner_diagnostics['context_gaps'])


@pytest.mark.parametrize('sql', ['value', '"SELECT 1"'])
def test_python_parent_relative_import_and_keyword_forwarding(tmp_path, sql):
    found, _ = scan(tmp_path, {'app/__init__.py':'', 'app/routes/__init__.py':'',
        'app/routes/entry.py': '''from flask import request
from ..helper import run
import sqlite3
def route():
    run(sqlite3.connect(':memory:').cursor(), value=request.args.get('q'))
''', 'app/helper.py': 'def run(db, *, value):\n    db.execute(' + sql + ')\n'}, ['app/routes/entry.py'])
    assert len(found) == (1 if sql == 'value' else 0)


@pytest.mark.parametrize('safe', [False, True])
def test_java_cross_file_constructor_field_and_return(tmp_path, safe):
    found, run = scan(tmp_path, {'Entry.java': '''import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
class Entry { void route(HttpServletRequest req, Connection con) {
 Box box = new Box(req.getParameter("q"));
 con.prepareStatement(box.value());
} }''', 'Box.java': '''class Box {
 private String text;
 Box(String value) { this.text = ''' + ('"fixed"' if safe else 'value') + '''; }
 String value() { return this.text; }
}'''}, ['Entry.java'])
    assert run.status == 'SUCCESS'
    assert len(found) == (0 if safe else 1)


def test_java_bound_spring_service_field_and_downstream_sql(tmp_path):
    found, run = scan(tmp_path, {'Entry.java': '''import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
@RestController class Entry {
 @Autowired Repo repo;
 @GetMapping void route(String value) { repo.lookup(value); }
}''', 'Repo.java': '''import java.sql.Connection;
class Repo { Connection con; void lookup(String value) { con.prepareStatement("SELECT " + value); } }
'''}, ['Entry.java'])
    assert run.status == 'SUCCESS' and len(found) == 1
    assert any(t['file'] == 'Repo.java' and t['kind'] == 'SINK' for t in found[0].technical_details['dataflow_trace'])


@pytest.mark.parametrize('method', ['queryForMap', 'queryForRowSet', 'queryForInt', 'queryForLong'])
def test_java_sdk_bound_jdbc_query_methods(tmp_path, method):
    found, _ = scan(tmp_path, {'Entry.java': '''import javax.servlet.http.HttpServletRequest;
import org.springframework.jdbc.core.JdbcTemplate;
class Entry { void route(HttpServletRequest req, JdbcTemplate db) {
 db.''' + method + '''("SELECT " + req.getParameter("q"));
} }'''})
    assert len(found) == 1


@pytest.mark.parametrize('decoded', [True, False])
def test_java_base64_roundtrip_and_string_constructor(tmp_path, decoded):
    expression = 'org.apache.commons.codec.binary.Base64.encodeBase64(value.getBytes())'
    if decoded: expression = 'org.apache.commons.codec.binary.Base64.decodeBase64(' + expression + ')'
    found, _ = scan(tmp_path, {'Entry.java': JAVA_ROUTE, 'Helper.java': JAVA_HELPERS.replace(
        'return "select * from things where name = " + value;', 'return new String(' + expression + ');')}, ['Entry.java'])
    assert len(found) == (1 if decoded else 0)


def test_java_same_named_local_codec_does_not_get_sdk_semantics(tmp_path):
    found, _ = scan(tmp_path, {'Entry.java': JAVA_ROUTE, 'Helper.java': JAVA_HELPERS.replace(
        'return "select * from things where name = " + value;', 'return Base64.decodeBase64(value);'),
        'Base64.java': 'class Base64 { static String decodeBase64(String s) { return "fixed"; } }'}, ['Entry.java'])
    assert not found


def test_java_resolution_cache_invalidates_when_another_unit_loads(tmp_path):
    from security_runtime.flow_java import JavaFlow
    (tmp_path / 'Entry.java').write_text('class Entry {}')
    flow = JavaFlow(Analysis(tmp_path))
    flow.load('Entry.java')
    flow.file, flow.cls = 'Entry.java', 'Entry'
    assert flow.find_class('Later') is None
    (tmp_path / 'Later.java').write_text('class Later {}')
    flow.load('Later.java')
    assert flow.find_class('Later') == 'Later'


@pytest.mark.parametrize('route,parameter,expected', [('GetMapping', 'String', 1), ('GetMapping', 'Integer', 0), ('Other', 'String', 0)])
def test_spring_inputs_require_known_route_controller_and_string_type(tmp_path, route, parameter, expected):
    found, _ = scan(tmp_path, {'Entry.java': f'''import org.springframework.web.bind.annotation.*;
import java.sql.Connection;
@RestController class Entry {{
  Connection con;
  @{route} void route({parameter} value) {{ con.prepareStatement("SELECT " + value); }}
}}'''})
    assert len(found) == expected


def test_switch_fallthrough_and_terminated_branch(tmp_path):
    found, _ = scan(tmp_path, {'Entry.java': '''import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
class Entry { void route(HttpServletRequest req, Connection con) {
 String value = "safe";
 switch (1) { case 1: value = "safe"; case 2: value = req.getParameter("q"); break; default: value = "safe"; }
 con.prepareStatement(value);
 return;
} }'''})
    assert len(found) == 1


def test_context_escape_and_source_change_fail_closed(tmp_path):
    analysis = Analysis(tmp_path)
    with pytest.raises(Limit, match='UNSAFE_CONTEXT_PATH'): analysis.read('../outside.py')
    (tmp_path / 'entry.py').write_text('v=1')
    analysis.read('entry.py')
    (tmp_path / 'entry.py').write_text('v=2')
    assert not analysis.stable()


def test_target_initializers_are_not_executed(tmp_path):
    marker = tmp_path / 'executed'
    scan(tmp_path, {'entry.py': f'''import os
open({str(marker)!r}, 'w').write('bad')
os.system('echo bad')
raise Exception('target was executed')
'''})
    assert not marker.exists()


def test_merged_instance_state_stays_unknown_instead_of_crashing(tmp_path):
    found, run = scan(tmp_path, {'entry.py': '''class Box:
    def __init__(self, unknown):
        if unknown: self.value = 'one'
        else: self.value = 'two'
        self.other = self.value
def handler(flag):
    b = Box(flag)
    return b.value
'''})
    assert not found and run.status == 'SUCCESS'


def test_dynamic_choice_of_local_instance_is_unknown(tmp_path):
    found, run = scan(tmp_path, {'entry.py': '''class One:
    def __init__(self): self.value = 'one'
class Two:
    def __init__(self): self.value = 'two'
def handler(flag):
    obj = One() if flag else Two()
    return obj.value
'''})
    assert not found and run.status == 'SUCCESS'
    assert any(g['reason'] == 'AMBIGUOUS_INSTANCE_TYPE' for g in run.scanner_diagnostics['context_gaps'])


def test_large_project_uses_bounded_batches_without_losing_targets(tmp_path):
    found, run = scan(tmp_path, {f'case_{i:03d}.py': '''from flask import request
import sqlite3
def route():
    sqlite3.connect(':memory:').cursor().execute('SELECT ' + request.args.get('x'))
''' for i in range(81)})
    assert len(found) == 81 and run.status == 'SUCCESS'
    assert run.rule_coverage['per_language']['python']['scanned_files'] == 81
    assert run.scanner_diagnostics['batches'] == 2


def test_deduplication_preserves_supplemental_chain_without_relabelling_rule(tmp_path):
    found, _ = scan(tmp_path, {'route.py': PY_ROUTE, 'helpers.py': PY_HELPERS}, ['route.py'])
    native = found[0]
    original = FindingNormalizer(tmp_path).make(scanner='semgrep', category=native.category,
        title='SQL', description='', severity='HIGH', confidence='MEDIUM',
        file_path=native.file_path, line=native.line_start, rule_id='original-rule')
    merged = deduplicate([original, native])
    assert len(merged) == 1
    assert merged[0].technical_details['rule_id'] == 'original-rule'
    assert merged[0].technical_details['supporting_dataflow'][0]['verification_scope_complete'] is False
