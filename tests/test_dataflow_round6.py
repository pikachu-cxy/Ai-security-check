"""Independent controls for executed JDBC batches and typed Flask path splitting."""
import pytest

from test_bounded_dataflow import scan


@pytest.mark.parametrize('operation,expected', [
    ('statement.addBatch(input); statement.executeBatch();', 1),
    ('statement.addBatch(input); statement.executeLargeBatch();', 1),
    ('statement.addBatch(input);', 0),
    ('statement.addBatch(input); statement.clearBatch(); statement.executeBatch();', 0),
    ('statement.addBatch("SELECT 1"); statement.executeBatch();', 0),
    ('statement.addBatch(input); return;', 0),
])
def test_jdbc_batch_requires_a_matching_execution(tmp_path, operation, expected):
    findings, run = scan(tmp_path, {'Entry.java': '''import java.sql.Connection;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;
class Entry { void route(HttpServletRequest req, Connection con) throws Exception {
 String input = req.getParameter("sql");
 Statement statement = con.createStatement();
 %s
} }''' % operation})
    assert run.status == 'SUCCESS' and len(findings) == expected
    if findings:
        assert any(step['kind'] == 'JDBC_BATCH_ADD' for step in findings[0].technical_details['dataflow_trace'])


def test_batch_state_survives_a_resolved_cross_file_call(tmp_path):
    findings, _ = scan(tmp_path, {'Entry.java': '''import java.sql.Connection;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;
class Entry { void route(HttpServletRequest req, Connection con) throws Exception {
 Statement statement=con.createStatement();
 Store.enqueue(statement, req.getParameter("sql"));
 statement.executeBatch();
} }''', 'Store.java': '''import java.sql.Statement;
class Store { static void enqueue(Statement stmt, String query) throws Exception {
 stmt.addBatch(query);
} }'''}, ['Entry.java'])
    assert len(findings) == 1
    assert {step['file'] for step in findings[0].technical_details['dataflow_trace']} == {'Entry.java', 'Store.java'}


def test_prepared_statement_bound_values_are_not_sql_templates(tmp_path):
    findings, _ = scan(tmp_path, {'Entry.java': '''import java.sql.Connection;
import java.sql.PreparedStatement;
import javax.servlet.http.HttpServletRequest;
class Entry { void route(HttpServletRequest req, Connection con) throws Exception {
 PreparedStatement statement=con.prepareStatement("SELECT * FROM t WHERE name=?");
 statement.setString(1, req.getParameter("name"));
 statement.addBatch(); statement.executeBatch();
} }'''})
    assert not findings


@pytest.mark.parametrize('source,expected', [
    ('request.path.split("/")[1]', 1),
    ('request.full_path.rsplit("/", 1)[0]', 1),
    ('request.url.split("/")[2]', 1),
    ('request.path.split(sep="/", maxsplit=2)[1]', 1),
    ('"/fixed/one".split("/")[1]', 0),
    ('request.path.split("")[0]', 0),
    ('request.path.split("/", "bad")[0]', 0),
    ('request.path.split(sep="")[0]', 0),
    ('request.path.split("/", sep="/")[0]', 0),
    ('request.path.split("/", maxsplit="bad")[0]', 0),
    ('request.path.split(unknown="/")[0]', 0),
])
def test_flask_typed_path_split_to_cross_file_sink(tmp_path, source, expected):
    findings, _ = scan(tmp_path, {'entry.py': '''from flask import request
from storage import read
@app.route('/<path:filename>')
def route(filename=None):
    read(%s)
''' % source, 'storage.py': '''import io
def read(filename): return io.open(filename)
'''}, ['entry.py'])
    assert len(findings) == expected


def test_local_flask_module_does_not_become_an_http_source(tmp_path):
    findings, _ = scan(tmp_path, {'entry.py': '''from flask import request
import io
def route(): io.open(request.path.split('/')[1])
''', 'flask.py': '''class Request:
    path='/fixed/file'
request=Request()
'''}, ['entry.py'])
    assert not findings


def test_fixed_flask_path_is_not_tainted_by_a_previous_dynamic_entry(tmp_path):
    findings, _ = scan(tmp_path, {'entry.py': '''from flask import request
import io
@app.route('/<path:filename>')
def dynamic(filename=None): io.open(request.path.split('/')[1])
@app.route('/fixed/file')
def fixed(): io.open(request.path.split('/')[1])
'''})
    assert len(findings) == 1
    assert findings[0].line_start == 4


def test_dynamic_flask_route_context_reaches_a_resolved_helper(tmp_path):
    findings, _ = scan(tmp_path, {'entry.py': '''from helper import filename
from storage import read
@app.route('/<path:value>')
def route(value=None): read(filename())
''', 'helper.py': '''from flask import request
def filename(): return request.path.split('/')[1]
''', 'storage.py': '''import io
def read(name): return io.open(name)
'''}, ['entry.py'])
    assert len(findings) == 1
    assert {s['file'] for s in findings[0].technical_details['dataflow_trace']} == {'entry.py', 'helper.py', 'storage.py'}


@pytest.mark.parametrize('safe', [False, True])
def test_only_resolved_java_cross_file_paths_are_promoted(tmp_path, safe):
    value = '"fixed.txt"' if safe else 'input'
    findings, run = scan(tmp_path, {'Entry.java': '''import javax.servlet.http.HttpServletRequest;
class Entry { void route(HttpServletRequest request) throws Exception {
 new java.io.FileReader(Storage.name(request.getParameter("file")));
} }''', 'Storage.java': '''class Storage {
 static String name(String input) { return %s; }
}''' % value}, ['Entry.java'])
    assert len(findings) == (0 if safe else 1)
    assert run.rule_coverage['java_path_scope'] == 'RESOLVED_CROSS_FILE_CALLS_ONLY'
    if findings:
        assert {step['file'] for step in findings[0].technical_details['dataflow_trace']} == {'Entry.java', 'Storage.java'}


def test_java_intraprocedural_path_stays_experimental(tmp_path):
    findings, _ = scan(tmp_path, {'Entry.java': '''import javax.servlet.http.HttpServletRequest;
class Entry { void route(HttpServletRequest request) throws Exception {
 new java.io.FileReader(request.getParameter("file"));
} }'''})
    assert not findings
