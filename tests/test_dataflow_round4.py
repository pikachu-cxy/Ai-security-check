"""Independent flow/control counterexamples; fixtures are parsed, never executed."""
import pytest

from test_bounded_dataflow import scan


@pytest.mark.parametrize('api',['io.open','codecs.open'])
@pytest.mark.parametrize('safe',[False,True])
def test_promoted_stream_sinks_preserve_collection_slice_and_with(tmp_path,api,safe):
    value="'fixed.txt'" if safe else "values[0][1:-1]"
    found,run=scan(tmp_path,{'entry.py':f'''from flask import request
import io, codecs
def route():
    values = request.form.getlist('filename')
    with {api}({value}, 'r') as stream:
        pass
'''})
    assert run.status=='SUCCESS'
    assert len(found)==(0 if safe else 1)
    if found: assert found[0].technical_details['path_default_basis']=='EXACT_IO_CODECS_OPEN'


def test_local_stream_name_is_not_an_sdk_sink(tmp_path):
    found,_=scan(tmp_path,{'entry.py':'''from flask import request
import codecs
def route(): codecs.open(request.args.get('f'))
''','codecs.py':'''def open(value): return 'fixed'
'''})
    assert not found


@pytest.mark.parametrize('operation',['read_text','exists','stat'])
@pytest.mark.parametrize('safe',[False,True])
def test_path_join_resolve_and_cross_file_sink(tmp_path,operation,safe):
    argument="'fixed.txt'" if safe else "request.headers.get('file')"
    found,run=scan(tmp_path,{'entry.py':f'''from flask import request
from store import load
def route(): load({argument})
''','store.py':f'''from pathlib import Path
def load(value):
    path = (Path('files') / value).resolve()
    return path.{operation}()
'''},['entry.py'])
    assert run.status=='SUCCESS'
    assert len(found)==(0 if safe else 1)
    if found:
        trace=found[0].technical_details['dataflow_trace']
        assert {s['file'] for s in trace}=={'entry.py','store.py'}
        assert {s['kind'] for s in trace}=={'SOURCE','RESOLVED_CALL','SINK'}


@pytest.mark.parametrize('guard',["'../' in value","not str(path).startswith('files')"])
def test_partial_path_checks_are_not_universal_sanitizers(tmp_path,guard):
    found,_=scan(tmp_path,{'entry.py':'''from flask import request
from store import load
def route(): load(request.args.get('file'))
''','store.py':f'''from pathlib import Path
def load(value):
    path = (Path('files') / value).resolve()
    if {guard}: return None
    return path.read_text()
'''},['entry.py'])
    assert len(found)==1


def java_loop(body,after=''):
    return '''import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.Cookie;
import java.sql.Connection;
class Entry {
 void route(HttpServletRequest req, Connection con) {
   String term="SAFE";
   for (Cookie cookie : req.getCookies()) { %s }
   %s
 }
}''' % (body,after)


def test_java_conditional_break_carries_exit_state_to_cross_file_sink(tmp_path):
    found,run=scan(tmp_path,{'Entry.java':java_loop('''
       if (cookie.getName().equals("search")) { term=cookie.getValue(); break; }
       term="SAFE";
    ''','Store.send(con,term);'),'Store.java':'''import java.sql.Connection;
class Store { static void send(Connection c,String q) { c.prepareStatement(q); } }
'''},['Entry.java'])
    assert run.status=='SUCCESS' and len(found)==1
    assert {s['file'] for s in found[0].technical_details['dataflow_trace']}=={'Entry.java','Store.java'}


def test_java_break_does_not_contaminate_continuing_loop_branch(tmp_path):
    found,run=scan(tmp_path,{'Entry.java':java_loop('''
       if (cookie.getName().equals("search")) { term=cookie.getValue(); break; }
       con.prepareStatement(term);
    ''')})
    assert run.status=='SUCCESS' and not found


def test_java_switch_break_is_not_a_loop_exit(tmp_path):
    found,run=scan(tmp_path,{'Entry.java':java_loop('''
       term=cookie.getValue();
       switch(1) { case 1: term="SAFE"; break; default: break; }
    ''','con.prepareStatement(term);')})
    assert run.status=='SUCCESS' and not found


@pytest.mark.parametrize('safe',[False,True])
def test_java_request_enumeration_one_pass(tmp_path,safe):
    query='"SELECT 1"' if safe else 'name'
    found,run=scan(tmp_path,{'Entry.java':'''import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.util.Enumeration;
class Entry { void route(HttpServletRequest req, Connection con) {
 Enumeration<String> names=req.getParameterNames();
 while(names.hasMoreElements()) { String name=names.nextElement();
 con.prepareStatement(%s); }
} }''' % query})
    assert run.status=='SUCCESS' and len(found)==(0 if safe else 1)
    assert any(g['reason']=='REQUEST_ENUMERATION_ONE_PASS' for g in run.scanner_diagnostics['context_gaps'])


@pytest.mark.parametrize('result',['unknownConnection()','null'])
def test_declared_sdk_return_kind_requires_resolved_method(tmp_path,result):
    found,run=scan(tmp_path,{'Entry.java':'''import javax.servlet.http.HttpServletRequest;
class Entry { void route(HttpServletRequest req) {
 Factory.connection().prepareStatement(req.getParameter("q"));
} }''','Factory.java':'''import java.sql.Connection;
class Factory { static Connection connection() { return %s; } }''' % result},['Entry.java'])
    assert run.status=='SUCCESS'
    assert len(found)==(0 if result=='null' else 1)
