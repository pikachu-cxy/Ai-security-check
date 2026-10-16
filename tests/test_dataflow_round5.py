"""Independent bounded-loop and Python control-flow counterexamples."""
import pytest

from test_bounded_dataflow import scan


@pytest.mark.parametrize('flag',[True,False])
def test_nested_request_enumeration_array_and_cross_file_sink(tmp_path,flag):
    found,run=scan(tmp_path,{'Entry.java':'''import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.util.Enumeration;
class Entry { void route(HttpServletRequest req,Connection con) {
 String query="SAFE";
 boolean flag=%s;
 Enumeration<String> names=req.getParameterNames();
 while(names.hasMoreElements() && flag) {
  String name=names.nextElement();
  String[] values=req.getParameterValues(name);
  for(int i=0;i<values.length && flag;i++) {
   if(values[i].equals("search")) { query=name; flag=false; }
  }
 }
 Store.query(con,query);
} }''' % str(flag).lower(),'Store.java':'''import java.sql.Connection;
class Store { static void query(Connection c,String s) { c.prepareStatement(s); } }
'''},['Entry.java'])
    assert run.status=='SUCCESS' and len(found)==int(flag)
    if found:
        assert {s['file'] for s in found[0].technical_details['dataflow_trace']}=={'Entry.java','Store.java'}
        assert any(g['reason']=='REQUEST_ARRAY_ONE_PASS' for g in run.scanner_diagnostics['context_gaps'])


@pytest.mark.parametrize('condition',['!names.hasMoreElements()','false && names.hasMoreElements()'])
def test_negated_or_disabled_request_iteration_not_promoted(tmp_path,condition):
    found,_=scan(tmp_path,{'Entry.java':'''import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.util.Enumeration;
class Entry { void route(HttpServletRequest req,Connection con) {
 Enumeration<String> names=req.getParameterNames();
 while(%s) { con.prepareStatement(names.nextElement()); }
} }''' % condition})
    assert not found


def test_loop_return_does_not_flow_to_after_loop_sink(tmp_path):
    found,_=scan(tmp_path,{'Entry.java':'''import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.util.Enumeration;
class Entry { void route(HttpServletRequest req,Connection con) {
 String query="SAFE";
 Enumeration<String> names=req.getParameterNames();
 while(names.hasMoreElements()) { query=names.nextElement(); return; }
 con.prepareStatement(query);
} }'''})
    assert not found


@pytest.mark.parametrize('condition',['i < -values.length','i++ < values.length'])
def test_unsupported_index_condition_cannot_fabricate_loop(tmp_path,condition):
    found,run=scan(tmp_path,{'Entry.java':'''import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
class Entry { void route(HttpServletRequest req,Connection con) {
 String[] values=req.getParameterValues("q");
 for(int i=0;%s;i++) { con.prepareStatement(values[i]); }
} }''' % condition})
    assert not found
    assert any(g['reason']=='LOOP_UNRESOLVED' for g in run.scanner_diagnostics['context_gaps'])


@pytest.mark.parametrize('which,expected',[('a',1),('b',0),('c',1),('other',0)])
def test_constant_match_preserves_only_selected_path(tmp_path,which,expected):
    found,run=scan(tmp_path,{'entry.py':'''from flask import request
import codecs
def route():
    source=request.form.get('path')
    match %r:
        case 'a' | 'c': filename=source
        case 'b': filename='fixed'
        case _: filename='other'
    codecs.open(filename)
''' % which})
    assert run.status=='SUCCESS' and len(found)==expected


def test_unknown_match_pattern_remains_unresolved(tmp_path):
    found,run=scan(tmp_path,{'entry.py':'''from flask import request
import codecs
def route():
    filename='fixed'
    match 'a':
        case Status.SAFE: filename='fixed'
        case _: filename=request.form.get('path')
    codecs.open(filename)
'''})
    assert not found
    assert any(g['reason']=='MATCH_PATTERN_UNRESOLVED' for g in run.scanner_diagnostics['context_gaps'])


@pytest.mark.parametrize('safe',[False,True])
def test_request_key_iteration_through_local_call(tmp_path,safe):
    found,_=scan(tmp_path,{'entry.py':'''from flask import request
from helper import read
def route():
    filename='fixed'
    for key in request.headers.keys(): filename=key
    read(%s)
''' % ("'fixed'" if safe else 'filename'),'helper.py':'''import io
def read(name): return io.open(name)
'''},['entry.py'])
    assert len(found)==(0 if safe else 1)


def test_decoded_query_slice_with_typed_offsets_preserves_flow(tmp_path):
    found,_=scan(tmp_path,{'entry.py':'''from flask import request
from helper import parse
import codecs
def route(): codecs.open(parse(request.query_string.decode('utf-8')))
''','helper.py':'''def parse(raw):
    start=raw.find('file=')
    value=raw[start+len('file='):]
    end=value.find('&')
    if end != -1: value=value[:end]
    return value
'''},['entry.py'])
    assert len(found)==1


def test_invalid_slice_bound_does_not_invent_a_path(tmp_path):
    found,_=scan(tmp_path,{'entry.py':'''from flask import request
import codecs
def route(): codecs.open(request.form.get('file')['bad':])
'''})
    assert not found


def test_python_return_inside_request_loop_does_not_taint_after_loop(tmp_path):
    found,_=scan(tmp_path,{'entry.py':'''from flask import request
import io
def route():
    filename='fixed'
    for key in request.headers.keys():
        filename=key
        return 'done'
    io.open(filename)
'''})
    assert not found


def test_python_break_skips_remaining_iteration_statements(tmp_path):
    found,_=scan(tmp_path,{'entry.py':'''from flask import request
import io
def route():
    filename='fixed'
    for key in request.headers.keys():
        break
        filename=key
    io.open(filename)
'''})
    assert not found


def test_python_conditional_break_keeps_exit_for_cross_file_sink(tmp_path):
    found,_=scan(tmp_path,{'entry.py':'''from flask import request
from helper import read
def route():
    filename='fixed'
    for key in request.headers.keys():
        if key:
            filename=key
            break
        filename='fixed'
    read(filename)
''','helper.py':'''import io
def read(name): return io.open(name)
'''},['entry.py'])
    assert len(found)==1


@pytest.mark.parametrize('body,expected',[
    ("continue\n        filename=key",0),
    ("filename=key\n    else:\n        filename='fixed'",0),
    ("filename=key\n        break\n    else:\n        filename='fixed'",1)])
def test_python_continue_and_for_else_keep_distinct_exit_paths(tmp_path,body,expected):
    found,_=scan(tmp_path,{'entry.py':'''from flask import request
import io
def route():
    filename='fixed'
    for key in request.headers.keys():
        %s
    io.open(filename)
''' % body})
    assert len(found)==expected
