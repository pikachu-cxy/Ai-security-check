import hashlib
import time

import pytest

from security_runtime.python_constants import proven_constant_calls, filter_results
from test_scanner_hot_path import engine  # noqa: F401


def proofs(code):
    return proven_constant_calls('def handle(value):\n'+''.join('    '+line+'\n' for line in code.splitlines()))


@pytest.mark.parametrize('code',[
    'x="fixed"\neval(x)',
    'd={"safe":"fixed", "unsafe":value}\nx=d["unsafe"]\nx=d["safe"]\nos.system(x)',
    'n=86\nif 7*42-n>200:\n    x="fixed"\nelse:\n    x=value\neval(x)',
    'if value:\n    prefix="sh -c "\nelse:\n    prefix="cmd /c "\nx="fixed"\nos.system(prefix+f"echo {x}")',
    'guess="ABC"[1]\nmatch guess:\n    case "A":\n        x=value\n    case "B":\n        x="fixed"\neval(x)',
])
def test_only_proved_constant_scalars_are_suppressed(code):
    assert proofs(code)


@pytest.mark.parametrize('code',[
    'eval(value)',
    'x="fixed"\nx=value\neval(x)',
    'if value:\n    x="fixed"\nelse:\n    x=value\neval(x)',
    'd={"safe":"fixed"}\nmutate(d)\nos.system(d["safe"])',
    'd={"safe":"fixed"}\nalias=d\nalias["safe"]=value\nos.system(d["safe"])',
    'x=unknown_sanitizer(value)\neval(x)',
    'x="fixed"\nexec(value)\neval(x)',
    'x="fixed"\nfor item in value:\n    x=item\neval(x)',
    'try:\n    x="fixed"\nexcept:\n    x=value\neval(x)',
    'x="fixed"\neval(x);eval(value)',
    'x="fixed"\nx,y=value\neval(x)',
    'd=alias={"safe":"fixed"}\nalias["safe"]=value\neval(d["safe"])',
    'd={"child":{"safe":"fixed"}}\nalias=d["child"]\nalias["safe"]=value\neval(d["child"]["safe"])',
    'd={"safe":"fixed"}\ncall(mutate(d),eval(d["safe"]))',
    'x="fixed"\ncall((x:=value),eval(x))',
    'x="fixed"\nfor item in value:\n    eval(x)\n    x=item',
    'x="fixed"\nfrom external import x\neval(x)',
])
def test_uncertainty_and_reassignment_retain_alerts(code):
    assert not proofs(code)


def test_filter_requires_matching_source_hash(tmp_path):
    text='def f():\n    x="fixed"\n    eval(x)\n'
    (tmp_path/'app.py').write_text(text,encoding='utf-8')
    raw=(tmp_path/'app.py').read_bytes();digest=hashlib.sha256(raw).hexdigest()
    data={'results':[{'check_id':'ai-security.python.unsafe-eval','path':'app.py','start':{'line':3}}]}
    kept,suppressed=filter_results(data,tmp_path,{'app.py':{'file_sha256':digest}},time.monotonic()+1)
    assert not kept['results'] and len(suppressed)==1
    kept,suppressed=filter_results(data,tmp_path,{'app.py':{'file_sha256':'wrong'}},time.monotonic()+1)
    assert kept['results']==data['results'] and not suppressed


def test_budget_and_invalid_syntax_keep_originals():
    assert not proven_constant_calls('def invalid(')
    assert not proven_constant_calls('def f():\n    eval("fixed")\n',seconds=0)


def test_multiline_engine_range_requires_all_calls_proved(tmp_path):
    text='def f(value):\n    x="fixed"\n    result=(\n        eval(x)\n    )\n'
    path=tmp_path/'app.py';path.write_text(text,encoding='utf-8')
    data={'results':[{'check_id':'ai-security.python.unsafe-eval','path':'app.py','start':{'line':3},'end':{'line':5}}]}
    before={'app.py':{'file_sha256':hashlib.sha256(path.read_bytes()).hexdigest()}}
    kept,suppressed=filter_results(data,tmp_path,before,time.monotonic()+1)
    assert not kept['results'] and suppressed
    path.write_text(text.replace('eval(x)','eval(x),eval(value)'),encoding='utf-8')
    before={'app.py':{'file_sha256':hashlib.sha256(path.read_bytes()).hexdigest()}}
    kept,suppressed=filter_results(data,tmp_path,before,time.monotonic()+1)
    assert kept['results'] and not suppressed


def test_user_rule_directory_bypasses_builtin_constant_filter(engine,monkeypatch):
    import json
    from dataclasses import replace
    from security_runtime.models import ScanContext,ScanMode
    from security_runtime.findings import FindingNormalizer
    from security_runtime.processes import ProcessResult
    root,_,pack,adapter,_,_=engine
    (root/'app.py').write_text('def handle():\n    value="fixed"\n    eval(value)\n')
    result={'check_id':'ai-security.python.unsafe-eval','path':'app.py','start':{'line':3},'end':{'line':3},
            'extra':{'message':'Dynamic eval','severity':'ERROR','metadata':{}}}
    def execute(*_args):
        return ProcessResult(0,json.dumps({'results':[result],'paths':{'scanned':['app.py']},'errors':[]}), '',1)
    monkeypatch.setattr('security_runtime.scanners._execute',execute)
    context=ScanContext(str(root),ScanMode.RELEASE,('app.py',))
    found,run=adapter.scan(context,FindingNormalizer(root))
    assert not found and run.scanner_diagnostics['constant_proof']['suppressed_count']==1
    found,run=adapter.scan(replace(context,rules_path=str(pack)),FindingNormalizer(root))
    assert len(found)==1 and run.scanner_diagnostics['constant_proof']['suppressed_count']==0


CONFIG='''import configparser
c=configparser.ConfigParser()
c.add_section('commands')
c.set('commands','safe','echo fixed')
c.set('commands','unsafe',value)
'''


def test_configparser_exact_local_key_and_case_folding():
    assert proofs(CONFIG+'x=c.get("commands","SAFE")\nexec(x)')
    assert not proofs(CONFIG+'x=c.get("commands","unsafe")\nexec(x)')
    assert not proofs(CONFIG+'c.set("commands","SAFE",value)\nx=c.get("commands","safe")\neval(x)')


@pytest.mark.parametrize('change',[
    'c.set("commands","safe","%(unsafe)s")',
    'c.read("external.ini")',
    'c.read_dict(value)',
    'c.set("commands",value,"fixed")',
    'alias=c\nalias.set("commands","safe",value)',
    'holder={"config":c}\nmutate(holder)',
    'c.optionxform=lambda key:key',
    'mutate(c)',
    'c.set("commands","safe",mutate(c))',
])
def test_configparser_unknown_mutations_and_interpolation_retain_alerts(change):
    assert not proofs(CONFIG+change+'\nx=c.get("commands","safe")\nos.system(x)')


def test_configparser_constructor_arguments_and_shadowing_not_trusted():
    assert not proofs(CONFIG.replace('ConfigParser()','ConfigParser(value)')+'\neval(c.get("commands","safe"))')
    assert not proofs(CONFIG.replace('c=configparser','configparser=value\nc=configparser')+'\neval(c.get("commands","safe"))')
    text='import configparser\ndef outer(configparser):\n    def inner():\n        c=configparser.ConfigParser()\n        c.add_section("s")\n        c.set("s","k","fixed")\n        eval(c.get("s","k"))\n'
    assert not proven_constant_calls(text)


def test_exec_constant_is_safe_only_before_unknown_writes():
    assert proofs('text="x=1"\nexec(text)')
    result=proven_constant_calls('def f(user):\n    x="fixed"\n    exec(user)\n    eval(x)\n')
    assert not result


def test_configparser_global_bindings_and_nested_mutations_are_not_proofs():
    global_import='import configparser\ndef f(value):\n'+''.join('    '+line+'\n' for line in (CONFIG.split('\n',1)[1]+'eval(c.get("commands","safe"))').splitlines())
    assert not proven_constant_calls(global_import)
    assert not proofs(CONFIG+'x=c.get("commands","safe") if mutate(c) else "fixed"\neval(x)')
    two=CONFIG+'other=configparser.ConfigParser()\nother.add_section("s")\nother.set("s","k","fixed")\n'
    # Recreate c after constructing other: unknown constructors invalidate old objects.
    two+='c=configparser.ConfigParser()\nc.set("s","k",mutate(other))\neval(other.get("s","k"))'
    assert not proofs(two)


GUARD='''if not value.startswith("'") or not value.endswith("'") or "'" in value[1:-1]:
    return
'''


@pytest.mark.parametrize('sink',['eval(value)','exec(value)'])
def test_exact_rejecting_literal_guard(sink):
    assert proofs(GUARD+sink)
    assert proofs(GUARD+'try:\n    '+sink+'\nexcept Exception:\n    pass')


@pytest.mark.parametrize('code',[
    GUARD.replace('    return','    pass')+'exec(value)',
    GUARD.replace(' or ', ' and ')+'exec(value)',
    GUARD.replace(' or "\'" in value[1:-1]','')+'exec(value)',
    GUARD.replace('value[1:-1]','value[2:-2]')+'exec(value)',
    GUARD.replace('value.endswith','other.endswith')+'exec(value)',
    GUARD+'value=unknown()\nexec(value)',
    GUARD+'exec(other)',
    GUARD+'exec(value+other)',
    GUARD+'os.system(value)',
    GUARD+'else:\n    value=unknown()\nexec(value)',
    GUARD.replace('    return','    if unknown():\n        return')+'exec(value)',
])
def test_incomplete_literal_guards_and_changed_values_retain_alerts(code):
    assert not proofs(code)


def test_guard_diagnostic_is_distinct_from_constant_proof(tmp_path):
    code='def f(value):\n'+''.join('    '+line+'\n' for line in (GUARD+'exec(value)').splitlines())
    path=tmp_path/'app.py';path.write_text(code,encoding='utf-8')
    data={'results':[{'check_id':'ai-security.python.unsafe-eval','path':'app.py','start':{'line':4}}]}
    before={'app.py':{'file_sha256':hashlib.sha256(path.read_bytes()).hexdigest()}}
    kept,suppressed=filter_results(data,tmp_path,before,time.monotonic()+1)
    assert not kept['results']
    assert suppressed[0]['basis']=='EXACT_STRING_LITERAL_GUARD'


@pytest.mark.parametrize('code',[
    'd={}\nd["safe"]="public"\nd["input"]=value\nx=d["safe"]\nsql="SELECT "+x\ncur.execute(sql)',
    'd={}\nd["input"]=value\nd["input"]="public"\nx=d["input"]\ncur.execute("SELECT "+x)',
    'd={"safe":"public","input":value}\nx=d.get("safe")\ncur.execute("SELECT "+x)',
    'd={"input":value}\nx=d.get("absent","public")\ncur.execute("SELECT "+x)',
])
def test_sql_constant_key_is_not_contaminated_by_other_dictionary_keys(code):
    assert proofs(code)


@pytest.mark.parametrize('code',[
    'd={}\nd["input"]=value\nd["other"]="public"\nx=d["input"]\ncur.execute("SELECT "+x)',
    'd={"safe":"public"}\nalias=d\nalias["safe"]=value\ncur.execute(d["safe"])',
    'd={"safe":"public"}\nmutate(d)\nx=d["safe"]\ncur.execute("SELECT "+x)',
    GUARD+'cur.execute(value)',
    'd={"input":value}\nx=d.get("input")\ncur.execute("SELECT "+x)',
    'd={"safe":"public"}\nx=d.get(value)\ncur.execute("SELECT "+x)',
    'd={"safe":"public"}\nx=d.get("safe",mutate(d))\ncur.execute("SELECT "+x)',
])
def test_sql_unknown_values_aliases_and_quote_guard_retain_alerts(code):
    assert not proofs(code)


@pytest.mark.parametrize('sink', ['open(path, "rb")', 'flask.send_file(path)'])
def test_path_requires_the_whole_operand_to_be_a_local_constant(sink):
    code = 'n=86\nif 7*42-n>200:\n    leaf="fixed.txt"\nelse:\n    leaf=value\n'
    assert proofs(code + 'path="/srv/public/"+leaf\n' + sink)
    # An imported base is not a constant merely because its name looks trusted.
    assert not proofs(code + 'path=f"{settings.ROOT}/{leaf}"\n' + sink)
    assert not proofs(code.replace('n=86', 'n=value') + 'path="/srv/public/"+leaf\n' + sink)
    assert not proofs(code + 'path="/srv/public/"+leaf\npath=value\n' + sink)


def test_path_constant_filter_keeps_a_second_dynamic_call_on_the_same_line(tmp_path):
    text = 'def read(value):\n    path="fixed.txt"\n    open(path);open(value)\n'
    path = tmp_path/'app.py'
    path.write_text(text, encoding='utf-8')
    before = {'app.py': {'file_sha256': hashlib.sha256(path.read_bytes()).hexdigest()}}
    data = {'results': [{'check_id': 'ai-security.python.path-traversal', 'path': 'app.py', 'start': {'line': 3}}]}
    kept, suppressed = filter_results(data, tmp_path, before, time.monotonic()+1)
    assert kept['results'] == data['results'] and not suppressed


@pytest.mark.parametrize('branch', [
    'n=86\nif 7*42-n>200:\n    value="fixed"\nelse:\n    value=request.form.get("value")',
    'choice="ABC"[1]\nmatch choice:\n    case "A":\n        value=request.form.get("value")\n    case "B":\n        value="fixed"',
])
@pytest.mark.parametrize('response', [
    'response += f"<p>{value}</p>"',
    'response += "<p>%s</p>" % value',
    'response += "<p>%s:%s</p>" % (value, "fixed")',
    'response += "<p>{}</p>".format(value)',
])
def test_flask_response_filter_proves_the_entire_formatted_operand(tmp_path, branch, response):
    body = 'response=""\n' + branch + '\n' + response + '\nreturn response'
    text = '@app.route("/")\ndef route():\n' + ''.join('    '+line+'\n' for line in body.splitlines())
    path = tmp_path/'app.py'
    path.write_text(text, encoding='utf-8')
    line = next(i for i, value in enumerate(text.splitlines(), 1) if 'response +=' in value)
    data = {'results': [{'check_id': 'ai-security.python.flask-html-response', 'path': 'app.py',
                         'start': {'line': line}, 'end': {'line': line}}]}
    before = {'app.py': {'file_sha256': hashlib.sha256(path.read_bytes()).hexdigest()}}
    kept, suppressed = filter_results(data, tmp_path, before, time.monotonic()+1)
    assert not kept['results'] and suppressed[0]['basis'] == 'PROVEN_LOCAL_CONSTANT'
    # Unknown branch inputs and reassignment invalidate the proof.
    changed = text.replace('n=86', 'n=request.form.get("n")').replace('choice="ABC"[1]', 'choice=request.form.get("choice")')
    path.write_text(changed, encoding='utf-8')
    before = {'app.py': {'file_sha256': hashlib.sha256(path.read_bytes()).hexdigest()}}
    kept, suppressed = filter_results(data, tmp_path, before, time.monotonic()+1)
    assert kept['results'] == data['results'] and not suppressed


def test_flask_response_constant_filter_never_runs_target_formatting():
    text = '@app.route("/")\ndef route():\n    return "%999999999999s" % "fixed"\n'
    assert ('ai-security.python.flask-html-response', 3) in proven_constant_calls(text)


def test_annotation_only_statement_retains_unknown_and_existing_raw_alerts():
    assert not proofs('value: str\neval(value)')
    assert not proofs('path="fixed.txt"\npath: str\nopen(path)')
    assert not proofs('value: str\nvalue=unknown()\neval(value)')
