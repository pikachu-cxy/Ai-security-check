import hashlib,hmac,json
import pytest
from test_hook_runtime import repo
from test_first_scan_attribution import harness,commit
from test_remediation import FIXED,UNSAFE
from test_cursor_host_adapter import payload
from security_runtime.cursor_hook import CursorBindings,handle_cursor_event
from security_runtime.cursor_integration import GlobalCursorIntegration,encode
from security_runtime.cursor_event_adapter import CursorHostEventAdapter
from security_runtime.recent_hooks import RecentHookStore

@pytest.mark.parametrize('old_matcher,flag',[('*',' --post-tool-use-probe'),('^Write$','')])
def test_owned_five_hook_cleanup_and_user_preservation(tmp_path,old_matcher,flag):
    home=tmp_path/'cursor';home.mkdir();path=home/'hooks.json'
    user={'version':1,'unknown':{'keep':True},'hooks':{'postToolUse':[{'command':'user-owned','matcher':'*'}]}}
    path.write_bytes(encode(user));mcp=home/'mcp.json';mcp.write_bytes(b'{"user":"unchanged"}')
    runtime=dict(kind='INSTALLED',command='runtime',prefix=[])
    installer=GlobalCursorIntegration(home=home,directory=tmp_path/'ownership',discover=lambda:runtime)
    assert installer.execute('setup')['overall']=='CONFIGURED'
    value=json.loads(path.read_bytes());mp,manifest=installer._manifest()
    old=dict(command='runtime cursor-hook'+flag,type='command',timeout=120,matcher=old_matcher)
    value['hooks']['postToolUse'].append(old);manifest['records']['postToolUse']=old
    path.write_bytes(encode(value));key=installer.store.key(home)
    mp.write_bytes(encode({**manifest,'signature':hmac.new(key,encode(manifest),hashlib.sha256).hexdigest()}))
    assert installer.execute('status')['overall']=='NEEDS_REPAIR'
    assert installer.execute('repair')['overall']=='CONFIGURED'
    value=json.loads(path.read_bytes());assert value['hooks']['postToolUse']==user['hooks']['postToolUse']
    assert set(installer._manifest()[1]['records'])=={'sessionStart','afterFileEdit','afterShellExecution','stop'}
    before=path.read_bytes();assert not installer.execute('setup')['changed'];assert not installer.execute('repair')['changed']
    assert before==path.read_bytes() and mcp.read_bytes()==b'{"user":"unchanged"}'
    installer.execute('remove');assert json.loads(path.read_bytes())==user

def test_detection_advisory_no_pending_and_stop_unchanged(repo,harness,tmp_path):
    commit(repo,FIXED);core,calls=harness[:2]
    bindings=CursorBindings(tmp_path/'bindings');recent=RecentHookStore(tmp_path/'recent.db')
    class Forbidden:
        def __getattr__(self,name):raise AssertionError('Disabled delivery accessed')
    def hook(event,**kwargs):
        return handle_cursor_event(payload(repo,event,**kwargs),core=core,feedback=Forbidden(),
            bindings=bindings,store=recent,project_dir=str(repo))
    hook('sessionStart');(repo/'A.java').write_text(UNSAFE,encoding='utf-8')
    native,result=hook('afterFileEdit')
    assert native=={} and result['execution']['scanner_run']
    assert result['remediation']['remediation_status']=='OFFERED'
    assert not result['security_feedback_pending'] and result['security_feedback_count']==0
    assert result['security_feedback_delivery_status']=='HOST_CAPABILITY_UNAVAILABLE_ON_OBSERVED_PATH'
    count=len(calls);native,result=hook('stop',status='completed',loop_count=0)
    assert native=={} and not result['scanner_run'] and len(calls)==count
    native,result=hook('postToolUse',tool_name='Write',tool_use_id='opaque')
    assert native=={} and result['reason']=='HOST_CAPABILITY_UNAVAILABLE' and len(calls)==count
    caps=CursorHostEventAdapter.transport_capabilities
    assert caps.supports_detection and caps.supports_advisory_remediation
    assert not caps.supports_user_visible_feedback and not caps.supports_agent_continuation
