"""Explicit Windows process acceptance; simulates Host events, not a Cursor desktop/model test."""
import argparse
import asyncio, json, os, subprocess
from pathlib import Path
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from task_review_v3_acceptance import TASK_TOOLS, V3Review, require_v3
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--bundle', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--empty-tool-id', action='store_true', help='Replay Cursor writes without an invocation ID')
parser.add_argument('--diagnostic-tool-id', action='store_true', help='Check an opaque non-string diagnostic ID')
parser.add_argument('--mcp-begin', action='store_true', help='Exercise pre-MCP and MCP begin idempotency before native editing')
args=parser.parse_args()
if os.name != 'nt':
    parser.error('This acceptance currently covers Windows x64 only')
from security_runtime.hook_state import no_links
from security_runtime.delivery import package_metadata
bundle=args.bundle.absolute()
package_metadata(bundle)
base=args.output.absolute()
workspace=Path(__file__).resolve().parents[1]
no_links(base)
if not base.is_relative_to(workspace/'artifacts'):
    parser.error('Output must be a fresh directory inside repository artifacts')
base.mkdir(exist_ok=False, parents=True)
env=dict(os.environ, SECURITY_RUNTIME_STATE_DIR=str(base/'state'), SECURITY_RUNTIME_CURSOR_HOME=str(base/'cursor home'), SECURITY_RUNTIME_SKILLS_DIR=str(base/'skills'), SECURITY_RUNTIME_OFFLINE='1')
project=base/'project';project.mkdir()
subprocess.run(['git','init','-q',str(project)],check=True)
(project/'sample.py').write_text('value = 1\n')
proc=subprocess.run([str(bundle/'security-check.exe'),'install','cursor','--bundle',str(bundle),'--root',str(base/'program'),'--offline','--json'],env=env,capture_output=True,timeout=120)
(base/'install.json').write_bytes(proc.stdout)
print('installation exit',proc.returncode)
receipt=json.loads(proc.stdout);print(json.dumps({k:receipt.get(k) for k in ('overall','integration','installation','diagnostics')},ensure_ascii=True))
assert receipt['installation']['local_files_ready']
assert receipt['routine_tool_approval']['status']=='CONFIGURED'
assert receipt['routine_tool_approval']['live_no_prompt_verified'] is False
permissions=json.loads((base/'cursor home/permissions.json').read_bytes())
assert TASK_TOOLS <= {entry.split(':',1)[1] for entry in permissions['mcpAllowlist']}
assert all(v.startswith('ai-security-runtime:') and '*' not in v for v in permissions['mcpAllowlist'])
assert 'ai-security-runtime:confirm_remediation' not in permissions['mcpAllowlist']
assert 'terminalAllowlist' not in permissions and 'approvalMode' not in permissions
hooks=json.loads((base/'cursor home/hooks.json').read_bytes())['hooks']
config=json.loads((base/'cursor home/mcp.json').read_bytes())['mcpServers']['ai-security-runtime']
env['CURSOR_PROJECT_DIR']=str(project)
def hook(event,**extra):
    payload=dict(conversation_id='smoke-session',generation_id='smoke-turn',hook_event_name=event,workspace_roots=['project'],**extra)
    p=subprocess.run(hooks[event][0]['command'],input=json.dumps(payload).encode(),env=env,capture_output=True,timeout=130)
    assert p.returncode==0,(event,p.stderr[-1000:])
    value=json.loads(p.stdout);print(event, sorted(value));return value
assert hook('preToolUse',tool_name='Read',tool_use_id='read',tool_input={})=={'permission':'allow'}
assert hook('stop',status='completed',loop_count=0)=={}
prepared_ref=None
if args.mcp_begin:
    begin_input=dict(workspace_path=str(project),task_key='native-mcp-task')
    assert hook('preToolUse',tool_name='MCP:begin_security_task',tool_use_id={},tool_input=begin_input)=={'permission':'allow'}
    async def begin():
        params=StdioServerParameters(command=config['command'],args=config['args'],env={**env,**config['env']})
        async with stdio_client(params) as (reader,writer):
            async with ClientSession(reader,writer) as session:
                await session.initialize()
                result=await session.call_tool('begin_security_task',begin_input)
                data=result.structuredContent or json.loads(result.content[0].text)
                assert not result.isError and data['status']=='ACTIVE',data
                return data['task_ref']
    prepared_ref=asyncio.run(begin())
    assert prepared_ref in hook('postToolUse',tool_name='MCP:begin_security_task',tool_use_id={})['additional_context']
write_id={} if args.diagnostic_tool_id else '' if args.empty_tool_id else 'write'
assert hook('preToolUse',tool_name='Write',tool_use_id=write_id,tool_input={})=={'permission':'allow'}
(project/'sample.py').write_text('value = 2\n')
hook('afterFileEdit',file_path=str(project/'sample.py'))
post=hook('postToolUse',tool_name='Write',tool_use_id=write_id)
assert 'additional_context' in post and 'ts1-' in post['additional_context'],post
binding=json.loads(post['additional_context'].splitlines()[1])
ref,session_ref=binding['task_ref'],binding['session_ref']
if prepared_ref is not None:
    assert ref==prepared_ref
follow=hook('stop',status='completed',loop_count=0)
assert ref in follow['followup_message']
assert hook('stop',status='completed',loop_count=0)=={}
async def run():
    params=StdioServerParameters(command=config['command'],args=config['args'],env={**env,**config['env']})
    async with stdio_client(params) as (reader,writer):
        async with ClientSession(reader,writer) as session:
            await session.initialize()
            tools=(await session.list_tools()).tools
            names={t.name for t in tools}
            assert all(entry.split(':',1)[1] in names for entry in permissions['mcpAllowlist'])
            assert 'handle_hook_event' not in names and 'prepare_functional_verification' not in names
            async def call(name,**args):
                arguments = ({} if name == 'get_runtime_info' else
                             dict(workspace_path=str(project),session_ref=session_ref))
                arguments.update(args)
                value=await session.call_tool(name,arguments)
                data=value.structuredContent or json.loads(value.content[0].text)
                assert not value.isError,(name,data)
                return data
            require_v3(await call('get_runtime_info'), names)
            finished=await call('finish_security_task',task_ref=ref)
            packet=await call('prepare_task_security_review',task_ref=ref,protocol_version=3)
            assert finished['status']=='READY',finished
            assert packet['review_required'],packet
            review=V3Review(call,ref,packet['review_session'],project)
            units=await review.plan()
            assert [unit['path'] for unit in units]==['sample.py']
            await review.read('sample.py',1,1)
            submitted,pages=await review.save_partial([],
                ['Process smoke and requested source only; no observed host model reasoning.'])
            (base/'task-result.json').write_text(json.dumps(dict(receipt=submitted,history_pages=pages),ensure_ascii=True,indent=2))
            print('MCP task status', submitted['status'], 'coverage', pages[0]['host_review']['coverage'])
asyncio.run(run())
assert hook('stop',status='completed',loop_count=0)=={}
removed=subprocess.run([config['command'],'integration','remove','cursor','--scope','global','--json'],
    env=env,capture_output=True,timeout=60)
assert removed.returncode==0,removed.stderr[-1000:]
assert json.loads(removed.stdout)['overall']=='REMOVED'
assert not (base/'cursor home/permissions.json').exists()
print('NATIVE_CURSOR_SMOKE_PASSED')
