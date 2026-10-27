"""Isolated real stdio/scan check with synthetic Pre/Post claims, not desktop proof."""
import argparse
import asyncio
from datetime import timedelta
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def unpack(response):
    assert not response.isError, 'Isolated MCP request failed'
    return response.structuredContent or json.loads(response.content[0].text)


async def verify(parent):
    root, home = parent/'project', parent/'home'
    (root/'src').mkdir(parents=True)
    (root/'src/historical.py').write_text('morning = 1\n')
    env = dict(os.environ,CODEX_HOME=str(home),SECURITY_RUNTIME_STATE_DIR=str(parent/'private'),
        SECURITY_RUNTIME_SKILLS_DIR=str(parent/'skills'),SECURITY_RUNTIME_OFFLINE='1',
        SECURITY_RUNTIME_WORKSPACE='',SECURITY_RUNTIME_GLOBAL='0',SECURITY_RUNTIME_DEVELOPMENT_WAIT_SECONDS='20')
    for key in ('SECURITY_RUNTIME_CODEX_HOME','SECURITY_RUNTIME_INTEGRATION'):
        env.pop(key,None)
    flags = {'creationflags':subprocess.CREATE_NO_WINDOW} if os.name == 'nt' else {}
    subprocess.run(['git','init','-q',str(root)],check=True,capture_output=True,timeout=30,**flags)
    setup = subprocess.run([sys.executable,'-m','security_runtime.cli','setup','codex','--dev',
        '--path',str(root),'--json'],env=env,cwd=parent,capture_output=True,timeout=120,**flags)
    assert setup.returncode == 0, 'Isolated setup failed'
    entry = tomllib.loads((home/'config.toml').read_text())['mcp_servers']['ai_security_runtime']
    params = StdioServerParameters(command=entry['command'],args=entry['args'],env={**env,**entry['env']})
    session = 'synthetic-watchfiles-stdio'
    common = dict(workspace_path=str(root))
    async with stdio_client(params) as (read,write):
        async with ClientSession(read,write,read_timeout_seconds=timedelta(seconds=120)) as client:
            await client.initialize()
            async def call(tool,**args):
                return unpack(await client.call_tool(tool,{**common,**args}))
            ready = await call('handle_readiness_event',event='SessionStart',session_id=session)
            token = ready['task_session_ref']
            info = unpack(await client.call_tool('get_runtime_info',dict(view='summary')))
            assert info['features']['development_file_watch'].startswith('development-file-watch-v1;')
            check = await call('begin_development_check',task_key='watchfiles-stdio',session_ref=token)
            ref = check['check_ref']
            args = dict(session_id=session,turn_id='fixture-turn',tool_use_id='fixture-script',
                tool_name='Bash',tool_input={'command':'python opaque_script.py'})
            before = await call('handle_before_hook_event',event='PreToolUse',**args)
            assert before['file_watch']['status'] == 'ACTIVE'
            source = "from pathlib import Path; import sys; r=Path(sys.argv[1]); (r/'src/one.py').write_text('one = 1'); (r/'src/two.py').write_text('two = 2')"
            subprocess.run([sys.executable,'-B','-c',source,str(root)],check=True,capture_output=True,timeout=30,**flags)
            post = await call('handle_hook_event',event='PostToolUse',**args)
            assert post['host_claim_status'] == 'VALID' and not post['scanner_run']
            result = await call('complete_development_check',check_ref=ref,session_ref=token)
            for _ in range(6):
                if result['status'] not in {'QUEUED','RUNNING'}:
                    break
                result = await call('wait_development_check',check_ref=ref,session_ref=token)
            assert result['status'] in {'RESULTS_READY','PARTIAL'}, result['status']
            assert result['scope']['paths'] == ['src/one.py','src/two.py']
            assert result['scope']['scope_unknown'] is False
            assert result['file_watch']['status'] == 'STOPPED'
            assert result['dirty_seq'] == result['scanned_seq'] and result['scan_id']
            saved = await call('get_development_check',check_ref=ref,session_ref=token)
            assert saved['scan_id'] == result['scan_id']
            return dict(contract='watchfiles-stdio-acceptance-v1',status='PASSED',
                build_id=info['build_identity']['build_id'],observed_paths=result['scope']['paths'],
                unobserved_historical_excluded=True,scope_unknown=False,final_seq=result['dirty_seq'],
                saved_seq=result['scanned_seq'],scan_status=result['scan_status'],scan_coverage=result['scan_coverage'],
                gaps=result['gaps'],native_desktop_hook_verified=False,
                boundary='REAL_STDIO_AND_SCOPED_SCAN; SYNTHETIC_HOST_CLAIMS; BENIGN_FILES; NO_MODEL_OR_CHAT_SPEED_CLAIM')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='asr-watchfiles-mcp-',ignore_cleanup_errors=True) as directory:
        base = Path(directory).absolute()
        assert base.parent == Path(tempfile.gettempdir()).absolute()
        result = asyncio.run(verify(base))
    result['temporary_cleanup'] = 'COMPLETE' if not base.exists() else 'PENDING_WINDOWS_RETIREMENT'
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,ensure_ascii=False))


if __name__ == '__main__':
    main()
