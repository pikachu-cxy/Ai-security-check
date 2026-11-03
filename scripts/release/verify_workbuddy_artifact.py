"""Focused frozen WorkBuddy install/Hook/MCP/Stop contract; no desktop claim."""
from __future__ import annotations
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from security_runtime._version import __version__
from security_runtime.toolchain import platform_key
from verify_artifact import extract, verification_environment


def main(archive):
    archive=archive.resolve()
    with tempfile.TemporaryDirectory(prefix='asr-workbuddy-artifact-') as temporary:
        root=Path(temporary).resolve()
        extract(archive,root)
        bundle=root/'security-check'
        metadata=json.loads((bundle/'version.json').read_text())
        assert metadata['version']==__version__ and metadata['source_dirty'] is False
        executable=bundle/('security-check.exe' if os.name=='nt' else 'security-check')
        home=root/'workbuddy-home'
        home.mkdir()
        (home/'settings.json').write_text(json.dumps(dict(theme='preserved')))
        (home/'mcp.json').write_text(json.dumps(dict(mcpServers={'other':dict(command='preserved')})))
        env=verification_environment(root,root/'data',full=False)
        env['SECURITY_RUNTIME_WORKBUDDY_HOME']=str(home)
        (root/'config.toml').write_text('schema_version = 1\n')
        env['SECURITY_RUNTIME_CONFIG']=str(root/'config.toml')
        def command(*args,payload=None):
            completed=subprocess.run([str(executable),*args],input=json.dumps(payload) if payload is not None else None,
                text=True,capture_output=True,env=env,cwd=root,timeout=300)
            assert completed.returncode in {0,2}, completed.stderr[-1500:]
            return json.loads(completed.stdout)
        install=command('install','workbuddy','--root',str(root/'installed'),'--offline','--json')
        assert install['installation']['local_files_ready'], install
        # Use the installed command for status/Hook/MCP so its desired fingerprint
        # agrees with the committed stable launcher rather than the portable copy.
        entry=json.loads((home/'mcp.json').read_text())['mcpServers']['ai-security-runtime']
        executable=Path(entry['command'])
        assert command('integration','status','workbuddy','--scope','global','--json')['overall']=='CONFIGURED'
        assert (home/'skills/ai-security-review/SKILL.md').is_file()
        project=root/'project'; project.mkdir()
        subprocess.run(['git','init','-q',str(project)],check=True)
        file=project/'sample.py';file.write_text('value = 1\n')
        packet=dict(hook_event_name='PreToolUse',session_id='artifact-session',generation_id='artifact-turn',
            cwd=str(project),tool_name='Write',tool_use_id='artifact-call',tool_input=dict(file_path=str(file)))
        assert command('workbuddy-hook',payload=dict(hook_event_name='SessionStart',session_id='artifact-session'))=={}
        command('workbuddy-hook',payload=packet)
        file.write_text('value = 2\n')
        packet['hook_event_name']='PostToolUse'
        post=command('workbuddy-hook',payload=packet)['hookSpecificOutput']
        context=post['additionalContext']
        import re
        session=re.search(r'"session_ref":\s*"([^"]+)"',context).group(1)
        check=re.search(r'"check_ref":\s*"([^"]+)"',context).group(1)
        stop=dict(hook_event_name='Stop',session_id='artifact-session',generation_id='artifact-turn',
                  cwd=str(project),stop_hook_active=False)
        first=command('workbuddy-hook',payload=stop)
        assert first.get('decision')=='block', first
        stop['stop_hook_active']=True
        command('workbuddy-hook',payload=stop)
        assert command('workbuddy-hook',payload=stop).get('decision')!='block'
        async def mcp():
            from mcp import ClientSession, StdioServerParameters
            from mcp.client.stdio import stdio_client
            params=StdioServerParameters(command=str(executable),args=['mcp'],env={**env,**entry['env']})
            async with stdio_client(params) as (reader,writer):
                async with ClientSession(reader,writer) as client:
                    await client.initialize()
                    names={t.name for t in (await client.list_tools()).tools}
                    assert {'get_runtime_info','finish_development_check','get_development_check'}<=names
                    assert 'handle_hook_event' not in names
                    result=await client.call_tool('get_development_check',dict(check_ref=check,session_ref=session,workspace_path=str(project)))
                    data=result.structuredContent or json.loads(result.content[0].text)
                    assert not result.isError and data.get('check_ref')==check, data
                    return sorted(names)
        names=asyncio.run(mcp())
        assert command('integration','remove','workbuddy','--scope','global','--json')['overall']=='REMOVED'
        assert json.loads((home/'settings.json').read_text())==dict(theme='preserved')
        assert json.loads((home/'mcp.json').read_text())==dict(mcpServers={'other':dict(command='preserved')})
        record=dict(version=__version__,source_commit=metadata['source_commit'],platform='-'.join(platform_key()),
            archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),smoke=True,mcp_tools=names,
            validation_scope='workbuddy-adapter',workbuddy_connector=True,
            workbuddy_native_desktop=False,managed_engines=False,
            checked=['frozen-install','settings-preservation','native-edit-record','owner-bound-mcp',
                     'bounded-stop','owned-uninstall'])
        archive.with_name(archive.name+'.verification.json').write_text(json.dumps(record,indent=2)+'\n')
        print('WorkBuddy frozen adapter checks passed; desktop/scanner acceptance remains separate.')


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('archive',type=Path)
    main(parser.parse_args().archive)
