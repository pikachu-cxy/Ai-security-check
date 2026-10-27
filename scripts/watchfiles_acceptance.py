"""Windows/macOS repeatable path-capture experiment; not native Codex acceptance.

Creates an isolated 6,000-file Git repository and two real linked worktrees.
No dependency installation, target service, vulnerable code or scanner is run.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import time

from security_runtime.development_check import DevelopmentCheckService
from security_runtime.development_file_watch import start_window, _shutdown
from security_runtime.hook_state import HookStateStore
from security_runtime.tasks.ownership import session_owner


def run(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, timeout=90,
        **({'creationflags':subprocess.CREATE_NO_WINDOW} if os.name == 'nt' else {}), **kwargs)


def experiment(base):
    repository = base/'repository'
    repository.mkdir()
    for i in range(6000):
        path = repository/f'packages/p{i//100:02d}/file{i:04d}.py'
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(f'value = {i}\n')
    run(['git','init','-q',str(repository)])
    run(['git','-C',str(repository),'add','.'])
    run(['git','-C',str(repository),'-c','user.name=watchfiles-fixture',
         '-c','user.email=fixture@example.invalid','commit','-qm','safe fixture'])
    rows = []
    services = []
    for label in ('A','B'):
        root = base/f'worktree-{label}'
        run(['git','-C',str(repository),'worktree','add','--detach',str(root),'HEAD'])
        # Both are already dirty. Only one is touched during this task window.
        for number in (0,1):
            (root/f'packages/p00/file{number:04d}.py').write_text('morning = 1\n')
        hooks = HookStateStore(base/'private-hooks')
        owner = session_owner('codex',f'isolated-{label}')
        launches = []
        service = DevelopmentCheckService(None,hooks,owner=owner,
            scan_path_provider=base/'scans.db',launcher=lambda *_:launches.append('scan'))
        ref = service.begin(root,'watchfiles-worktrees')['check_ref']
        before = time.perf_counter()
        assert start_window(service.store(root),ref,owner) == 'ACTIVE'
        rows.append(dict(worktree=label,registration_ms=round((time.perf_counter()-before)*1000,3)))
        services.append((root,service,ref,launches))
    try:
        for label,(root,service,ref,launches) in zip(('A','B'),services):
            source = """import os,sys
from pathlib import Path
r=Path(sys.argv[1]); label=sys.argv[2]
(r/'packages/p00/file0000.py').write_text('morning = 2')
(r/f'generated-{label}').mkdir()
(r/f'generated-{label}'/'child.py').write_text('generated = 1')
(r/'packages/p00/file0002.py').unlink()
(r/'packages/p00/file0003.py').rename(r/f'renamed-{label}.py')
(r/'swap.tmp').write_text('atomic = 1')
os.replace(r/'swap.tmp',r/'packages/p00/file0004.py')
"""
            before = time.perf_counter()
            run([sys.executable,'-B','-c',source,str(root),label])
            rows[ord(label)-ord('A')]['child_write_ms'] = round((time.perf_counter()-before)*1000,3)
            assert launches == []
        for label,(root,service,ref,launches) in zip(('A','B'),services):
            before = time.perf_counter()
            finished = service.finish(root,ref)
            paths = set(finished['scope']['paths'])
            expected = {'packages/p00/file0000.py','packages/p00/file0002.py',
                'packages/p00/file0003.py','packages/p00/file0004.py',
                f'generated-{label}/child.py',f'renamed-{label}.py'}
            assert expected <= paths, (label,sorted(paths))
            assert 'packages/p00/file0001.py' not in paths
            other = 'B' if label == 'A' else 'A'
            assert not any(f'-{other}' in path for path in paths)
            assert not finished['scope']['scope_unknown']
            assert launches == ['scan']
            rows[ord(label)-ord('A')].update(drain_and_submit_ms=round((time.perf_counter()-before)*1000,3),
                observed_paths=sorted(paths),untouched_dirty_excluded=True,worktree_isolated=True,
                scan_during_edit=False,submit_count=len(launches))
    finally:
        _shutdown()
    return dict(contract='watchfiles-path-capture-experiment-v1',platform=platform.system(),
        python=platform.python_version(),watchfiles='1.3.0',tracked_files_per_worktree=6000,
        real_git_worktrees=True,native_desktop_hook_verified=False,scanner_run=False,
        timing_scope='PATH_REGISTRATION_AND_CAPTURE_ONLY; NO_SCAN_SPEEDUP_CLAIM',results=rows,status='PASSED')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    # Owned TemporaryDirectory is the only recursively cleaned target.
    with tempfile.TemporaryDirectory(prefix='asr-watchfiles-') as directory:
        base = Path(directory).absolute()
        assert base.parent == Path(tempfile.gettempdir()).absolute()
        result = experiment(base)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,ensure_ascii=False))


if __name__ == '__main__':
    main()
