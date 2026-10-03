"""Fail-closed local execution. Offline flags alone are NOT a sandbox.

Linux requires bubblewrap plus a delegated cgroup v2. Other platforms return
NOT_AVAILABLE; no permissive direct-process fallback exists. Builds use a
transient bounded workspace projection, never the live remediation workspace.
"""
from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

TIMEOUT = 60
MAX_OUTPUT = 65536  # combined stdout + stderr; contents never leave this module
MAX_PROCESSES = 32
MAX_MEMORY = 1073741824
TOTAL_TIMEOUT = 180
ISOLATION_VERSION = 'bwrap-cgroup-v1'


class Unavailable(ValueError): pass


class LocalSandbox:
    """Runtime-owned backend; no host-supplied sandbox/command/network override."""
    def availability(self):
        if sys.platform != 'linux': return 'ENFORCED_LOCAL_SANDBOX_UNAVAILABLE'
        if not shutil.which('bwrap'): return 'BUBBLEWRAP_UNAVAILABLE'
        try:
            text = Path('/proc/self/cgroup').read_text()
            entry = next(line[3:] for line in text.splitlines() if line.startswith('0::'))
            self.delegate = Path('/sys/fs/cgroup') / entry.lstrip('/')
            self.delegate.resolve().relative_to(Path('/sys/fs/cgroup'))
            if not os.access(self.delegate, os.W_OK): return 'CGROUP_DELEGATION_UNAVAILABLE'
        except (OSError, ValueError, StopIteration): return 'CGROUP_DELEGATION_UNAVAILABLE'
        return None

    @contextmanager
    def limits(self):
        reason = self.availability()
        if reason: raise Unavailable(reason)
        group = Path(tempfile.mkdtemp(prefix='asr-functional-',dir=self.delegate))
        try:
            for name,value in [('pids.max',MAX_PROCESSES),('memory.max',MAX_MEMORY),('memory.swap.max',0)]:
                (group/name).write_text(str(value))
                if (group/name).read_text().strip() != str(value): raise Unavailable('CGROUP_LIMIT_NOT_ENFORCED')
            if not (group/'cgroup.kill').exists(): raise Unavailable('CGROUP_KILL_UNAVAILABLE')
            yield group
        except OSError as error:
            raise Unavailable('CGROUP_LIMIT_UNAVAILABLE') from error
        finally:
            try: (group/'cgroup.kill').write_text('1')
            except OSError: pass
            try: group.rmdir()
            except OSError: pass

    @staticmethod
    def command(copy, argv, provider):
        executable = argv[0]
        if not executable.startswith('./') and not Path(executable).resolve().is_relative_to(Path('/usr').resolve()):
            # Do not expose arbitrary home directories or host tool caches.
            raise Unavailable('TOOL_OUTSIDE_ISOLATED_RUNTIME')
        bwrap = shutil.which('bwrap')
        if not bwrap: raise Unavailable('BUBBLEWRAP_UNAVAILABLE')
        args = [bwrap,'--unshare-all','--disable-userns','--die-with-parent','--new-session',
                '--cap-drop','ALL','--clearenv','--ro-bind','/usr','/usr']
        for name in ('bin','sbin','lib','lib64'):
            path = Path('/'+name)
            if path.is_symlink(): args += ['--symlink',os.readlink(path),'/'+name]
            elif path.exists(): args += ['--ro-bind',str(path),str(path)]
        args += ['--dir','/etc']
        if Path('/etc/ld.so.cache').is_file(): args += ['--ro-bind','/etc/ld.so.cache','/etc/ld.so.cache']
        # Only public JDK runtime configuration; no host /etc or user settings.
        for path in sorted(Path('/etc').glob('java-*-openjdk')):
            if path.is_dir(): args += ['--ro-bind',str(path),str(path)]
        args += ['--proc','/proc','--dev','/dev','--tmpfs','/tmp','--dir','/home',
                 '--dir','/home/verifier','--ro-bind',str(copy),'/workspace']
        # Build artifacts live on memory-backed mounts bounded by memory.max.
        # Project sources/configs stay read-only even inside the projection.
        for name in ('target','build','.gradle','dist','.pytest_cache'):
            (copy/name).mkdir(exist_ok=True)
            args += ['--tmpfs','/workspace/'+name]
        args += ['--chdir','/workspace',
                 '--setenv','HOME','/home/verifier','--setenv','PATH','/usr/local/bin:/usr/bin:/bin',
                 '--setenv','LANG','C.UTF-8','--setenv','PYTEST_DISABLE_PLUGIN_AUTOLOAD','1',
                 '--setenv','PYTHONNOUSERSITE','1','--setenv','PIP_NO_INDEX','1',
                 '--setenv','npm_config_offline','true','--setenv','npm_config_ignore_scripts','true',
                 '--setenv','JAVA_TOOL_OPTIONS','-Xmx256m -XX:ActiveProcessorCount=2']
        # Existing artifact caches are read-only, not credentials/settings files.
        cache = Path.home()/'.m2/repository'
        if provider == 'maven' and cache.is_dir():
            from .hook_state import no_links
            no_links(cache)
            args += ['--dir','/home/verifier/.m2','--ro-bind',str(cache),'/home/verifier/.m2/repository',
                     '--setenv','MAVEN_OPTS','-Duser.home=/home/verifier']
        # No Gradle cache mount in v0.1: never expose user init scripts/properties.
        return [*args,'--',*argv]

    def run(self, copy, step, *, timeout=TIMEOUT):
        with self.limits() as group:
            argv = self.command(copy,step.argv(),step.provider)
            fd = os.open(group/'cgroup.procs',os.O_WRONLY)
            try:
                def enter():
                    # Only async-safe OS operations before exec, no project code.
                    os.write(fd,b'0')
                observed=bounded_run(argv,copy,preexec_fn=enter,pass_fds=(fd,),timeout=timeout)
                if ((group/'memory.events').exists() and any(
                        line.startswith('oom_kill ') and line.split()[1]!='0'
                        for line in (group/'memory.events').read_text().splitlines())):
                    observed['reason']='MEMORY_LIMIT'
                if ((group/'pids.events').exists() and any(
                        line.startswith('max ') and line.split()[1]!='0'
                        for line in (group/'pids.events').read_text().splitlines())):
                    observed['reason']='PROCESS_LIMIT'
                return observed
            finally: os.close(fd)


def bounded_run(argv, cwd, *, preexec_fn=None, pass_fds=(), timeout=TIMEOUT, max_output=MAX_OUTPUT):
    """Internal transport only, never exposed as an arbitrary-command API."""
    start = time.monotonic()
    proc = subprocess.Popen(argv,cwd=cwd,env={'PATH':os.defpath},stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=False,
                            start_new_session=True,preexec_fn=preexec_fn,pass_fds=pass_fds)
    output = bytearray()
    lock = threading.Lock()
    overflow = threading.Event()
    def read(stream):
        try:
            while chunk := stream.read1(4096):
                with lock:
                    remaining=max_output-len(output)
                    output.extend(chunk[:max(0,remaining)])
                    if len(chunk)>remaining: overflow.set()
        finally: stream.close()
    readers=[threading.Thread(target=read,args=(s,),daemon=True) for s in (proc.stdout,proc.stderr)]
    for thread in readers: thread.start()
    reason=None
    try:
        while proc.poll() is None:
            if overflow.is_set(): reason='OUTPUT_LIMIT'; break
            if time.monotonic()-start>=timeout: reason='TIMEOUT'; break
            time.sleep(.01)
    finally:
        # Kill the process group even if the parent exited leaving helpers.
        if os.name != 'nt':
            try: os.killpg(proc.pid,signal.SIGKILL)
            except ProcessLookupError: pass
        elif proc.poll() is None:
            proc.kill()  # unit transport tests only; Windows sandbox never executes
        proc.wait(timeout=5)
        for thread in readers: thread.join(timeout=1)
    if any(t.is_alive() for t in readers): reason='OUTPUT_DID_NOT_CLOSE'
    if overflow.is_set(): reason='OUTPUT_LIMIT'
    return dict(exit_code=proc.returncode,output=bytes(output),reason=reason,
                duration_ms=round((time.monotonic()-start)*1000))
