"""Reusable bounded subprocess capture. Raw output stays internal."""
from dataclasses import dataclass
import subprocess
import threading
import time
import os
import signal

from .progress import checkpoint


@dataclass(frozen=True)
class ProcessResult:
    return_code: int
    stdout: str
    stderr: str
    duration_ms: int

    @property
    def returncode(self):
        return self.return_code


class OutputLimitError(ValueError):
    pass


def run_process(args, *, cwd=None, env=None, timeout=30, max_output=4_000_000) -> ProcessResult:
    checkpoint()
    start = time.monotonic()
    proc = subprocess.Popen(args, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=os.name != 'nt')
    buffers = [bytearray(), bytearray()]
    overflow = threading.Event()

    def consume(stream, buffer):
        try:
            while chunk := stream.read1(4096):
                remaining = max_output - len(buffer)
                buffer.extend(chunk[:max(0, remaining)])
                if len(chunk) > remaining:
                    overflow.set()
                    # Drain and discard until the parent kills the process.
        finally:
            stream.close()

    readers = [threading.Thread(target=consume, args=(stream, buffers[index]), daemon=True)
               for index, stream in enumerate((proc.stdout, proc.stderr))]
    for reader in readers:
        reader.start()
    failure = None
    try:
        while proc.poll() is None:
            checkpoint()
            if overflow.is_set():
                failure = OutputLimitError("scanner output limit exceeded")
                break
            if time.monotonic() - start >= timeout:
                failure = TimeoutError("process timed out")
                break
            time.sleep(.01)
    finally:
        if proc.poll() is None:
            if os.name == 'nt':
                # Kill engine helpers too; use the trusted system utility only.
                taskkill = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', 'taskkill.exe')
                try:
                    subprocess.run([taskkill, '/PID', str(proc.pid), '/T', '/F'],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
                except (OSError, subprocess.TimeoutExpired):
                    pass
                if proc.poll() is None:
                    proc.kill()
            else:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        proc.wait(timeout=5)
        for reader in readers:
            reader.join(timeout=1)
    if failure:
        raise failure
    if overflow.is_set():
        raise OutputLimitError("scanner output limit exceeded")
    if any(reader.is_alive() for reader in readers):
        raise TimeoutError("process output did not close")
    return ProcessResult(proc.returncode, *(bytes(buffer).decode('utf-8', errors='replace') for buffer in buffers),
                         round((time.monotonic() - start) * 1000))
