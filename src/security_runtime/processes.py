"""Reusable bounded subprocess capture. Raw output stays internal."""
from dataclasses import dataclass
from dataclasses import field
import subprocess
import threading
import time
import os
import signal
from .preparation_budget import bounded_timeout

from .progress import checkpoint


@dataclass(frozen=True)
class ProcessResult:
    return_code: int
    stdout: str
    stderr: str
    duration_ms: int
    timing_ms: dict = field(default_factory=dict)

    @property
    def returncode(self):
        return self.return_code


class OutputLimitError(ValueError):
    pass


class ProcessIdleTimeout(TimeoutError):
    pass


class ProcessStartError(OSError):
    """Bounded launch facts without paths, argv, environment or raw OS text."""
    def __init__(self, error, *, cwd=None, executable=None):
        super().__init__('External process could not be started.')
        kind = type(error).__name__ if type(error).__module__ == 'builtins' else 'OSError'
        self.failure = dict(stage='PROCESS_START', exception_type=kind,
            errno=error.errno if type(error.errno) is int else None,
            winerror=getattr(error, 'winerror', None) if type(getattr(error, 'winerror', None)) is int else None,
            cwd_length=len(os.fspath(cwd)) if cwd is not None else 0,
            executable_length=len(os.fspath(executable)) if executable is not None else 0)


def run_process(args, *, cwd=None, env=None, timeout=30, max_output=4_000_000, on_stderr_line=None,
                idle_timeout=None, activity_clock=None, on_stderr_chunk=None, remaining_callback=None,
                capture_start_failure=False) -> ProcessResult:
    checkpoint()
    # A dynamic preparation deadline may grow, but the process's static ceiling
    # remains absolute. Ordinary scans retain their original timeout contract.
    timeout = bounded_timeout(timeout, hard=remaining_callback is not None)
    start = time.monotonic()
    creation_started = time.perf_counter()
    # Captured engine helpers must not create a Windows console, even when
    # launched by the detached preparation worker. Pipes still carry progress.
    creationflags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
    try:
        proc = subprocess.Popen(args, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                creationflags=creationflags, start_new_session=os.name != 'nt')
    except OSError as error:
        if not capture_start_failure:
            raise  # Installation/probe callers retain their OS exception types.
        raise ProcessStartError(error, cwd=cwd, executable=args[0] if args else None) from None
    creation_ms = round((time.perf_counter()-creation_started)*1000, 3)
    buffers = [bytearray(), bytearray()]
    overflow = threading.Event()

    def consume(stream, buffer, callback=None, chunk_callback=None):
        pending = b''
        discarded = False
        try:
            while chunk := stream.read1(4096):
                remaining = max_output - len(buffer)
                buffer.extend(chunk[:max(0, remaining)])
                if len(chunk) > remaining:
                    overflow.set()
                    # Drain and discard until the parent kills the process.
                if chunk_callback is not None:
                    try:
                        chunk_callback(chunk)
                    except Exception:
                        # Numeric observation failures cannot echo raw output.
                        pass
                if callback is not None:
                    pending += chunk
                    while b'\n' in pending or b'\r' in pending:
                        endings = [index for index in (pending.find(b'\n'), pending.find(b'\r')) if index >= 0]
                        index = min(endings)
                        line, pending = pending[:index], pending[index + 1:]
                        if line and not discarded and len(line) <= 256:
                            try:
                                callback(line.decode('utf-8', errors='replace').rstrip('\r'))
                            except Exception:
                                # Presentation failures cannot invalidate a receipt.
                                pass
                        discarded = False
                    if len(pending) > 256:
                        pending = b''
                        discarded = True
        finally:
            stream.close()

    readers = [threading.Thread(target=consume,
               args=(stream, buffers[index], on_stderr_line if index == 1 else None,
                   on_stderr_chunk if index == 1 else None), daemon=True)
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
            if (time.monotonic() - start >= timeout
                    or remaining_callback is not None and remaining_callback() <= 0):
                failure = TimeoutError("process timed out")
                break
            if (idle_timeout is not None and activity_clock is not None
                    and time.monotonic() - activity_clock() >= idle_timeout):
                failure = ProcessIdleTimeout('download made no progress')
                break
            time.sleep(.01)
    finally:
        if proc.poll() is None:
            if os.name == 'nt':
                # Kill engine helpers too; use the trusted system utility only.
                taskkill = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', 'taskkill.exe')
                try:
                    subprocess.run([taskkill, '/PID', str(proc.pid), '/T', '/F'],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   creationflags=subprocess.CREATE_NO_WINDOW, timeout=3)
                except (OSError, subprocess.TimeoutExpired):
                    pass
                if proc.poll() is None:
                    proc.kill()
            else:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except PermissionError:
                    # Some POSIX hosts deny group signalling during exit.
                    # Retain the deadline/output error and reap our own child.
                    if proc.poll() is None:
                        try:
                            proc.kill()
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
                         round((time.monotonic() - start) * 1000),
                         {'process_creation': creation_ms})
