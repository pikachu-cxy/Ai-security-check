"""Invocation-local scratch space for native engines; never change host settings."""
from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import secrets
import shutil
import tempfile
import uuid

from .diagnostics import DiagnosticError, ErrorDiagnostic
from .hook_state import no_links
from .private_directories import windows_private_directory

# Reserve room for OCaml/Semgrep's own temporary directory and socket filename.
# This is a UTF-8 address budget, independent of Win32's normal file path limit.
SEMGREP_TEMP_PATH_BYTES = 60
WINDOWS = os.name == 'nt'


def _temp_failure(code='ENGINE_TEMP_DIRECTORY_UNAVAILABLE'):
    return DiagnosticError(ErrorDiagnostic(code,
        'A private, short engine temporary directory could not be prepared.',
        'Check local directory permissions or set SECURITY_RUNTIME_ENGINE_TEMP_ROOT '
        'to an existing short local directory outside the project.'))


def _windows_temp_parent():
    """Use the account's OS-known local folder, independently of TEMP/TMP."""
    import ctypes
    from ctypes import wintypes
    shell = ctypes.WinDLL('shell32', use_last_error=True)
    ole = ctypes.WinDLL('ole32', use_last_error=True)
    get_folder = shell.SHGetKnownFolderPath
    get_folder.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.HANDLE,
                           ctypes.POINTER(wintypes.LPWSTR)]
    get_folder.restype = ctypes.c_long
    ole.CoTaskMemFree.argtypes = [ctypes.c_void_p]
    folder = ctypes.create_string_buffer(uuid.UUID('f1b32785-6fba-4fcf-9d55-7b8e7f157091').bytes_le)
    value = wintypes.LPWSTR()
    try:
        if get_folder(folder, 0, None, ctypes.byref(value)) != 0 or not value:
            raise OSError('Local temporary folder unavailable')
        return Path(value.value) / 'Temp'
    finally:
        if value:
            ole.CoTaskMemFree(value)


def _short_path(path):
    """An existing 8.3 spelling may help; never create an alias or a junction."""
    import ctypes
    from ctypes import wintypes
    function = ctypes.WinDLL('kernel32', use_last_error=True).GetShortPathNameW
    function.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    function.restype = wintypes.DWORD
    needed = function(str(path), None, 0)
    if not 0 < needed <= 32768:
        return path
    buffer = ctypes.create_unicode_buffer(needed)
    length = function(str(path), buffer, needed)
    return Path(buffer.value) if 0 < length < needed else path


def _temporary_parent(environment, workspace):
    configured = environment.get('SECURITY_RUNTIME_ENGINE_TEMP_ROOT')
    parent = Path(configured) if configured else _windows_temp_parent()
    # UNC/device paths and relative overrides have unsuitable socket semantics.
    if not parent.is_absolute() or str(parent).startswith('\\\\'):
        raise _temp_failure()
    no_links(parent)
    parent = parent.resolve(strict=True)
    if not parent.is_dir():
        raise _temp_failure()
    if workspace is not None:
        root = Path(workspace).resolve(strict=True)
        if parent == root or parent.is_relative_to(root):
            raise _temp_failure()
    name_budget = '/r-' + '0' * 12
    if len((str(parent) + name_budget).encode('utf-8')) > SEMGREP_TEMP_PATH_BYTES:
        alias = _short_path(parent)
        no_links(alias)
        if alias.resolve(strict=True) != parent:
            raise _temp_failure()
        parent = alias
    if len((str(parent) + name_budget).encode('utf-8')) > SEMGREP_TEMP_PATH_BYTES:
        raise _temp_failure('ENGINE_TEMP_PATH_TOO_LONG')
    return parent


@contextmanager
def engine_environment(engine_id, environment, *, workspace=None):
    """Yield a fixed child environment, with one private scratch dir per scan.

    Other engines retain their existing environment. The parent is
    never chmod'ed, removed, or used as a workspace fallback. Cleanup addresses
    only the exact directory created here, after checking its file identity.
    """
    child = dict(environment)
    if engine_id != 'semgrep':
        yield child
        return
    directory = None
    identity = None
    try:
        try:
            if WINDOWS:
                parent = _temporary_parent(child, workspace)
            else:
                parent = Path(child.get('SECURITY_RUNTIME_ENGINE_TEMP_ROOT') or tempfile.gettempdir())
                if not parent.is_absolute():
                    raise _temp_failure()
                parent = parent.resolve(strict=True)
                no_links(parent)
                if not parent.is_dir() or (workspace is not None and
                        parent.is_relative_to(Path(workspace).resolve(strict=True))):
                    raise _temp_failure()
            for _ in range(8):
                candidate = parent / ('r-' + secrets.token_hex(6))
                try:
                    if WINDOWS:
                        windows_private_directory(candidate)
                    else:
                        candidate.mkdir(mode=0o700)
                except FileExistsError:
                    continue
                directory = candidate
                no_links(directory)
                info = directory.stat()
                identity = info.st_dev, info.st_ino
                break
            if directory is None:
                raise _temp_failure()
        except (OSError, ValueError) as error:
            if isinstance(error, DiagnosticError):
                raise
            raise _temp_failure() from None
        # Keep the user's settings readable but never let the engine rewrite
        # them or its shared home log, including during a version-only probe.
        from .component_health import _settings_bytes
        try:
            _, settings, _ = _settings_bytes(child)
        except (OSError, ValueError):
            raise DiagnosticError(ErrorDiagnostic('COMPONENT_SETTINGS_UNREADABLE',
                'Semgrep settings cannot be read safely.',
                'Check the selected settings file; no settings were replaced.')) from None
        config = directory / '.semgrep'
        config.mkdir(mode=0o700)
        settings_path = config / 'settings.yml'
        settings_path.write_bytes(settings if settings is not None else b'{}\n')
        child.update(SEMGREP_LOG_FILE=str(config / 'semgrep.log'),
            SEMGREP_SETTINGS_FILE=str(settings_path), XDG_CONFIG_HOME=str(directory))
        if WINDOWS:
            # Python checks TMPDIR first; Win32 checks TMP before TEMP.
            child.update(TEMP=str(directory), TMP=str(directory), TMPDIR=str(directory))
        yield child
    finally:
        if directory is not None and identity is not None:
            try:
                no_links(directory)
                info = directory.stat()
                if (info.st_dev, info.st_ino) != identity:
                    raise _temp_failure()
                shutil.rmtree(directory)
            except FileNotFoundError:
                pass
            except (OSError, ValueError):
                raise _temp_failure() from None
