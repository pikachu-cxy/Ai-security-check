"""One-time, explicit-install migration out of Windows AppData overlays.

Never invoked by a Hook, status read or MCP startup. Original trees are retained.
Divergent histories require an explicit source; SQLite stores are never merged.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile

from .hook_state import HookStateStore, atomic_bytes, no_links, native_io_path
from .integration_lifecycle import IntegrationDiagnostic
from .user_paths import windows_home, windows_root

CONTRACT = 'windows-user-directories-v1'
MESSAGES = {
    'LEGACY_USER_DIRECTORIES_CONFLICT_SELECT_APPDATA':
        '检测到不同的旧版用户数据，尚未覆盖或合并。请用 --legacy-appdata 指定保留为活动状态的 AppData 或 LocalCache 根目录；其他原件继续保留。',
    'LEGACY_DIRECTORY_REDIRECTED_RUN_EXTERNAL_INSTALLER':
        '旧数据读取被宿主重定向。请完全退出相关宿主，在普通 PowerShell 中运行安装脚本，再重新打开宿主。',
    'LEGACY_RUNTIME_STILL_RUNNING_CLOSE_HOSTS':
        '旧版服务仍在运行或无法确认已退出。请完全退出相关宿主后重试迁移；旧数据尚未删除。',
    'USER_DIRECTORY_DESTINATION_CONFLICT':
        '新目录已有不同的数据，迁移已停止并保留两份原件，请先核对要保留的状态。',
    'LEGACY_USER_DIRECTORIES_CHANGED':
        '迁移时旧数据发生变化，本次副本未发布。请停止旧版写入后重试。',
    'LEGACY_DIRECTORY_IDENTITY_UNKNOWN':
        '读取旧版用户数据目录时失败，文件可能在扫描过程中被其他程序删除或改写。请完全退出相关宿主后重试；'
        '如仍失败，可用 --legacy-appdata 指定要保留的 AppData 或 LocalCache 根目录。',
}
OVERRIDES = {'state': 'SECURITY_RUNTIME_STATE_DIR', 'data': 'SECURITY_RUNTIME_DATA_DIR',
             'config': 'SECURITY_RUNTIME_CONFIG'}


def _physical_file(stream, path):
    """Reject a legacy read redirected behind the installer's back."""
    if os.name != 'nt':
        return
    import ctypes
    import msvcrt
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    get = kernel.GetFinalPathNameByHandleW
    get.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
    get.restype = wintypes.DWORD
    buffer = ctypes.create_unicode_buffer(32768)
    size = get(msvcrt.get_osfhandle(stream.fileno()), buffer, len(buffer), 0)
    if not size or size >= len(buffer):
        raise IntegrationDiagnostic('LEGACY_DIRECTORY_IDENTITY_UNKNOWN')
    actual = buffer.value.removeprefix('\\\\?\\')
    expected = str(path.absolute()).removeprefix('\\\\?\\')
    if os.path.normcase(actual) != os.path.normcase(expected):
        raise IntegrationDiagnostic('LEGACY_DIRECTORY_REDIRECTED_RUN_EXTERNAL_INSTALLER')


def _inventory(root):
    root = native_io_path(root)
    if not root.exists():
        return {}
    no_links(root)
    result = {}
    for directory, directories, files in os.walk(root, followlinks=False):
        for name in directories:
            no_links(Path(directory) / name)
        for name in sorted(files):
            path = Path(directory) / name
            no_links(path)
            try:
                with path.open('rb') as stream:
                    _physical_file(stream, path)
                    result[str(path.relative_to(root))] = hashlib.file_digest(stream, 'sha256').hexdigest()
            except OSError as exc:
                # A legacy tree still written by a live host can lose a file
                # between enumeration and hashing. Report a fixed diagnostic
                # instead of letting a bare OSError read as a broken package.
                raise IntegrationDiagnostic('LEGACY_DIRECTORY_IDENTITY_UNKNOWN') from exc
    return result


def _sources(legacy_appdata=None):
    if legacy_appdata is not None:
        base = Path(legacy_appdata)
        if not base.is_absolute():
            raise IntegrationDiagnostic('LEGACY_APPDATA_MUST_BE_ABSOLUTE')
        no_links(base)
        if not base.is_dir() or not any((base / part).exists() for part in
                ('Local/AI Security Runtime', 'Local/AI-Security-Runtime', 'Roaming/ai-security-runtime')):
            raise IntegrationDiagnostic('LEGACY_APPDATA_UNAVAILABLE')
        bases = [(base / 'Local', base / 'Roaming')]
    else:
        home = windows_home()
        local = Path(os.getenv('LOCALAPPDATA', str(home / 'AppData/Local')))
        roaming = Path(os.getenv('APPDATA', str(home / 'AppData/Roaming')))
        bases = [(local, roaming)]
        packages = home / 'AppData/Local/Packages'
        if packages.is_dir():
            no_links(packages)
            # Only one directory level; no recursive package inventory.
            for package in packages.iterdir():
                cache = package / 'LocalCache'
                if any((cache / part).exists() for part in
                       ('Local/AI Security Runtime', 'Local/AI-Security-Runtime', 'Roaming/ai-security-runtime')):
                    no_links(cache)
                    bases.append((cache / 'Local', cache / 'Roaming'))
    return {
        'state': [local / 'AI Security Runtime' for local, _ in bases],
        'data': [local / 'AI-Security-Runtime' for local, _ in bases],
        'config': [roaming / 'ai-security-runtime' for _, roaming in bases],
    }, [local / 'ASR' for local, _ in bases]


def migrate_user_directories(*, legacy_appdata=None):
    base = windows_root()
    marker = base / 'user-directories.json'
    no_links(base)
    no_links(marker)
    completed = set()
    scan_store_sources = []
    wanted = {kind for kind, key in OVERRIDES.items() if not os.getenv(key)}
    if marker.is_file():
        # Constant work on repeat installs: never rescan old trees or processes.
        if marker.stat().st_size > 16384:
            raise IntegrationDiagnostic('USER_DIRECTORY_MIGRATION_INVALID')
        receipt = json.loads(marker.read_bytes())
        if receipt.get('contract') != CONTRACT or receipt.get('status') != 'COMPLETE':
            raise IntegrationDiagnostic('USER_DIRECTORY_MIGRATION_INVALID')
        completed = set(receipt.get('completed', []))
        scan_store_sources = receipt.get('scan_store_sources', [])
        if wanted <= completed:
            return receipt
    with HookStateStore(base / '.migration-lock').lock(base) as acquired:
        if not acquired:
            raise IntegrationDiagnostic('USER_DIRECTORY_MIGRATION_BUSY')
        sources, old_installs = _sources(legacy_appdata)
        if any(path.exists() for kind, paths in sources.items()
               if kind in wanted - completed for path in paths):
            from .delivery_processes import running_slot_builds
            for old in old_installs:
                if old.exists() and running_slot_builds(old, exclude_pid=os.getpid(), include_launchers=False) != set():
                    raise IntegrationDiagnostic('LEGACY_RUNTIME_STILL_RUNNING_CLOSE_HOSTS')
        planned = {}
        for kind, candidates in sources.items():
            if kind not in wanted or kind in completed:
                continue  # An explicit profile is never silently relocated.
            found = [(path, _inventory(path)) for path in dict.fromkeys(candidates) if path.exists()]
            found = [(path, inventory) for path, inventory in found if inventory]
            if not found:
                continue
            source, inventory = found[0]
            if any(other != inventory for _, other in found[1:]):
                raise IntegrationDiagnostic('LEGACY_USER_DIRECTORIES_CONFLICT_SELECT_APPDATA')
            destination = base / kind
            if destination.exists() and _inventory(destination) != inventory:
                raise IntegrationDiagnostic('USER_DIRECTORY_DESTINATION_CONFLICT')
            planned[kind] = (source, inventory)
        copied = []
        for kind, (source, inventory) in planned.items():
            destination = base / kind
            if not destination.exists():
                stage = Path(tempfile.mkdtemp(prefix='.migrate-', dir=base))
                # Do not copy an in-flight directory into the published state.
                # Both source and copy are rechecked before atomic publication.
                try:
                    def checked_copy(src, dst):
                        no_links(Path(src))
                        Path(dst).parent.mkdir(parents=True, exist_ok=True)
                        with Path(src).open('rb') as stream:
                            _physical_file(stream, Path(src))
                            with Path(dst).open('xb') as output:
                                shutil.copyfileobj(stream, output)
                        shutil.copystat(src, dst, follow_symlinks=False)
                        return dst
                    (stage / kind).mkdir()
                    for relative in inventory:
                        checked_copy(native_io_path(source / relative), native_io_path(stage / kind / relative))
                    if _inventory(source) != inventory or _inventory(stage / kind) != inventory:
                        raise IntegrationDiagnostic('LEGACY_USER_DIRECTORIES_CHANGED')
                    os.replace(stage / kind, destination)
                finally:
                    # Keep interrupted data for diagnosis, never delete a source.
                    if not any(stage.iterdir()):
                        stage.rmdir()
            copied.append(kind)
        receipt = {'contract': CONTRACT, 'status': 'COMPLETE', 'copied': copied,
                   'completed': sorted(completed | wanted),
                   'originals_retained': True,
                   'explicit_overrides': [kind for kind, key in OVERRIDES.items() if os.getenv(key)]}
        if 'state' in planned:
            source = planned['state'][0]
            scan_store_sources = [str(source / 'scans.db')]
            # Packaged hosts stored the logical AppData filename in signed
            # records even when their actual bytes lived in LocalCache.
            if 'LocalCache' in source.parts:
                scan_store_sources.append(str(windows_home() / 'AppData/Local/AI Security Runtime/scans.db'))
        receipt['scan_store_sources'] = scan_store_sources
        atomic_bytes(marker, json.dumps(receipt, sort_keys=True).encode())
        return receipt
