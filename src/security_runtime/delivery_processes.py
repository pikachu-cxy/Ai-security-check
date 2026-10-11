"""Read-only process inventory; uncertainty defers historical-slot cleanup."""
from __future__ import annotations

import os
from pathlib import Path


def running_slot_builds(root):
    versions = (Path(root) / 'versions').resolve()
    found = set()
    def observe(value):
        if Path(value).absolute().parent == Path(root).absolute() / 'launcher':
            found.add('@legacy-launcher')
        try:
            relative = Path(value).absolute().relative_to(versions)
            if relative.parts:
                found.add(relative.parts[0])
        except (ValueError, OSError):
            pass
    if os.name == 'nt':
        import ctypes
        from ctypes import wintypes
        class Entry(ctypes.Structure):
            _fields_ = [('dwSize', wintypes.DWORD), ('cntUsage', wintypes.DWORD),
                ('th32ProcessID', wintypes.DWORD), ('th32DefaultHeapID', ctypes.c_size_t),
                ('th32ModuleID', wintypes.DWORD), ('cntThreads', wintypes.DWORD),
                ('th32ParentProcessID', wintypes.DWORD), ('pcPriClassBase', wintypes.LONG),
                ('dwFlags', wintypes.DWORD), ('szExeFile', wintypes.WCHAR * 260)]
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        kernel.Process32FirstW.argtypes = kernel.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Entry)]
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        snapshot = kernel.CreateToolhelp32Snapshot(2, 0)
        if snapshot == ctypes.c_void_p(-1).value:
            return None
        try:
            entry = Entry(dwSize=ctypes.sizeof(Entry))
            ok = kernel.Process32FirstW(snapshot, ctypes.byref(entry))
            while ok:
                # Only this product's executable can keep a Runtime slot live.
                if entry.szExeFile.lower() in {'security-check.exe', 'security-launcher.exe'}:
                    handle = kernel.OpenProcess(0x1000, False, entry.th32ProcessID)
                    if not handle:
                        return None
                    try:
                        buffer, size = ctypes.create_unicode_buffer(32768), wintypes.DWORD(32768)
                        if not kernel.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
                            return None
                        observe(buffer.value)
                    finally:
                        kernel.CloseHandle(handle)
                ok = kernel.Process32NextW(snapshot, ctypes.byref(entry))
        finally:
            kernel.CloseHandle(snapshot)
        return found
    proc = Path('/proc')
    if not proc.is_dir():
        return None
    for process in proc.iterdir():
        if process.name.isdigit():
            try:
                observe((process / 'exe').resolve(strict=True))
            except FileNotFoundError:
                pass
            except OSError:
                return None
    return found
