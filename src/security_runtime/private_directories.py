"""OS-level private directory creation, independent of scan input/lifecycle."""
from .hook_state import native_io_path


def windows_private_directory(path):
    """Create with an owner/System DACL before writing any private bytes."""
    import ctypes
    from ctypes import wintypes

    class SecurityAttributes(ctypes.Structure):
        _fields_ = [('length', wintypes.DWORD), ('descriptor', ctypes.c_void_p),
                    ('inherit', wintypes.BOOL)]

    advapi = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
                        ctypes.POINTER(wintypes.ULONG)]
    convert.restype = wintypes.BOOL
    create = kernel.CreateDirectoryW
    create.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(SecurityAttributes)]
    create.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    descriptor = ctypes.c_void_p()
    token = wintypes.HANDLE()
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                         wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
        raise OSError('Private directory unavailable')
    user_string = wintypes.LPWSTR()
    try:
        needed = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        if not 1 <= needed.value <= 65_536:
            raise OSError('Private directory unavailable')
        buffer = ctypes.create_string_buffer(needed.value)
        if not advapi.GetTokenInformation(token, 1, buffer, needed.value, ctypes.byref(needed)):
            raise OSError('Private directory unavailable')
        sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p)).contents.value
        if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(user_string)):
            raise OSError('Private directory unavailable')
        user = user_string.value
    finally:
        if user_string:
            kernel.LocalFree(user_string)
        kernel.CloseHandle(token)
    security = f'O:{user}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{user})'
    if not convert(security, 1, ctypes.byref(descriptor), None):
        raise OSError('Private directory unavailable')
    try:
        attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
        if not create(str(native_io_path(path)), ctypes.byref(attributes)):
            if ctypes.get_last_error() == 183:
                raise FileExistsError()
            raise OSError('Private directory unavailable')
    finally:
        kernel.LocalFree(descriptor)
