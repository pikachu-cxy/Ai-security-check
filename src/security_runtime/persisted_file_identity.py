"""Validate historical inode identities without treating macOS mount IDs as permanent.

Only authenticated historical data (or private guard metadata) may supply the
saved identity and anchor. Live descriptor/path comparisons remain exact.
"""
from functools import lru_cache
import math
import os
import sys
import time


@lru_cache(maxsize=1)
def boot_time():
    if sys.platform != 'darwin':
        return None
    try:
        import ctypes
        class Timeval(ctypes.Structure):
            _fields_ = [('seconds', ctypes.c_long), ('microseconds', ctypes.c_int)]
        function = ctypes.CDLL(None, use_errno=True).sysctlbyname
        function.argtypes = [ctypes.c_char_p, ctypes.c_void_p,
                            ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t]
        function.restype = ctypes.c_int
        value, size = Timeval(), ctypes.c_size_t(ctypes.sizeof(Timeval))
        if function(b'kern.boottime', ctypes.byref(value), ctypes.byref(size), None, 0):
            return None
        if size.value != ctypes.sizeof(Timeval) or not 0 <= value.microseconds < 1_000_000:
            return None
        result = value.seconds + value.microseconds / 1_000_000
        return result if 0 < result <= time.time() else None
    except (AttributeError, OSError, TypeError, ValueError):
        return None


def historical_identity_matches(saved, info, *, anchor=None, captured_at=None):
    if (not isinstance(saved, (list, tuple)) or len(saved) != 2
            or any(type(n) is not int or n < 0 for n in saved)):
        return False
    if list(saved) == [info.st_dev, info.st_ino]:
        return True
    if saved[1] != info.st_ino or sys.platform != 'darwin':
        return False
    boot = boot_time()
    born = getattr(info, 'st_birthtime', None)
    if (boot is None or info.st_uid != os.getuid()
            or not isinstance(born, (int, float)) or not 0 < born < boot):
        return False
    if anchor is not None:
        return preboot_anchor(anchor)
    return (type(captured_at) in {int, float} and math.isfinite(captured_at)
            and 0 < captured_at < boot)


def preboot_anchor(info):
    boot = boot_time() if sys.platform == 'darwin' else None
    born = getattr(info, 'st_birthtime', None)
    return (boot is not None and info.st_uid == os.getuid()
            and isinstance(born, (int, float)) and 0 < born <= info.st_mtime < boot)
