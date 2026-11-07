"""Cheap shared exclusions for installed dependencies and compiled artifacts."""
from pathlib import Path

# These are installation/cache locations, not source-language directories.
# Keep manifests and lockfiles outside them, including extensionless inputs.
INSTALLATION_DIRS = frozenset({
    '.venv', 'venv', 'env', 'node_modules', 'vendor',
    '.runtime', 'site-packages', 'dist-packages', '__pypackages__',
    '.tox', '.nox', '.eggs', '.npm', '.pnpm-store', '.gradle', '.m2',
})
_NATIVE = (b'\x7fELF', b'MZ', b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe',
           b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe', b'\xca\xfe\xba\xbe',
           b'\xbe\xba\xfe\xca', b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca')
_COMPILED = {
    **dict.fromkeys(('.so', '.dylib', '.dll', '.pyd', '.exe', '.o'), _NATIVE),
    '.obj': _NATIVE + (b'\x4c\x01', b'\x64\x86', b'\x64\xaa'),
    '.a': (b'!<arch>\n', b'!<thin>\n'), '.lib': (b'!<arch>\n',),
    '.class': (b'\xca\xfe\xba\xbe',), '.wasm': (b'\x00asm',),
    '.pyc': (), '.pyo': (),
}


def is_compiled_artifact(path: Path) -> bool:
    """Inspect at most eight bytes, only for a compiled-file name.

    Caller validates workspace containment and symlinks before calling.
    Unknown/unreadable content remains eligible for normal scan validation.
    Archives such as JAR remain available to dependency analyzers.
    """
    suffix = path.suffix.lower()
    if suffix not in _COMPILED:
        stem, marker, version = path.name.lower().rpartition('.so.')
        if not (stem and marker and version and all(p.isdigit() for p in version.split('.'))):
            return False
        suffix = '.so'
    try:
        with path.open('rb') as stream:
            prefix = stream.read(8)
    except OSError:
        return False
    if suffix in {'.pyc', '.pyo'}:
        return len(prefix) >= 4 and prefix[2:4] == b'\r\n' and prefix[0:1] != b'\x00'
    return prefix.startswith(_COMPILED[suffix])
