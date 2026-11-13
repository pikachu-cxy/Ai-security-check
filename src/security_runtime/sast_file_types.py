"""Name-based capabilities for already selected SAST inputs (OpenGrep 1.32)."""
from dataclasses import dataclass
from pathlib import PurePosixPath
import re
from types import MappingProxyType


POLICY_VERSION = 'sast-file-types-v1'
NATIVE = 'NATIVE'
TS_PROJECTION = 'TS_PROJECTION'
VUE_SCRIPT = 'VUE_SCRIPT'
TEXT = 'TEXT'
TEXT_LANGUAGES = frozenset({'generic', 'regex'})


@dataclass(frozen=True)
class FileCapability:
    language: str
    mode: str
    reason: str = ''

    @property
    def analyzers(self):
        if self.language == 'typescript' and self.mode in {NATIVE, TS_PROJECTION}:
            return ('typescript', 'javascript')
        if self.mode == VUE_SCRIPT:
            return ('javascript', 'typescript')
        return (self.language,) if self.mode == NATIVE else ()


_NATIVE_SUFFIXES = {
    'python': ('.py', '.pyi'), 'java': ('.java',), 'javascript': ('.js', '.jsx', '.mjs', '.cjs'),
    'typescript': ('.ts', '.tsx'), 'go': ('.go',), 'php': ('.php', '.phtml'),
    'apex': ('.cls', '.trigger'), 'bash': ('.sh', '.bash'), 'c': ('.c', '.h'),
    'cpp': ('.cpp', '.cc', '.cxx', '.hpp'),
    'clojure': ('.clj', '.cljs', '.cljc', '.edn'), 'csharp': ('.cs',), 'dart': ('.dart',),
    'dockerfile': ('.dockerfile',), 'elixir': ('.ex', '.exs'), 'hcl': ('.tf', '.hcl', '.tfvars'),
    'html': ('.html', '.htm'), 'json': ('.json',), 'kotlin': ('.kt', '.kts', '.ktm'),
    'lua': ('.lua',), 'ocaml': ('.ml', '.mli'), 'ruby': ('.rb',), 'rust': ('.rs',),
    'scala': ('.scala',), 'solidity': ('.sol',), 'swift': ('.swift',), 'yaml': ('.yml', '.yaml'),
}
TEMPLATE_SUFFIXES = frozenset({'.ejs', '.pug', '.mustache', '.hbs', '.jsp', '.erb', '.page'})
_NAMES = MappingProxyType({'dockerfile': FileCapability('dockerfile', NATIVE)})
_SUFFIXES = MappingProxyType({
    **{suffix: FileCapability(language, NATIVE)
       for language, suffixes in _NATIVE_SUFFIXES.items() for suffix in suffixes},
    '.C': FileCapability('cpp', NATIVE),
    **dict.fromkeys(('.mts', '.cts'), FileCapability('typescript', TS_PROJECTION)),
    '.vue': FileCapability('vue', VUE_SCRIPT, 'VUE_SEMANTICS_NOT_COVERED'),
    **dict.fromkeys(TEMPLATE_SUFFIXES, FileCapability('template', TEXT, 'TEMPLATE_TEXT_ONLY')),
    '.xml': FileCapability('xml', TEXT, 'XML_NATIVE_NOT_COVERED'),
})
_COMPOUND = MappingProxyType({
    '.min.js': FileCapability('javascript', TEXT, 'MINIFIED_TYPE_SCAN_EXCLUDED'),
    **dict.fromkeys(('.d.ts', '.d.mts', '.d.cts'),
                    FileCapability('typescript', TEXT, 'DECLARATION_TYPE_SCAN_EXCLUDED')),
})

# Catalog metadata and legacy presentation callers keep their existing shapes.
EXTENSIONS = MappingProxyType({
    **{language: frozenset(s for s, capability in _SUFFIXES.items()
                           if capability.language == language)
       for language in (*_NATIVE_SUFFIXES, 'vue')},
    **dict.fromkeys(TEXT_LANGUAGES, frozenset({'*'})),
})
DISPLAY_NAMES = MappingProxyType({'javascript': 'JavaScript', 'typescript': 'TypeScript', 'php': 'PHP'})
PROFILE_EXTENSIONS = MappingProxyType({
    suffix: DISPLAY_NAMES.get(cap.language, cap.language.title())
    for suffix, cap in _SUFFIXES.items() if cap.language != 'xml'
})
# Discovery consumers outside SAST still use their original file inventory.
LEGACY_PROFILE_EXTENSIONS = MappingProxyType({
    suffix: language for suffix, language in PROFILE_EXTENSIONS.items()
    if suffix not in TEMPLATE_SUFFIXES | {
        '.C', '.mjs', '.cjs', '.mts', '.cts', '.pyi', '.ktm', '.phtml', '.tfvars', '.edn'}
})


def file_type(name):
    basename = PurePosixPath(str(name).replace('\\', '/')).name
    lower = basename.lower()
    if lower in _NAMES:
        return _NAMES[lower], ''
    for suffix, capability in _COMPOUND.items():
        if lower.endswith(suffix):
            return capability, suffix
    suffix = PurePosixPath(basename).suffix
    # .C is C++; normalizing it before the exact match routes it to C.
    suffix = suffix if suffix in _SUFFIXES else suffix.lower()
    return _SUFFIXES.get(suffix), suffix


def restricted_text_suffixes(rule):
    """Only opt in explicit template suffix rules; the engine handles paths."""
    paths = rule.get('paths')
    includes = paths.get('include') if isinstance(paths, dict) else None
    allowed = {'*' + suffix for suffix in TEMPLATE_SUFFIXES}
    if not isinstance(includes, list) or any(
            not isinstance(pattern, str) or not re.fullmatch(r'\*\.[a-z]+', pattern)
            for pattern in includes):
        return ()
    return tuple(sorted({pattern[1:] for pattern in includes
                         if isinstance(pattern, str) and pattern in allowed}))
