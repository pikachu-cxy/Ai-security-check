"""Bounded Vue SFC script extraction for static scanners, without compilation.

Only top-level inline JavaScript and TypeScript blocks are projected. Templates,
styles, imported scripts and custom blocks are never interpreted as script code.
Each block gets its own projection, so separate scopes cannot acquire accidental
data flow from concatenation. Projection positions use UTF-8 byte coordinates,
as Semgrep does: masking preserves byte length, CR/LF, offsets and byte columns.
This module makes no claim about template or compiled Vue semantics.
"""
from dataclasses import dataclass
from html import unescape
from pathlib import Path
import re


MAX_SOURCE_BYTES = 512 * 1024
MAX_TAG_BYTES = 8192
MAX_TAGS = 4096
MAX_TEMPLATE_DEPTH = 128
_SPACE = b' \t\r\n\f'
_NAME = re.compile(rb'[A-Za-z][A-Za-z0-9_.:-]*')
_ATTR = re.compile(rb'[^\s=<>/\x00\"\x27`]+')
_TEMPLATE_TOKEN = re.compile(rb'<|\{\{')
_VOID_TAGS = frozenset({'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input',
                        'link', 'meta', 'param', 'source', 'track', 'wbr'})
_BLANK_TABLE = bytes(char if char in (10, 13) else 32 for char in range(256))


@dataclass(frozen=True)
class VueScript:
    language: str
    setup: bool
    content_start: int
    content_end: int
    shadow_bytes: bytes

    @property
    def suffix(self) -> str:
        return '.ts' if self.language == 'typescript' else '.js'

    def contains_offset(self, offset: int) -> bool:
        """Whether a scanner's byte start offset is inside this script body."""
        return self.content_start <= offset < self.content_end


@dataclass(frozen=True)
class VueExtraction:
    scripts: tuple[VueScript, ...] = ()
    issues: tuple[str, ...] = ()
    has_template: bool = False

    @property
    def complete(self) -> bool:
        """All inline script blocks extracted; does not mean Vue is covered."""
        return not self.issues


class _Unsupported(Exception):
    pass


class _Parser:
    def __init__(self, source: bytes):
        self.source = source
        self.tags = 0

    def comment(self, start: int) -> int:
        end = self.source.find(b'-->', start + 4)
        if end < 0:
            raise _Unsupported('MALFORMED_SFC')
        return end + 3

    def tag(self, start: int):
        """Read one quoted-attribute-aware HTML-like tag, with a local bound."""
        self.tags += 1
        if self.tags > MAX_TAGS:
            raise _Unsupported('SFC_TAG_LIMIT')
        source = self.source
        closing = source[start:start + 2] == b'</'
        match = _NAME.match(source, start + (2 if closing else 1))
        if match is None:
            raise _Unsupported('MALFORMED_SFC')
        name = match[0].decode('ascii').lower()
        cursor, attrs, self_closing = match.end(), {}, False
        limit = min(len(source), start + MAX_TAG_BYTES)
        while cursor < limit:
            while cursor < limit and source[cursor] in _SPACE:
                cursor += 1
            if source[cursor:cursor + 1] == b'>':
                return name, attrs, closing, self_closing, cursor + 1
            if source[cursor:cursor + 2] == b'/>':
                if closing:
                    raise _Unsupported('MALFORMED_SFC')
                return name, attrs, closing, True, cursor + 2
            if closing:
                raise _Unsupported('MALFORMED_SFC')
            attribute = _ATTR.match(source, cursor, limit)
            if attribute is None:
                raise _Unsupported('MALFORMED_SFC')
            if attribute.end() == limit:
                raise _Unsupported('SFC_TAG_LIMIT')
            key = attribute[0].decode('utf-8').lower()
            if key in attrs:
                raise _Unsupported('DUPLICATE_SFC_ATTRIBUTE')
            cursor = attribute.end()
            while cursor < limit and source[cursor] in _SPACE:
                cursor += 1
            value = None
            if source[cursor:cursor + 1] == b'=':
                cursor += 1
                while cursor < limit and source[cursor] in _SPACE:
                    cursor += 1
                quote = source[cursor:cursor + 1]
                if quote in (b'"', b"'"):
                    end = source.find(quote, cursor + 1, limit)
                    if end < 0:
                        raise _Unsupported('MALFORMED_SFC')
                    value = source[cursor + 1:end]
                    cursor = end + 1
                else:
                    end = cursor
                    while end < limit and source[end] not in _SPACE + b'>':
                        if source[end] in b'\x00\"\x27<=`':
                            raise _Unsupported('MALFORMED_SFC')
                        end += 1
                    if end == cursor:
                        raise _Unsupported('MALFORMED_SFC')
                    value = source[cursor:end]
                    cursor = end
                value = unescape(value.decode('utf-8'))
            attrs[key] = value
        raise _Unsupported('SFC_TAG_LIMIT')

    def raw_end(self, name: str, cursor: int):
        # HTML raw-text ends at the closing tag even inside a JS/CSS string.
        close = re.compile(rb'</' + re.escape(name.encode('ascii')) + rb'(?=[\s/>])', re.I)
        found = close.search(self.source, cursor)
        if found is None:
            raise _Unsupported('MALFORMED_SFC')
        actual, _, closing, _, end = self.tag(found.start())
        if actual != name or not closing:
            raise _Unsupported('MALFORMED_SFC')
        return found.start(), end

    def template_end(self, cursor: int):
        """Skip HTML templates, including nested templates and raw-text tags."""
        # Deliberately require explicit matching end tags (except HTML void
        # elements). Unsupported implicit HTML repairs must not expose a script.
        stack = ['template']
        source = self.source
        while cursor < len(source):
            token = _TEMPLATE_TOKEN.search(source, cursor)
            if token is None:
                break
            opening = token.start()
            if token[0] == b'{{':
                end = source.find(b'}}', opening + 2)
                if end < 0:
                    raise _Unsupported('MALFORMED_SFC')
                cursor = end + 2
                continue
            if source.startswith(b'<!--', opening):
                cursor = self.comment(opening)
                continue
            # Literal less-than characters in ordinary template text are not tags.
            marker = opening + (2 if source.startswith(b'</', opening) else 1)
            if _NAME.match(source, marker) is None:
                if source.startswith((b'<!', b'<?'), opening):
                    raise _Unsupported('UNSUPPORTED_SFC_MARKUP')
                cursor = opening + 1
                continue
            name, _, closing, self_closing, cursor = self.tag(opening)
            if closing:
                if name != stack[-1]:
                    raise _Unsupported('MALFORMED_SFC')
                stack.pop()
                if not stack:
                    return cursor
            elif self_closing or name in _VOID_TAGS:
                continue
            elif name in {'script', 'style', 'textarea', 'title'}:
                _, cursor = self.raw_end(name, cursor)
            else:
                stack.append(name)
                if len(stack) > MAX_TEMPLATE_DEPTH:
                    raise _Unsupported('SFC_NESTING_LIMIT')
        raise _Unsupported('MALFORMED_SFC')


def extract_vue_scripts(source: bytes) -> VueExtraction:
    """Extract bounded, valid UTF-8 SFC bytes; never load referenced resources.

    Structural ambiguity discards all projections rather than guessing where
    script starts. Known unsupported script blocks are skipped individually and
    their reason codes make the extraction explicitly incomplete.
    """
    if len(source) > MAX_SOURCE_BYTES:
        return VueExtraction(issues=('SFC_SIZE_LIMIT',))
    try:
        source.decode('utf-8')
    except UnicodeDecodeError:
        return VueExtraction(issues=('SFC_INVALID_UTF8',))
    if b'\x00' in source:
        return VueExtraction(issues=('MALFORMED_SFC',))
    parser, cursor = _Parser(source), 3 if source.startswith(b'\xef\xbb\xbf') else 0
    blocks, issues, seen, has_template = [], [], set(), False
    try:
        while cursor < len(source):
            if source[cursor] in _SPACE:
                cursor += 1
                continue
            if source.startswith(b'<!--', cursor):
                cursor = parser.comment(cursor)
                continue
            if source[cursor:cursor + 1] != b'<':
                raise _Unsupported('MALFORMED_SFC')
            name, attrs, closing, self_closing, body_start = parser.tag(cursor)
            if closing:
                raise _Unsupported('MALFORMED_SFC')
            original_name = _NAME.match(source, cursor + 1)[0].decode('ascii')
            if name in {'script', 'template', 'style'} and original_name != name:
                # Vue component/custom-block names are case-sensitive. Do not
                # turn a custom <Script> block into a JavaScript language block.
                raise _Unsupported('UNSUPPORTED_SFC_MARKUP')
            if name == 'template':
                if has_template:
                    raise _Unsupported('DUPLICATE_TEMPLATE')
                has_template = True
                cursor = body_start if self_closing else (
                    parser.template_end(body_start) if attrs.get('lang') in (None, '', 'html')
                    else parser.raw_end(name, body_start)[1])
                continue
            body_end, cursor = (body_start, body_start) if self_closing else parser.raw_end(name, body_start)
            if name != 'script':
                continue
            setup = 'setup' in attrs
            if setup in seen:
                raise _Unsupported('DUPLICATE_SCRIPT')
            seen.add(setup)
            if 'src' in attrs:
                issues.append('EXTERNAL_SCRIPT')
                continue
            if any(key in attrs for key in (':lang', 'v-bind:lang', ':src', 'v-bind:src')):
                issues.append('UNSUPPORTED_SCRIPT_ATTRIBUTES')
                continue
            language = {'js': 'javascript', 'javascript': 'javascript',
                        'ts': 'typescript', 'typescript': 'typescript'}.get(attrs.get('lang') or 'js')
            if language is None:
                issues.append('UNSUPPORTED_SCRIPT_LANGUAGE')
                continue
            if attrs.get('type') not in (None, '', 'module', 'text/javascript', 'application/javascript'):
                issues.append('UNSUPPORTED_SCRIPT_TYPE')
                continue
            blocks.append((language, setup, body_start, body_end))
        if len({block[0] for block in blocks}) > 1:
            raise _Unsupported('SCRIPT_LANGUAGE_MISMATCH')
    except _Unsupported as error:
        return VueExtraction(issues=tuple(dict.fromkeys((*issues, str(error)))), has_template=has_template)
    # One pass to mask non-ASCII bytes too; this preserves byte offsets even when
    # preceding template/style text contains multi-byte UTF-8 characters.
    blank = source.translate(_BLANK_TABLE)
    scripts = tuple(VueScript(language, setup, start, end, blank[:start] + source[start:end] + blank[end:])
                    for language, setup, start, end in blocks)
    return VueExtraction(scripts, tuple(dict.fromkeys(issues)), has_template)


def read_vue_scripts(path: Path) -> VueExtraction:
    """Read a caller-validated local snapshot path with an allocation bound."""
    try:
        with Path(path).open('rb') as stream:
            source = stream.read(MAX_SOURCE_BYTES + 1)
    except OSError:
        return VueExtraction(issues=('SFC_READ_ERROR',))
    return extract_vue_scripts(source)
