"""Source representation versions; legacy masking is retained for saved tasks."""
from __future__ import annotations

import re
from pathlib import Path

VERSION = 3
SUPPORTED_VERSIONS = frozenset({1, 2, VERSION})
_MARKER = '[REDACTED_SECRET]'
_KEY = re.compile(r'(?:password|passwd|pwd|token|apikey|secretkey|secret|credentials?|privatekey|authorization|signingkey|accesskey)(?:id|value)?$', re.I)
_ASSIGNMENT = re.compile(r'''(?P<key>[A-Za-z_$][\w$]*|["'][^"'\r\n]{1,80}["'])\s*\]?\s*(?::\s*[A-Za-z_$][\w$.[\]<>?, &|]*)?\s*(?:===|!==|==|!=|=|:)\s*\(?\s*[rubf]{0,2}$''', re.I)
_DEFAULT = re.compile(r'''(?:getenv|environ\.get|config\.get)\(\s*["'](?P<key>[^"'\r\n]+)["']\s*,\s*$''')
_FLAG = re.compile(r'''["']--(?P<key>[\w-]+)["']\s*,\s*$''')
_SETTER = re.compile(r'\b(?P<key>(?:set|with)[A-Za-z_][\w]*)\(\s*$', re.I)
_XML_PROPERTY = re.compile(r'''<(?:property|add|entry)\b[^<>]*\b(?:name|key)\s*=\s*["'](?P<key>[^"']+)["'][^<>]*\bvalue\s*=\s*$''', re.I)
_XML_VALUE = re.compile(r'(?P<open><(?P<key>[\w:.-]+)>)(?P<value>[^<]+)(?P<close></[\w:.-]+>)')
_XML_TAG = re.compile(r'<(?:property|add|entry)\b[^<>]*>', re.I)
_XML_NAME = re.compile(r'''\b(?:name|key)\s*=\s*(["'])(?P<key>[^"']+)\1''', re.I)
_XML_ATTRIBUTE = re.compile(r'''(?P<prefix>\bvalue\s*=\s*)(?P<value>"[^"<>]*"|'[^'<>]*')''', re.I)
_ESCAPES = re.compile(r'\\(?:u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2})|U([0-9a-fA-F]{8}))')
_QUOTED = re.compile(r'''(?i)(?:[rubf]{0,2})(?P<quote>"{3}|'{3}|"|'|`)''')
_REFERENCE = re.compile(r'(?:\$\{[A-Za-z_]\w*\}|\$[A-Za-z_]\w*|%[A-Za-z_]\w*%|\$?\{\{[ \t]*[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*[ \t]*\}\})')
_CONFIG_TEMPLATE = re.compile(
    r'''(?P<prefix>\b(?P<key>[A-Za-z_][\w.-]*)["']?[ \t]*[:=][ \t]*'''
    r'''(?:(?:\#[^\r\n]*)?(?:\r\n?|\n)[ \t]*)*)(?P<value>["']?\$\{\{)''')
_KNOWN = re.compile(r'(?<![\w-])(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|AIza[A-Za-z0-9_-]{30,}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})(?![\w-])')
_PEM = re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)')
_AUTH = re.compile(r'\b(?P<scheme>Bearer|Basic)(?P<space>[ \t]+)(?P<value>[A-Za-z0-9+/_.~=-]{8,})', re.I)
_USERINFO = re.compile(r'''(?<![a-z0-9+.-])(?P<scheme>[a-z][a-z0-9+.-]*://)(?P<value>[^/@\s"'`]+)@''', re.I)
_QUERY = re.compile(r'''(?P<prefix>[?&](?P<key>[\w.-]+)=)(?P<value>[^&#\s"'`]+)''')
_FREE_ASSIGNMENT = re.compile(r'''(?P<prefix>\b(?P<key>[A-Za-z_][\w.-]*)[ \t]*[:=][ \t]*)(?P<value>\$\{\{[^\r\n]*|"(?:\\[\s\S]|[^"\\])*(?:"|\Z)|'(?:\\[\s\S]|[^'\\])*(?:'|\Z)|`(?:\\[\s\S]|[^`\\])*(?:`|\Z)|[^\s;,}]+)''')
_CONFIG = frozenset({'.env', '.yaml', '.yml', '.properties', '.ini', '.conf', '.sh', '.bash', '.zsh', '.ps1', '.psm1', '.md', '.txt'})


def task_version(record):
    """An old task keeps its original policy, including newly added files."""
    return record['baseline'].get('redaction_version', 1)


def _sensitive(key):
    normalized = re.sub(r'[^a-z0-9]', '', _decode(key).lower())
    return bool(_KEY.search(normalized)) or normalized in {
        'sig', 'signature', 'xamzsignature', 'xamzcredential', 'xamzsecuritytoken', 'xgoogsignature'}


def _mask(value):
    return re.sub(r'[^\r\n\v\f\x1c-\x1e\x85\u2028\u2029]+', lambda _: _MARKER, value)


def _decode(value):
    def character(match):
        code = int(next(item for item in match.groups() if item is not None), 16)
        return chr(code) if code <= 0x10ffff else match[0]
    return _ESCAPES.sub(character, value)


def _literal(value):
    opening = _QUOTED.match(value)
    if opening is None:
        return value if value == _MARKER or _REFERENCE.fullmatch(value.strip()) or value.lower() in {'true', 'false', 'none', 'null', 'nil'} else _mask(value)
    quote = opening['quote']
    closed = len(value) >= opening.end() + len(quote) and value.endswith(quote)
    end = len(value) - len(quote) if closed else len(value)
    body = value[opening.end():end]
    if closed and (not body.strip() or body == _MARKER or _REFERENCE.fullmatch(body)):
        return value
    return value[:opening.end()] + _mask(body) + (quote if closed else '')


def _free_text(text, *, assignments=False):
    text = _PEM.sub(lambda match: _mask(match[0]), text)
    text = _KNOWN.sub(lambda _: _MARKER, text)
    text = _AUTH.sub(lambda match: match['scheme'] + match['space'] + _MARKER, text)
    text = _USERINFO.sub(lambda match: match['scheme'] + _MARKER + '@'
        if ':' in match['value'] or len(match['value']) >= 12 else match[0], text)
    text = _QUERY.sub(lambda match: match['prefix'] + _literal(match['value'])
        if _sensitive(match['key']) else match[0], text)
    text = _XML_VALUE.sub(lambda match: match['open'] + _mask(match['value']) + match['close']
        if _sensitive(match['key']) else match[0], text)
    if assignments:
        text = _FREE_ASSIGNMENT.sub(lambda match: match['prefix'] + _literal(match['value'])
            if _sensitive(match['key']) else match[0], text)
    return text


def _yaml_blocks(text):
    lines, block_indent = text.splitlines(keepends=True), None
    for index, line in enumerate(lines):
        if block_indent is not None:
            if not line.strip() or len(line) - len(line.lstrip(' \t')) > block_indent:
                lines[index] = _mask(line)
                continue
            block_indent = None
        header = re.match(r'''(?P<indent>[ \t]*)(?:-[ \t]+)?(?P<key>"[^"\r\n]+"|'[^'\r\n]+'|[\w.-]+)[ \t]*:[ \t]*[|>][-+0-9]*(?:[ \t]*(?:#.*)?)?$''', line.rstrip('\r\n'))
        if header and _sensitive(header['key']):
            block_indent = len(header['indent'])
    return ''.join(lines)


def _xml_property(match):
    key = _XML_NAME.search(match[0])
    if not key or not _sensitive(key['key']):
        return match[0]
    return _XML_ATTRIBUTE.sub(lambda attr: attr['prefix'] + _literal(attr['value']), match[0])


def _config_templates(text):
    """Inspect a whole sensitive template before splitting quoted literals.

    Only whitespace and complete comment lines may separate the key and value;
    another field cannot become part of this credential's prefix.
    """
    parts, end = [], 0
    for match in _CONFIG_TEMPLATE.finditer(text):
        if match.start() < end or not _sensitive(match['key']):
            continue
        cursor, quote = match.end(), None
        while cursor < len(text):
            character = text[cursor]
            if quote:
                if character == '\\' or (character == quote and text[cursor:cursor+2] == quote*2):
                    cursor = min(len(text), cursor+2)
                    continue
                if character == quote:
                    quote = None
            elif character in {'"', "'"}:
                quote = character
            elif text.startswith('}}', cursor):
                cursor += 2
                # A suffix may itself contain a credential. Keep it in the
                # same decision rather than exempting only a public prefix.
                while cursor < len(text) and text[cursor] not in '\r\n':
                    cursor += 1
                break
            cursor += 1
        parts.extend((text[end:match.start()], match['prefix'],
                      _literal(text[match.start('value'):cursor])))
        end = cursor
    parts.append(text[end:])
    return ''.join(parts)


def redact_source(text, tokens, source_path=None):
    # Private-key blocks take precedence over quote/comment tokenization. A
    # window in the middle of a block must never expose a credential fragment.
    text = _PEM.sub(lambda match: _mask(match[0]), text)
    text = _XML_TAG.sub(_xml_property, text)
    parts, end, credential_expression = [], 0, False
    path = Path(source_path) if source_path is not None else None
    if path is not None and path.suffix.lower() in {'.yaml', '.yml'}:
        text = _yaml_blocks(text)
    config = path is None or path.suffix.lower() in _CONFIG or path.name == '.env' or path.name.startswith('.env.')
    if config:
        # Inspect the whole unquoted template before tokenization can separate
        # a quoted credential inside an expression. Only a pure variable path
        # is public; expressions, fallbacks and trailing values stay masked.
        text = _config_templates(text)
    for match in tokens.finditer(text):
        gap = text[end:match.start()]
        parts.append(_free_text(gap, assignments=config))
        value = match[0]
        if match.lastgroup == 'comment':
            value = _free_text(value, assignments=True)
            credential_expression = False
        else:
            prefix = text[max(0, match.start()-256):match.start()]
            context = next((context for pattern in (_ASSIGNMENT, _DEFAULT, _FLAG, _SETTER, _XML_PROPERTY)
                            if (context := pattern.search(prefix)) and _sensitive(context['key'])), None)
            credential_expression = bool(context) or (credential_expression and re.fullmatch(r'[\s+()]*', gap) is not None)
            if credential_expression:
                value = _literal(value)
            elif _KNOWN.search(_decode(value)):
                value = _literal(value)
            else:
                value = _free_text(value, assignments=True)
        parts.append(value)
        end = match.end()
    parts.append(_free_text(text[end:], assignments=config))
    return ''.join(parts)
