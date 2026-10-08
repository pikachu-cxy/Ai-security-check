"""Bounded edits to one MCP subtree; never serialize the shared TOML document.

tomllib is the semantic authority. This lexer only locates complete statements,
respecting strings, comments and multiline values before interpreting key paths.
Ambiguous parent-inline layouts are readable but cannot be mutated safely here.
"""
from __future__ import annotations

import copy
import re
import tomllib

from .integration_lifecycle import IntegrationDiagnostic

OWNED = ('mcp_servers', 'ai_security_runtime')
LEGACY_MARKER = re.compile(r'[ \t]*# (?:BEGIN|END) AI Security Runtime managed Codex v0\.[12][ \t]*(?:\r?\n)?')


def _statements(text):
    start = i = depth = 0
    quote = None
    triple = False
    while i < len(text):
        c = text[i]
        if quote:
            if c == '\\' and quote == '"':
                i += 2
                continue
            if c == quote:
                if triple:
                    end = i
                    while end < len(text) and text[end] == quote:
                        end += 1
                    if end - i >= 3:
                        quote = None
                    i = end
                    continue
                quote = None
        elif c in "\"'":
            quote = c
            triple = text[i:i+3] == c * 3
            if triple:
                i += 3
                continue
        elif c == '#':
            end = text.find('\n', i)
            i = len(text) if end < 0 else end
            continue
        elif c in '[{':
            depth += 1
        elif c in ']}':
            depth -= 1
        if c == '\n' and not quote and depth == 0:
            yield start, i + 1, text[start:i+1]
            start = i + 1
        i += 1
    if start < len(text):
        yield start, len(text), text[start:]


def _delimiter(text, wanted):
    quote = None
    i = 0
    while i < len(text):
        c = text[i]
        if quote:
            if c == '\\' and quote == '"':
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in "\"'":
            quote = c
        elif c == wanted:
            return i
        i += 1
    raise ValueError('Missing TOML delimiter')


def _key_path(key):
    value = tomllib.loads(key + ' = 0')
    path = []
    while isinstance(value, dict) and len(value) == 1:
        name, value = next(iter(value.items()))
        path.append(name)
    if value != 0:
        raise ValueError('Invalid key path')
    return tuple(path)


def foreign_semantics(document):
    value = copy.deepcopy(document)
    servers = value.get('mcp_servers')
    if isinstance(servers, dict):
        servers.pop(OWNED[1], None)
        if not servers:
            value.pop('mcp_servers')
    return value


def patch_server(raw, canonical, *, remove=False):
    """Caller must first prove signed ownership (or absence for first install)."""
    try:
        text = raw.decode('utf-8')
        before = tomllib.loads(text)
        context = ()
        cuts = []
        for start, end, statement in _statements(text):
            body = statement.lstrip(' \t\r\n')
            if LEGACY_MARKER.fullmatch(statement):
                cuts.append((start, end))
                continue
            if not body or body.startswith('#'):
                continue
            if body.startswith('['):
                offset = 2 if body.startswith('[[') else 1
                close = _delimiter(body[offset:], ']') + offset
                context = _key_path(body[offset:close].strip())
                path = context
            else:
                eq = _delimiter(body, '=')
                path = context + _key_path(body[:eq].strip())
                # Removing an inline parent would also own sibling bytes.
                if len(path) < len(OWNED) and OWNED[:len(path)] == path:
                    raise IntegrationDiagnostic('MCP_CONFIGURATION_LAYOUT_UNSUPPORTED')
            if path[:len(OWNED)] == OWNED:
                cuts.append((start, end))
        result = text
        for start, end in reversed(cuts):
            result = result[:start] + result[end:]
        if not remove:
            if result and not result.endswith('\n'):
                result += '\n'
            result += canonical.decode('utf-8')
        after = tomllib.loads(result)
        expected = None if remove else tomllib.loads(canonical.decode())['mcp_servers'][OWNED[1]]
        if (after.get('mcp_servers', {}).get(OWNED[1]) != expected
                or foreign_semantics(before) != foreign_semantics(after)):
            raise ValueError('Patch changed unrelated semantics')
        return result.encode('utf-8')
    except IntegrationDiagnostic:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise IntegrationDiagnostic('CONFIG_INVALID') from None
