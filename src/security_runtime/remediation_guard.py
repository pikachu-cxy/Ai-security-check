"""Bounded source preservation proof for one inline JDK verifier installation.

This is corroboration of an existing scanner finding, not a Java scanner or a
call graph. Only hashes leave these functions; source is never persisted.
"""
import hashlib
import hmac
import os
from pathlib import Path
import re

from .hook_state import no_links

# Keep literals intact for preservation; blank comments without moving lines.
LEX = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*[\s\S]*?\*/')
TOKENS = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[A-Za-z_$][\w$]*|\d+|[^\s]')
UNSAFE = re.compile(r'(?m)^\s*(?P<receiver>[A-Za-z_$][\w$]*)\s*\.\s*setHostnameVerifier\s*\(\s*'
                    r'\(\s*[A-Za-z_$][\w$]*\s*,\s*[A-Za-z_$][\w$]*\s*\)\s*->\s*true\s*\)\s*;\s*(?=\n|$)')
DEFAULT = re.compile(r'(?m)^\s*(?P<receiver>[A-Za-z_$][\w$]*)\s*\.\s*setHostnameVerifier\s*\(\s*'
                     r'(?:javax\.net\.ssl\.)?HttpsURLConnection\s*\.\s*getDefaultHostnameVerifier\s*\(\s*\)\s*\)\s*;\s*(?=\n|$)')


def digest(key, content):
    return hmac.new(key, content, hashlib.sha256).hexdigest()


def source_proof(root: Path, relative: str, key: bytes, *, original_line=None):
    path = root / relative
    if (not relative.endswith('.java') or not path.absolute().is_relative_to(root) or
            '..' in Path(relative).parts or Path(relative).is_absolute()):
        raise ValueError('Target outside repair boundary')
    no_links(path)
    if not path.is_file() or path.stat().st_size > 32768:
        raise ValueError('Target unavailable or exceeds repair budget')
    with path.open('rb') as stream:
        content = stream.read(32769)
    if len(content) > 32768:
        raise ValueError('Target exceeds repair budget')
    text = content.decode('utf-8')
    # Fail closed on Java unicode escapes/text blocks (lexical ambiguity),
    # suppression directives and alternate/global TLS mutations.
    if re.search(r'\\u|"""|nosem|noinspection|SuppressWarnings|setDefault|setSSLSocketFactory|TrustManager', text, re.I):
        raise ValueError('Ambiguous or bypass-capable source')
    code = LEX.sub(lambda m: re.sub(r'[^\n]', ' ', m[0]) if m[0].startswith(('/',)) else m[0], text)
    masked = LEX.sub(lambda m: re.sub(r'[^\n]', ' ', m[0]), text)
    unsafe = list(UNSAFE.finditer(masked))
    safe = list(DEFAULT.finditer(masked))
    if len(unsafe) > 1 or len(safe) > 1 or unsafe and safe:
        raise ValueError('Multiple installations not eligible')
    declarations = re.findall(r'(?:javax\.net\.ssl\.)?HttpsURLConnection\s+([A-Za-z_$][\w$]*)\s*=', masked)
    if len(declarations) != 1 or safe and safe[0]['receiver'] != declarations[0]:
        raise ValueError('Ambiguous repair receiver')
    if original_line is not None:
        if len(unsafe) != 1:
            raise ValueError('No corroborated inline installation')
        match = unsafe[0]
        if not masked[:match.start()].count('\n') + 1 <= original_line <= masked[:match.end()].count('\n') + 1:
            raise ValueError('Scanner position not corroborated')
        receiver = match['receiver']
        type_name = r'(?:javax\.net\.ssl\.)?HttpsURLConnection'
        # Narrow local construction; rule signals in arbitrary custom objects
        # or anonymous implementations are advisory only in v0.1.
        declaration = re.compile(type_name + r'\s+' + re.escape(receiver) + r'\s*=\s*\(\s*' +
                                 type_name + r'\s*\)\s*new\s+(?:java\.net\.)?URL\s*\(')
        declarations = list(declaration.finditer(masked[:match.start()]))
        if len(declarations) != 1 or '.openConnection()' not in re.sub(r'\s', '', masked[declarations[0].start():match.start()]):
            raise ValueError('JDK HTTPS construction not established')
        if ('import javax.net.ssl.HttpsURLConnection;' not in re.sub(r'\s+', ' ', masked) and
                'javax.net.ssl.HttpsURLConnection' not in declarations[0][0]):
            raise ValueError('JDK type not established')
        if ('import java.net.URL;' not in re.sub(r'\s+', ' ', masked) and
                'java.net.URL' not in declarations[0][0]):
            raise ValueError('JDK URL type not established')
        if re.search(r'\b(class|interface|record)\s+(HttpsURLConnection|URL)\b', masked):
            raise ValueError('Shadowed JDK type')
        # Exactly one receiver declaration, no reassignment or alias mutation.
        if len(re.findall(r'\b' + re.escape(receiver) + r'\s*=', masked)) != 1:
            raise ValueError('Receiver reassignment')
    for match in reversed(unsafe or safe):
        code = code[:match.start()] + ' ' * (match.end() - match.start()) + code[match.end():]
    skeleton = '\0'.join(TOKENS.findall(code)).encode()
    return digest(key, skeleton)


def preservation_proof(root: Path, target: str, key: bytes):
    """Include ignored/untracked configuration and files; exclude only Git internals.

    Small fixture/local project budget is intentional. This is not Hook snapshot
    identity: it proves an authorized edit did not move/delete unrelated code.
    """
    entries, total, directories, visited = [], 0, 0, 0
    pending = [root]
    while pending:
        directory = pending.pop()
        directories += 1
        if directories > 200:
            raise ValueError('Preservation directory budget exceeded')
        with os.scandir(directory) as children:
            for child in children:
                path = Path(child.path)
                if path == root / '.git':
                    continue
                visited += 1
                if visited > 401:
                    raise ValueError('Preservation entry budget exceeded')
                no_links(path)
                if child.is_dir(follow_symlinks=False):
                    pending.append(path)
                    continue
                if not child.is_file(follow_symlinks=False):
                    raise ValueError('Special filesystem entries not supported')
                relative = path.relative_to(root).as_posix()
                if relative == target:
                    continue
                size = path.stat().st_size
                total += size
                if size > 524288 or total > 2000000 or len(entries) >= 200:
                    raise ValueError('Preservation file budget exceeded')
                with path.open('rb') as stream:
                    content = stream.read(524289)
                if len(content) > 524288 or len(content) != size:
                    raise ValueError('Preservation file changed during read')
                if relative.endswith('.java') and re.search(
                        rb'setDefaultHostnameVerifier|setDefaultSSLSocketFactory|\b(?:class|interface|record)\s+(?:URL|HttpsURLConnection)\b', content):
                    raise ValueError('Other source changes the default TLS environment')
                entries.append(digest(key, relative.encode() + b'\0' + content))
    return digest(key, '\0'.join(sorted(entries)).encode())
