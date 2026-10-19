"""Safe, structured failure semantics for scanners and remote preparation."""
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import os
import re
import socket
import ssl
import urllib.error
from http.client import IncompleteRead
from urllib.parse import urlsplit

from .redactor import SecretRedactor


def sanitize(text: str, limit: int = 1000) -> str:
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', str(text))
    text = re.sub(r'https?://[^\s<>"\']+', lambda match: safe_url(match.group()), text)
    text = re.sub(r'(?i)(?:proxy-)?authorization["\']?\s*[:=]\s*[^\r\n,}]+', '[REDACTED_SECRET]', text)
    text = re.sub(r'(?i)["\']?(?:password|passwd|token|access_token|api[_-]?key|secret|credential)["\']?\s*[:=]\s*(?:"[^"\n]*"|\x27[^\x27\n]*\x27|[^\s,}]+)', '[REDACTED_SECRET]', text)
    text = re.sub(r'(?is)<(?:password|token|secret)>.*?</(?:password|token|secret)>', '[REDACTED_SECRET]', text)
    text = SecretRedactor().redact(text)
    return ''.join(c for c in text if c in '\n\t' or ord(c) >= 32)[:limit]


def safe_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        host = parsed.hostname or ''
        return f'{parsed.scheme}://{host}/[REDACTED_URL_DETAILS]'
    except ValueError:
        return '[REDACTED_URL]'


def retry_after(value: str | None) -> int | None:
    if not value:
        return None
    match = re.match(r'\s*(\d+)', value)
    if match:
        return int(match.group(1))
    try:
        return max(0, int((parsedate_to_datetime(value) - datetime.now(timezone.utc)).total_seconds()))
    except (TypeError, ValueError, OverflowError):
        return None


@dataclass(frozen=True)
class ErrorDiagnostic:
    error_code: str
    error_summary: str
    remediation: str
    retry_after_seconds: int | None = None
    diagnostic_detail: str = ''
    source: str = ''
    http_proxy: str = 'not configured'
    https_proxy: str = 'not configured'

    def __post_init__(self):
        for name in ('error_summary', 'remediation', 'diagnostic_detail', 'source'):
            object.__setattr__(self, name, sanitize(getattr(self, name)))
        object.__setattr__(self, 'error_code', re.sub(r'[^A-Z0-9_]', '', self.error_code)[:80])
        for name in ('http_proxy', 'https_proxy'):
            object.__setattr__(self, name, 'configured' if getattr(self, name) == 'configured' else 'not configured')

    def to_dict(self):
        return asdict(self)


class DiagnosticError(ValueError):
    def __init__(self, diagnostic: ErrorDiagnostic):
        self.diagnostic = diagnostic
        super().__init__(diagnostic.error_summary)


def classify_network_error(error=None, *, stderr='', url='', offline=False, return_code=None,
                           fallback='SCANNER_FAILED') -> ErrorDiagnostic:
    """One classifier for urllib/socket errors, pip and scanner stderr.

    Output uses canonical reasons and hosts only, never raw scanner logs.
    """
    from .processes import ProcessStartError
    if isinstance(error, ProcessStartError):
        detail = '; '.join(f'{key}: {value}' for key, value in error.failure.items())
        return ErrorDiagnostic('PROCESS_START_FAILED',
            'The local scanner process could not be started.',
            'Inspect the recorded startup stage, OS error number and path lengths, then retry.',
            diagnostic_detail=detail)
    text = str(error or '') + '\n' + stderr
    lower = text.lower()
    cause = error.reason if isinstance(error, urllib.error.URLError) else error
    status = error.code if isinstance(error, urllib.error.HTTPError) else None
    if status is None:
        match = re.search(r'(?i)(?:http(?:/\d(?:\.\d)?)?\s*[:=]?\s*|returned\s+|status(?:\s+code)?\s*[:=]?\s*|:\s*)(401|403|404|429|5\d\d)\b', text)
        if not match:
            match = re.search(r'(?i)\b(401|403|404|429|5\d\d)\s+(?:Client Error|Server Error|Unauthorized|Forbidden|Not Found|Too Many Requests|Internal Server Error|Bad Gateway|Service Unavailable)', text)
        status = int(match.group(1)) if match else None
    header = error.headers.get('Retry-After') if isinstance(error, urllib.error.HTTPError) and error.headers else None
    match = re.search(r'(?i)retry-after\s*[:=]\s*([^\r\n]+)', text)
    delay = retry_after(header or (match.group(1) if match else None))
    source_url = url or getattr(error, 'url', '')
    urls = re.findall(r'https?://[^\s<>"\']+', text)
    source_url = source_url or (urls[0] if urls else '')
    try:
        source = urlsplit(source_url).hostname or ''
    except ValueError:
        source = ''
    if not source:
        match = re.search(r"(?:host=['\"]|\b)(repo\.maven\.apache\.org|mirror\.gcr\.io|ghcr\.io|github\.com|pypi\.org|files\.pythonhosted\.org)", text)
        source = match.group(1) if match else ''
    summary = 'The process did not complete successfully.'
    remedy = 'Inspect local engine configuration and retry the check.'
    code = fallback
    if offline or 'unavailable offline' in lower or 'tool unavailable offline' in lower:
        code, summary, remedy = 'OFFLINE_MODE', 'Required local data or engine is unavailable in offline mode.', 'Prepare the required engine/data online, then retry offline.'
    elif 'checksum' in lower or 'sha256 mismatch' in lower:
        code, summary, remedy = 'CHECKSUM_MISMATCH', 'Downloaded artifact failed checksum verification (SHA256 mismatch).', 'Retry the pinned official download. Do not bypass checksum verification.'
    elif any(word in lower for word in ('config corrupted', 'invalid install marker', 'metadata invalid', 'invalid tool configuration')):
        code, summary, remedy = 'CONFIG_CORRUPTED', 'Local engine configuration or installation metadata is invalid.', 'Repair the local configuration or installation metadata before retrying.'
    elif status:
        code = f'HTTP_{status}' if status < 500 else 'HTTP_5XX'
        summary = f'Remote source returned HTTP {status}.'
        remedy = 'Check access permissions/source availability and retry.'
        if status == 429:
            remedy = 'Wait for the rate limit to clear, then retry.'
            if 'maven' in lower or source == 'repo.maven.apache.org':
                code = 'MAVEN_RATE_LIMITED'
                # Informational documentation links can precede the failing
                # request. Prefer the actual Maven repository over those URLs.
                maven_host = re.search(r'\b(repo\.maven\.apache\.org|repo1\.maven\.org)\b', text)
                if maven_host:
                    source = maven_host.group(1)
                else:
                    for candidate_url in urls:
                        try:
                            parsed = urlsplit(candidate_url)
                            if '/maven2/' in parsed.path:
                                source = parsed.hostname or ''
                                break
                        except ValueError:
                            continue
                    if source in {'trivy.dev', 'aquasecurity.github.io'}:
                        source = ''
                summary = 'Maven repository returned HTTP 429 while resolving project dependencies.'
                remedy = 'Populate the local Maven cache, configure a Maven mirror, or retry after the repository rate limit clears.'
    elif 'proxy' in lower and any(word in lower for word in ('error', 'failed', 'refused', 'unable', 'cannot', 'timeout')):
        code, summary = 'PROXY_CONNECTION_FAILED', 'Unable to connect through the configured proxy.'
    elif isinstance(cause, ssl.SSLError) or any(word in lower for word in ('certificate verify failed', 'sslerror', 'tls handshake', 'x509:', 'certificate_verify_failed')):
        code, summary = 'TLS_ERROR', 'TLS connection or certificate validation failed.'
    elif isinstance(cause, socket.gaierror) or any(word in lower for word in ('name resolution', 'getaddrinfo failed', 'no such host', 'nodename nor servname', 'temporary failure in name')):
        code, summary = 'DNS_RESOLUTION_FAILED', 'Remote source hostname could not be resolved.'
    elif isinstance(cause, ConnectionRefusedError) or 'connection refused' in lower or 'actively refused' in lower:
        code, summary = 'CONNECTION_REFUSED', 'Remote source refused the connection.'
    elif isinstance(cause, TimeoutError) or any(word in lower for word in ('timed out', 'timeout', 'context deadline exceeded', 'connection attempt failed', 'did not properly respond')):
        code, summary = 'NETWORK_TIMEOUT', 'Connection timed out while contacting the remote source.'
    elif isinstance(cause, (IncompleteRead, ConnectionResetError)) or any(word in lower for word in ('incomplete read', 'incompleteread', 'connection reset', 'unexpected eof', 'download interrupted')):
        code, summary = 'DOWNLOAD_INTERRUPTED', 'Remote download was interrupted before completion.'
    elif 'failed to resolve dependencies' in lower or 'dependency resolution failed' in lower:
        code, summary = 'DEPENDENCY_RESOLUTION_FAILED', 'Project dependency resolution did not complete.'
    elif isinstance(error, urllib.error.URLError) or any(word in lower for word in ('network', 'dial tcp', 'connection error', 'http error')):
        code, summary = 'UNKNOWN_NETWORK_ERROR', 'A remote connection or download failed.'
    if code in {'NETWORK_TIMEOUT', 'CONNECTION_REFUSED', 'DNS_RESOLUTION_FAILED', 'PROXY_CONNECTION_FAILED', 'TLS_ERROR', 'DOWNLOAD_INTERRUPTED', 'UNKNOWN_NETWORK_ERROR'}:
        remedy = 'Check network connectivity, HTTPS_PROXY and remote service availability, then retry. Do not disable TLS verification.'
    detail = f'Return code: {return_code}.' if return_code is not None else ''
    return ErrorDiagnostic(code, summary, remedy, delay, detail, sanitize(source, 200),
                           'configured' if os.getenv('HTTP_PROXY') or os.getenv('http_proxy') else 'not configured',
                           'configured' if os.getenv('HTTPS_PROXY') or os.getenv('https_proxy') else 'not configured')


def format_diagnostic(diagnostic, *, retry='') -> str:
    data = diagnostic.to_dict() if isinstance(diagnostic, ErrorDiagnostic) else diagnostic
    lines = [f"Reason: {data.get('error_summary', '')}", f"Category: {data.get('error_code', '')}"]
    if data.get('source'):
        lines.append('Source: ' + data['source'])
    if data.get('retry_after_seconds') is not None:
        lines.append(f"Retry after: {data['retry_after_seconds']} seconds")
    lines += ['HTTP proxy: ' + data.get('http_proxy', 'not configured'),
              'HTTPS proxy: ' + data.get('https_proxy', 'not configured'), 'Suggestion: ' + data.get('remediation', '')]
    if retry:
        lines.append('Retry: ' + retry)
    return sanitize('\n'.join(lines), 2000)
