"""Shared local dashboard lifecycle, independent of scan and review transactions."""
from contextlib import closing
import json
import hashlib
import os
from pathlib import Path
import re
import secrets
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from urllib.parse import urlencode
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler

from .hook_state import no_links, identity

IDENTITY = re.compile(r'[A-Za-z0-9_$.-]{1,180}')
STARTUP_CODES = {'RISK_DASHBOARD_START_FAILED', 'RISK_DASHBOARD_UPGRADE_RESTART_REQUIRED',
                 'RISK_DASHBOARD_LOCK_TIMEOUT', 'DASHBOARD_ENDPOINT_INVALID',
                 'DASHBOARD_BUILD_IDENTITY_UNAVAILABLE'}


def directory():
    from .storage import SQLiteStore
    return SQLiteStore.default_path().parent / 'dashboard'


def endpoint():
    path = directory() / 'endpoint.json'
    no_links(path)
    if not path.exists():
        return None
    if path.stat().st_size > 4096:
        raise ValueError('DASHBOARD_ENDPOINT_INVALID')
    value = json.loads(path.read_text())
    if (not isinstance(value, dict) or type(value.get('port')) is not int or not 1 <= value['port'] <= 65535
            or not isinstance(value.get('token'), str)
            or not re.fullmatch(r'[A-Za-z0-9_-]{32}', value['token'])):
        raise ValueError('DASHBOARD_ENDPOINT_INVALID')
    return value


def save_endpoint(port, token):
    folder = directory()
    no_links(folder)
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = folder / 'endpoint.json'
    no_links(path)
    temporary = folder / ('endpoint-' + secrets.token_hex(8))
    try:
        with open(temporary, 'x', encoding='utf-8') as stream:
            os.chmod(temporary, 0o600)
            json.dump(dict(port=port, token=token), stream)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def live(value, timeout=0.05):
    """Loopback reachability only; proves nothing about identity or readiness."""
    if not isinstance(value, dict) or type(value.get('port')) is not int:
        return False
    try:
        with socket.create_connection(('127.0.0.1', value['port']), timeout=timeout):
            return True
    except OSError:
        return False


def address(value):
    return f"http://127.0.0.1:{value['port']}/risks"


def session_url(workspace, owner, *, check_ref=None, scan_id=None, seq=None):
    """Saved address for one verified batch; never launches a process during closeout.

    Identity values come from the saved check record. A value that cannot be
    verified yields no address, so callers report the gap instead of guessing.
    """
    try:
        value = endpoint()
        if value is None or not live(value):
            return None
        from .project_identity import describe
        scope = describe(workspace)
        query = dict(project=scope['project_id'], workspace=scope['workspace_id'],
                     session=owner['session'], editor=owner['host'])
        for key, item in (('check', check_ref), ('scan', scan_id)):
            if item is None:
                continue
            if not isinstance(item, str) or not IDENTITY.fullmatch(item):
                return None
            query[key] = item
        if seq is not None:
            if type(seq) is not int or seq < 0:
                return None
            query['seq'] = str(seq)
        return address(value) + '?' + urlencode(query)
    except (OSError, ValueError, KeyError, TypeError):
        return None


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


def code_id():
    # Frozen modules live in the Python archive, not as adjacent .py files.
    # Use the same immutable bundle identity as installation and MCP probes.
    if getattr(sys, 'frozen', False):
        from .build_identity import build_identity
        identity = build_identity()
        if identity.get('status') != 'IDENTIFIED':
            raise ValueError('DASHBOARD_BUILD_IDENTITY_UNAVAILABLE')
        return identity['build_id']
    base = Path(__file__).parent
    names = ('dashboard_service.py', 'risk_dashboard.py', 'dashboard_records.py',
             'dashboard_catalog.py', 'dashboard_presentation.py', 'dashboard_sessions.py', 'dashboard_health.py', 'dashboard_detail.py', 'dashboard_history.py', 'dashboard_entities.py', 'dashboard_export.py', 'risk_management.py',
             'project_identity.py', 'user_config.py', 'assets/risk_dashboard.html',
             'development_risks.py', 'business_audit.py', 'repair_notifications.py')
    digest = hashlib.sha256()
    for name in names:
        digest.update(name.encode())
        digest.update((base/name).read_bytes())
    return digest.hexdigest()


def health(value):
    if value is None:
        return None
    request = Request(f"http://127.0.0.1:{value['port']}/health",
                      headers={'Authorization': 'Bearer ' + value['token']})
    try:
        with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=.3) as response:
            result = json.loads(response.read(4096))
            return result if response.status == 200 and isinstance(result, dict) else None
    except (OSError, ValueError):
        return None


def healthy(value):
    result = health(value)
    return bool(result and result.get('service') == 'risk-dashboard-v2' and result.get('build') == code_id())


def ensure(timeout=5):
    folder = directory()
    no_links(folder)
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    # A healthy service needs no lock. This is the path taken by every explicit
    # "open risk statistics" request once the background start has finished.
    value = endpoint()
    if healthy(value):
        return value
    lock = folder / 'startup.db'
    no_links(lock)
    # This transaction serializes only service startup, never risk writes.
    with closing(sqlite3.connect(lock, timeout=timeout)) as db, db:
        db.execute('BEGIN IMMEDIATE')
        value = endpoint()
        if healthy(value):
            return value
        existing = health(value)
        if existing and existing.get('service') == 'risk-dashboard-v2':
            request = Request(f"http://127.0.0.1:{value['port']}/shutdown", data=b'',
                              headers={'Authorization': 'Bearer '+value['token']}, method='POST')
            with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=1) as response:
                response.read(1024)
            deadline = time.monotonic() + 1
            while health(value) and time.monotonic() < deadline:
                time.sleep(.05)
        elif existing:
            raise ValueError('RISK_DASHBOARD_UPGRADE_RESTART_REQUIRED')
        command = ([sys.executable] if getattr(sys, 'frozen', False)
                   else [sys.executable, '-m', 'security_runtime.cli'])
        options = {'creationflags': subprocess.CREATE_NO_WINDOW} if os.name == 'nt' else {'start_new_session': True}
        process = subprocess.Popen(command + ['risk-dashboard', '--shared'],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            close_fds=True, **options)
        deadline = time.monotonic() + min(5, max(2, timeout))
        while time.monotonic() < deadline:
            value = endpoint()
            if healthy(value):
                return value
            if process.poll() is not None:
                break
            time.sleep(.05)
        process.terminate()
        process.wait(timeout=2)
        raise ValueError('RISK_DASHBOARD_START_FAILED')


def _save_status(status, reason_code=None):
    folder = directory()
    no_links(folder)
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = folder / 'startup-status.json'
    no_links(path)
    temporary = folder / ('startup-' + secrets.token_hex(8))
    try:
        with open(temporary, 'x', encoding='utf-8') as stream:
            os.chmod(temporary, 0o600)
            json.dump(dict(status=status, reason_code=reason_code, at=time.time()), stream)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _reason(error):
    text = str(error)
    if text in STARTUP_CODES:
        return text
    if isinstance(error, sqlite3.OperationalError) and 'locked' in text:
        return 'RISK_DASHBOARD_LOCK_TIMEOUT'
    return 'RISK_DASHBOARD_START_FAILED'


def startup_status():
    try:
        path = directory() / 'startup-status.json'
        no_links(path)
        if not path.exists() or path.stat().st_size > 2048:
            return None
        value = json.loads(path.read_text())
        return value if isinstance(value, dict) else None
    except (OSError, ValueError):
        return None


def start_background():
    def start():
        try:
            ensure(timeout=15)
        except (OSError, ValueError, sqlite3.Error, subprocess.SubprocessError) as error:
            try:
                _save_status('FAILED', _reason(error))
            except (OSError, ValueError, sqlite3.Error):
                pass
        except Exception:
            # Startup never takes the MCP connection down, but it is no longer
            # silent: the explicit entry point reads this status.
            try:
                _save_status('FAILED', 'RISK_DASHBOARD_START_FAILED')
            except (OSError, ValueError, sqlite3.Error):
                pass
        else:
            try:
                _save_status('READY')
            except (OSError, ValueError, sqlite3.Error):
                pass
    thread = threading.Thread(target=start, name='risk-dashboard-start', daemon=True)
    thread.start()
    return thread
