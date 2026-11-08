"""Shared local dashboard lifecycle, independent of scan and review transactions."""
from contextlib import closing
import json
import hashlib
import os
from pathlib import Path
import re
import secrets
import sqlite3
import subprocess
import sys
import threading
import time
from urllib.parse import urlencode
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler

from .hook_state import no_links, identity


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


def address(value):
    return f"http://127.0.0.1:{value['port']}/risks"


def session_url(workspace, owner):
    """Pure saved-address lookup; never launches a process during closeout."""
    try:
        value = endpoint()
        if value is None:
            return None
        from .project_identity import describe
        scope = describe(workspace)
        query = urlencode(dict(project=scope['project_id'], workspace=scope['workspace_id'],
                               session=owner['session'], editor=owner['host']))
        return address(value) + '?' + query
    except (OSError, ValueError, KeyError, TypeError):
        return None


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


def code_id():
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


def ensure():
    folder = directory()
    no_links(folder)
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock = folder / 'startup.db'
    no_links(lock)
    # This transaction serializes only service startup, never risk writes.
    with closing(sqlite3.connect(lock, timeout=5)) as db, db:
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
            deadline = time.monotonic() + 2
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
        deadline = time.monotonic() + 5
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


def start_background():
    def start():
        try:
            ensure()
        except (OSError, ValueError, sqlite3.Error, subprocess.SubprocessError):
            # Explicit address requests report the failure; startup stays quiet.
            pass
    threading.Thread(target=start, name='risk-dashboard-start', daemon=True).start()
