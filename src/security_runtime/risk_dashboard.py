"""Read-only local prototype for persisted Runtime findings and development risks."""
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import json
import os
import re
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit

from security_runtime.hook_state import HookStateStore, identity, no_links
from security_runtime.redactor import SecretRedactor
from security_runtime.storage import SQLiteStore
from security_runtime.tasks.durable import SignedRecords

PAGE = Path(__file__).resolve().parent / 'assets' / 'risk_dashboard.html'
STATE = SQLiteStore.default_path().parent
MAX_WORKSPACES, MAX_SCANS, MAX_RISKS = 500, 100, 3000
redact = SecretRedactor().redact


def clean(value, fallback='未记录', limit=1500):
    return redact(str(value or fallback))[:limit]


def open_readonly(path):
    no_links(path)
    return sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True, timeout=2)


def display(f, project, status, source, key):
    path = clean(f.get('file_path'), '未知位置', 500)
    line = f.get('line_start')
    location = path + (':' + str(line) if type(line) is int and line > 0 else '')
    severity = {'CRITICAL': '严重', 'HIGH': '高', 'MEDIUM': '中', 'LOW': '低', 'INFO': '信息'}.get(str(f.get('severity', '')).upper(), '未评级')
    return dict(id=key, project=clean(project, '项目未知', 500), title=clean(f.get('plain_title') or f.get('title'), '未命名发现', 250),
                severity=severity, status=status, category=clean(f.get('category'), '未分类', 100), location=location,
                description=clean(f.get('description')), impact=clean(f.get('impact')), advice=clean(f.get('fix_advice')),
                unknowns='此记录未证明当前源码状态；外部防护和可达性需结合原记录复核。', source=source)


def signed_rows(path, workspace_dir):
    """Recover candidate root, then verify root binding and all record signatures."""
    with closing(open_readonly(path)) as db:
        row = db.execute('SELECT CASE WHEN length(CAST(data AS BLOB)) <= 4000000 THEN data END FROM records LIMIT 1').fetchone()
    if not row or not row[0]:
        return []
    root = json.loads(row[0]).get('workspace')
    if not isinstance(root, str) or not Path(root).is_absolute() or identity(os.path.normcase(root)) != workspace_dir.name:
        raise ValueError('Invalid workspace binding')
    hooks = HookStateStore(workspace_dir / 'hooks')
    return SignedRecords(hooks, Path(root), 'development-risks.db').rows()


def records():
    base = STATE / 'global-workspaces'
    if not base.exists():
        return {'risks': [], 'partial': False, 'note': '未找到全局工作区的已保存记录。', 'projects': []}
    no_links(base)
    entries, results, projects, issues, linked = [], [], set(), [], set()
    for entry in base.iterdir():
        if len(entries) >= MAX_WORKSPACES:
            issues.append('工作区数量达到上限'); break
        if re.fullmatch(r'[0-9a-f]{64}', entry.name) and entry.is_dir() and not entry.is_symlink():
            entries.append(entry)
    for wd in entries:
        risk_db = wd / 'hooks' / wd.name / 'development-risks.db'
        if not risk_db.exists():
            continue
        try:
            for row in signed_rows(risk_db, wd):
                project = row['workspace']
                projects.add(project)
                for risk in row.get('risks', {}).values():
                    for obs in risk.get('observations', []):
                        if obs.get('source') == 'SCANNER':
                            linked.add((obs.get('scan_id'), obs.get('scanner_id')))
                    decision, disposition, status = risk.get('decision'), risk.get('disposition', 'ACTIVE'), risk.get('status')
                    label = ('已暂缓' if disposition == 'DEFER' else '已排除' if disposition == 'EXCLUDE' else
                             '已复查' if status == 'CODE_REVIEWED_RESOLVED' else 'AI 排除' if decision == 'DISMISSED' else
                             '待确认' if decision == 'INCONCLUSIVE' else '待处理')
                    results.append(display(risk.get('finding') or {}, project, label, '已保存的开发风险', risk.get('id', '')))
                    if len(results) >= MAX_RISKS:
                        issues.append('发现数量达到上限'); break
                if len(results) >= MAX_RISKS: break
        except (OSError, ValueError, KeyError, TypeError, sqlite3.Error, json.JSONDecodeError):
            issues.append('部分开发风险记录不可读取或无法核验')
        if len(results) >= MAX_RISKS: break
    for wd in entries:
        path = wd / 'scans.db'
        if not path.exists():
            continue
        try:
            with closing(open_readonly(path)) as db:
                rows = db.execute('SELECT CASE WHEN length(CAST(data AS BLOB)) <= 16000000 THEN data END FROM scans ORDER BY rowid DESC LIMIT ?', (MAX_SCANS + 1,)).fetchall()
            if len(rows) > MAX_SCANS:
                issues.append('部分历史扫描未载入'); rows = rows[:MAX_SCANS]
            for (raw,) in rows:
                if not raw:
                    issues.append('部分扫描记录超出读取上限'); continue
                scan = json.loads(raw)
                project = (scan.get('target_profile') or {}).get('path')
                if not isinstance(project, str) or not Path(project).is_absolute() or identity(os.path.normcase(project)) != wd.name:
                    issues.append('部分扫描记录的项目归属无法核验'); continue
                projects.add(project)
                for f in scan.get('findings', []):
                    if (scan.get('scan_id'), f.get('id')) in linked:
                        continue
                    results.append(display(f, project, '处置未知', '扫描原始候选（历史记录）', str(scan.get('scan_id', '')) + ':' + str(f.get('id', ''))))
                    if len(results) >= MAX_RISKS:
                        issues.append('发现数量达到上限'); break
                if len(results) >= MAX_RISKS: break
        except (OSError, ValueError, TypeError, sqlite3.Error, json.JSONDecodeError):
            issues.append('部分扫描记录不可读取')
        if len(results) >= MAX_RISKS: break
    note = ('；'.join(dict.fromkeys(issues)) + '。' if issues else '') + '仅显示本机全局工作区可读取的开发风险及扫描候选；严格任务等其他记录尚未接入。'
    return {'risks': results[:MAX_RISKS], 'partial': bool(issues), 'note': note, 'projects': sorted(projects)}


class Server(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self):
        super().__init__(('127.0.0.1', 0), Handler)
        self.token = secrets.token_urlsafe(24)
        self.origin = f'http://127.0.0.1:{self.server_port}'


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self):
        if self.headers.get('Host') != urlsplit(self.server.origin).netloc:
            self.send_error(403); return
        path = urlsplit(self.path).path
        if path == f'/{self.server.token}/':
            payload, kind = PAGE.read_bytes(), 'text/html; charset=utf-8'
        elif path == f'/{self.server.token}/api/risks':
            try: payload = json.dumps(records(), ensure_ascii=False).encode()
            except (OSError, ValueError): self.send_error(503); return
            kind = 'application/json; charset=utf-8'
        else:
            self.send_error(404); return
        self.send_response(200)
        self.send_header('Content-Type', kind)
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(payload)


def serve(ready=None):
    server = Server()
    url = f'{server.origin}/{server.token}/'
    if ready is not None:
        Path(ready).write_text(url, encoding='utf-8')
    else:
        print(url, flush=True)
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close()


def launch():
    with tempfile.TemporaryDirectory(prefix='risk-dashboard-') as directory:
        ready = Path(directory) / 'ready'
        command = [sys.executable] if getattr(sys, 'frozen', False) else [sys.executable, '-m', 'security_runtime.cli']
        options = {'creationflags': subprocess.CREATE_NO_WINDOW} if os.name == 'nt' else {'start_new_session': True}
        process = subprocess.Popen(command + ['risk-dashboard', '--ready', str(ready)], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True, **options)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if ready.is_file():
                url = ready.read_text(encoding='utf-8')
                parsed = urlsplit(url)
                if parsed.scheme == 'http' and parsed.hostname == '127.0.0.1' and parsed.port and parsed.path.strip('/'):
                    return url
                break
            if process.poll() is not None: break
            time.sleep(.05)
        process.terminate()
        raise ValueError('RISK_DASHBOARD_START_FAILED')


if __name__ == '__main__':
    serve()
