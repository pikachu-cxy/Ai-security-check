"""Authenticated local management of persisted Runtime findings and development risks."""
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import json
import os
import re
import secrets
import sqlite3
from urllib.parse import urlsplit, parse_qs
from http.cookies import SimpleCookie, CookieError

from security_runtime.hook_state import identity, no_links, native_io_path
from security_runtime.redactor import SecretRedactor
from security_runtime.storage import SQLiteStore
from security_runtime.closeout_state import readonly_uri

PAGE = Path(__file__).resolve().parent / 'assets' / 'risk_dashboard.html'
STATE = SQLiteStore.default_path().parent
MAX_WORKSPACES, MAX_RISKS = 500, 3000
SOURCES = (('codex', 'Codex', 'global-workspaces'), ('cursor', 'Cursor', 'cursor-workspaces'),
           ('workbuddy', 'WorkBuddy', 'workbuddy-workspaces'))
redact = SecretRedactor().redact


def clean(value, fallback='未记录', limit=1500):
    return redact(str(value or fallback))[:limit]


def open_readonly(path):
    no_links(path)
    return sqlite3.connect(readonly_uri(path), uri=True, timeout=2)


def display(f, project, status, source, key, *, editor, editor_label):
    path = clean(f.get('file_path'), '未知位置', 500)
    line = f.get('line_start')
    location = path + (':' + str(line) if type(line) is int and line > 0 else '')
    severity = {'CRITICAL': '严重', 'HIGH': '高', 'MEDIUM': '中', 'LOW': '低', 'INFO': '信息'}.get(str(f.get('severity', '')).upper(), '未评级')
    return dict(id=key, editor=editor, editor_label=editor_label, project=clean(project, '项目未知', 500), title=clean(f.get('plain_title') or f.get('title'), '未命名发现', 250),
                severity=severity, status=status, category=clean(f.get('category'), '未分类', 100), location=location,
                description=clean(f.get('description')), impact=clean(f.get('impact')), advice=clean(f.get('fix_advice')),
                unknowns='此记录未证明当前源码状态；外部防护和可达性需结合原记录复核。', source=source)


def signed_rows(path, workspace_dir):
    """Recover candidate root, then verify root binding and all record signatures."""
    with closing(open_readonly(path)) as db:
        row = db.execute('SELECT CASE WHEN length(CAST(data AS BLOB)) <= 4000000 THEN data END FROM records LIMIT 1').fetchone()
    if not row:
        return []
    if not row[0]:
        raise ValueError('Oversized risk record')
    root = json.loads(row[0]).get('workspace')
    if not isinstance(root, str) or not Path(root).is_absolute() or identity(os.path.normcase(root)) != workspace_dir.name:
        raise ValueError('Invalid workspace binding')
    from .dashboard_history import HistoryRecords
    history = HistoryRecords(path, root)
    if Path(path).name == 'development-checks.db':
        from .business_audit import status as audit_status
        return [dict(row.get('security_result') or {'risks': {}}, workspace=row['workspace'], key=row['key'],
                     has_security_result='security_result' in row, updated_at=row.get('updated_at'),
                     owner=row['owner'], check_metadata=dict(state=row['state'], dirty_seq=row['dirty_seq'],
                     scanned_seq=row['scanned_seq'], audit=audit_status(row), gaps=(row.get('result') or {}).get('gaps', [])))
                for row in history.rows() if row.get('kind') == 'check']
    return history.rows()


def records(*, project_id=None, session_id=None, editor_id=None, workspace_id=None, max_risks=None, complete=False):
    from .project_identity import describe
    from .dashboard_records import enrich
    from .dashboard_history import scan_rows, diagnostic
    maximum = float("inf") if complete else MAX_RISKS if max_risks is None else max_risks
    diagnostics, warnings, missing_projects = [], [], set()
    entries, results, projects, issues, linked = [], [], set(), [], set()
    scopes = {}
    sessions = []
    sources = []
    for editor, label, directory in SOURCES:
        if editor_id and editor != editor_id:
            continue
        base = STATE / directory
        source = dict(id=editor, label=label, status='AVAILABLE', workspace_count=0)
        sources.append(source)
        try:
            no_links(base)
            if not base.exists():
                source['status'] = 'NO_RECORDS'
                continue
            for entry in base.iterdir():
                if workspace_id and entry.name != workspace_id:
                    continue
                if not re.fullmatch(r'[0-9a-f]{64}', entry.name):
                    continue
                no_links(entry)
                if not entry.is_dir():
                    continue
                if not complete and len(entries) >= MAX_WORKSPACES:
                    source['status'] = 'PARTIAL'
                    issues.append(label + '：工作区数量达到读取上限')
                    break
                entries.append((editor, label, entry))
                source['workspace_count'] += 1
        except (OSError, ValueError) as error:
            source['status'] = 'UNAVAILABLE'
            detail = diagnostic(error, editor, '', 'workspace-directory')
            diagnostics.append(detail)
            issues.append(label + '：' + detail['message'])
    for editor, label, wd in entries:
        risk_db = native_io_path(wd / 'hooks' / wd.name / 'development-risks.db')
        result_db = native_io_path(wd / 'hooks' / wd.name / 'development-checks.db')
        manual_db = native_io_path(wd / 'hooks' / wd.name / 'manual-risks.db')
        if not risk_db.exists() and not result_db.exists() and not manual_db.exists():
            continue
        try:
            unified = signed_rows(result_db, wd) if result_db.exists() else []
            migrated = {row['key'] for row in unified if row.get('has_security_result')}
            legacy = signed_rows(risk_db, wd) if risk_db.exists() else []
            manual = signed_rows(manual_db, wd) if manual_db.exists() else []
            for row in [*unified, *(r for r in legacy if r['key'] not in migrated), *manual]:
                if project_id and project_id not in {wd.name, describe(row['workspace'])['project_id']}:
                    continue
                if session_id and not (row.get('owner') or {}).get('session'):
                    issues.append('部分历史开发风险缺少可验证的会话归属，未纳入本会话')
                    continue
                if session_id and row.get('owner', {}).get('session') != session_id:
                    continue
                project = row['workspace']
                if project not in scopes:
                    scopes[project] = describe(project)
                    if not Path(project).exists():
                        missing_projects.add(project)
                if row.get('check_metadata'):
                    sessions.append(dict(row['check_metadata'], **scopes[project], editor=editor,
                        last_security_activity_at=row.get('updated_at'),
                        session_id=(row.get('owner') or {}).get('session', ''), check_id=row['key'],
                        anchor_id=':'.join((editor, wd.name, row['key'], '$scope'))))
                projects.add(project)
                for risk in row.get('risks', {}).values():
                    for obs in risk.get('observations', []):
                        if obs.get('source') == 'SCANNER':
                            linked.add((editor, wd.name, obs.get('scan_id'), obs.get('scanner_id')))
                    decision, disposition, status = risk.get('decision'), risk.get('disposition', 'ACTIVE'), risk.get('status')
                    status_label = ('已暂缓' if disposition == 'DEFER' else '已排除' if disposition == 'EXCLUDE' else
                             '已复查' if status == 'CODE_REVIEWED_RESOLVED' else
                             '重复命中' if (risk.get('assessment') or {}).get('duplicate_of') else 'AI 排除' if decision == 'DISMISSED' else
                             '待处理' if decision == 'CONFIRMED' else '待确认')
                    results.append(enrich(display(risk.get('finding') or {}, project, status_label, '人工记录' if row['key'] == 'manual' else '已保存的开发风险',
                        ':'.join((editor, wd.name, str(row.get('key', '')), str(risk.get('id', '')))),
                        editor=editor, editor_label=label), row, risk, scopes[project]))
                    if len(results) >= maximum:
                        issues.append('发现数量达到上限'); break
                if len(results) >= maximum: break
        except (OSError, ValueError, KeyError, TypeError, AttributeError, sqlite3.Error) as error:
            detail = diagnostic(error, editor, wd.name, 'development-records')
            diagnostics.append(detail)
            issues.append(label + '：' + detail['message'])
        if len(results) >= maximum: break
    for editor, label, wd in entries:
        if session_id:
            continue  # Raw legacy scans carry no verified session binding.
        path = wd / 'scans.db'
        if not path.exists():
            continue
        try:
            for (raw,) in scan_rows(path):
                if not raw:
                    issues.append('部分扫描记录超出读取上限'); continue
                scan = json.loads(raw)
                project = (scan.get('target_profile') or {}).get('path')
                if not isinstance(project, str) or not Path(project).is_absolute() or identity(os.path.normcase(project)) != wd.name:
                    issues.append('部分扫描记录的项目归属无法核验'); continue
                if project_id and project_id not in {wd.name, describe(project)['project_id']}:
                    continue
                projects.add(project)
                for f in scan.get('findings', []):
                    if (editor, wd.name, scan.get('scan_id'), f.get('id')) in linked:
                        continue
                    results.append(display(f, project, '处置未知', '扫描原始候选（历史记录）',
                        ':'.join((editor, wd.name, str(scan.get('scan_id', '')), str(f.get('id', '')))),
                        editor=editor, editor_label=label))
                    if len(results) >= maximum:
                        issues.append('发现数量达到上限'); break
                if len(results) >= maximum: break
        except (OSError, ValueError, TypeError, AttributeError, sqlite3.Error) as error:
            detail = diagnostic(error, editor, wd.name, 'scans.db')
            diagnostics.append(detail)
            issues.append(label + '：' + detail['message'])
        if len(results) >= maximum: break
    if missing_projects:
        warnings.append(f'{len(missing_projects)} 个原项目目录已不存在；已验证签名的历史记录仍完整纳入统计，未复查当前源码。')
    note = ('；'.join(dict.fromkeys(issues)) + '。' if issues else '') + '汇总当前本机用户数据目录中的 Codex、Cursor、WorkBuddy 开发风险和扫描候选。按记录计数，不是去重后的唯一漏洞数；严格审计及其他数据目录尚未接入。'
    note += ''.join(warnings)
    if session_id:
        note += '当前仅展示已验证归属的会话记录；缺少会话绑定的原始扫描不纳入此视图，可从全部风险入口查看。'
    return {'risks': results if complete else results[:maximum], 'sessions': sessions, 'partial': bool(issues), 'note': note, 'projects': sorted(projects), 'sources': sources, 'issues': list(dict.fromkeys(issues)), 'diagnostics': diagnostics, 'warnings': warnings}


class Server(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, settings=None, catalog=None):
        super().__init__(('127.0.0.1', settings['port'] if settings else 0), Handler)
        self.token = settings['token'] if settings else secrets.token_urlsafe(24)
        self.origin = f'http://127.0.0.1:{self.server_port}'
        self.catalog = catalog
        from .dashboard_service import code_id
        self.code_id = code_id()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def authorized(self):
        if self.headers.get('Host') != urlsplit(self.server.origin).netloc:
            return False
        cookies = SimpleCookie()
        try:
            cookies.load(self.headers.get('Cookie', ''))
            return bool(cookies.get('dashboard') and secrets.compare_digest(
                cookies['dashboard'].value, self.server.token))
        except (ValueError, TypeError, CookieError):
            return False

    def reply(self, status, payload, kind='application/json; charset=utf-8', filename=None):
        if not isinstance(payload, bytes):
            payload = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        for key, value in {'Content-Type':kind, 'Content-Length':str(len(payload)),
                'Cache-Control':'no-store', 'Referrer-Policy':'no-referrer',
                'X-Content-Type-Options':'nosniff',
                'Content-Security-Policy':"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"}.items():
            self.send_header(key, value)
        if filename:
            self.send_header('Content-Disposition', 'attachment; filename="'+filename+'"')
        self.end_headers()
        self.wfile.write(payload)

    def query(self):
        values = parse_qs(urlsplit(self.path).query, keep_blank_values=True, max_num_fields=30)
        if any(len(v) != 1 for v in values.values()):
            raise ValueError('DASHBOARD_QUERY_INVALID')
        return {k:v[0] for k,v in values.items()}

    def do_GET(self):
        if self.headers.get('Host') != urlsplit(self.server.origin).netloc:
            self.send_error(403); return
        path = urlsplit(self.path).path
        if path == '/health':
            if self.headers.get('Authorization') != 'Bearer ' + self.server.token:
                self.send_error(403); return
            self.reply(200, dict(service='risk-dashboard-v2', build=self.server.code_id)); return
        if path == f'/{self.server.token}/':
            self.send_response(303)
            self.send_header('Set-Cookie', f'dashboard={self.server.token}; HttpOnly; SameSite=Strict; Path=/')
            self.send_header('Location', '/risks')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.end_headers(); return
        # Loopback reads stay open; the Host check above is the boundary that
        # blocks cross-site and DNS-rebinding access to this process.
        try:
            if path in ('/risks', '/risks/'):
                self.reply(200, PAGE.read_bytes(), 'text/html; charset=utf-8')
            elif path == '/api/session':
                # Reads need no cookie; the CSRF token still requires the
                # one-time browser authorization performed by the editor.
                self.reply(200, dict(csrf=self.server.token if self.authorized() else None,
                                     service='risk-dashboard-v2'))
            elif path == '/api/monitor':
                from .dashboard_health import snapshot
                if self.query():
                    raise ValueError('HEALTH_QUERY_INVALID')
                self.reply(200, snapshot())
            elif path == '/api/detail':
                from .dashboard_detail import detail
                query = self.query()
                if set(query) - {'id', 'revision', 'context'} or not {'id', 'revision'} <= set(query):
                    raise ValueError('DETAIL_QUERY_INVALID')
                self.reply(200, detail(query['id'], query['revision'],
                    context=int(query.get('context', '5')), catalog=self.server.catalog))
            elif path == '/api/entities':
                from .dashboard_entities import listing
                query = self.query()
                if set(query) != {'kind'} or not self.server.catalog:
                    raise ValueError('ENTITY_QUERY_INVALID')
                self.server.catalog.titles.request()
                self.reply(200, listing(self.server.catalog, query['kind']))
            elif path == '/api/config':
                from .user_config import read_config
                from .stop_wait_policy import host_limit
                self.reply(200, dict(effective='NEXT_BATCH', stop_wait_support=host_limit(), **read_config()))
            elif path in ('/api/risks', '/api/export'):
                query = self.query()
                if self.server.catalog:
                    result = self.server.catalog.query(query, export=path == '/api/export')
                else:
                    if set(query) - {'project','workspace','session','editor','check','scan','seq'} or any(
                        not re.fullmatch('[0-9a-f]{64}', query[k]) for k in ('project','workspace','session') if k in query):
                        raise ValueError('DASHBOARD_QUERY_INVALID')
                    result = records(**{k+'_id':v for k,v in query.items()
                                        if k in ('project','workspace','session','editor')})
                    batch = {'scan:' + query['scan']} if query.get('scan') else set()
                    if query.get('seq'):
                        batch.add('seq:' + str(int(query['seq'])))
                    if query.get('check') or batch:
                        # Without the read index there is no batch table, so the
                        # saved items themselves must prove membership.
                        result['risks'] = [row for row in result['risks']
                                           if (not query.get('check') or row.get('check_id') == query['check'])
                                           and (not batch or batch.intersection(row.get('batch_keys') or ()))]
                        result['total'] = len(result['risks'])
                if path == '/api/export':
                    from .dashboard_export import render
                    format = query.get('format', 'json')
                    kind, payload = render(result, format)
                    self.reply(200, payload, kind, 'risks.'+format)
                else:
                    self.reply(200, result)
            else:
                self.send_error(404)
        except ValueError:
            self.reply(400, dict(error='请求参数或保存的数据无效，请刷新核对。'))
        except (OSError, sqlite3.Error):
            self.reply(503, dict(error='本机数据暂时不可用，请稍后重试。'))

    def do_POST(self):
        if self.headers.get('Host') != urlsplit(self.server.origin).netloc:
            self.send_error(403); return
        path = urlsplit(self.path).path
        if path == '/shutdown' and self.headers.get('Authorization') == 'Bearer '+self.server.token:
            self.reply(200, dict(stopping=True))
            import threading
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            return
        if (not self.authorized() or self.headers.get('Origin') != self.server.origin
                or not secrets.compare_digest(self.headers.get('X-CSRF-Token', ''), self.server.token)):
            self.send_error(403); return
        try:
            if self.headers.get('Content-Type') != 'application/json' or self.headers.get('Transfer-Encoding'):
                raise ValueError('DASHBOARD_CONTENT_TYPE_INVALID')
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= 262144:
                raise ValueError('DASHBOARD_BODY_INVALID')
            self.connection.settimeout(5)
            data = json.loads(self.rfile.read(size))
            if not isinstance(data, dict):
                raise ValueError('DASHBOARD_BODY_INVALID')
            from .dashboard_records import mutate, create
            if path == '/api/actions':
                if set(data) != {'items'} or not isinstance(data['items'], list) or not 1 <= len(data['items']) <= 200:
                    raise ValueError('DASHBOARD_BATCH_INVALID')
                results = []
                for item in data['items']:
                    try:
                        if not isinstance(item, dict) or set(item) != {'id','request'}:
                            raise ValueError('DASHBOARD_ITEM_INVALID')
                        result = dict(id=item['id'], **mutate(item['id'], item['request']))
                    except (ValueError, OSError, sqlite3.Error) as exc:
                        result = dict(id=item.get('id') if isinstance(item, dict) else None,
                                      saved=False, error='VERSION_CONFLICT' if 'CONFLICT' in str(exc) else 'ACTION_REJECTED')
                    results.append(result)
                self.reply(200, dict(results=results))
            elif path == '/api/entities':
                from .dashboard_entities import change
                if not self.server.catalog:
                    raise ValueError('ENTITY_INDEX_UNAVAILABLE')
                self.reply(200, change(self.server.catalog, data))
            elif path == '/api/session-alias':
                from .dashboard_sessions import alias
                if not self.server.catalog:
                    raise ValueError('ENTITY_INDEX_UNAVAILABLE')
                self.reply(200, alias(self.server.catalog,data))
            elif path == '/api/session-titles/refresh':
                if data or not self.server.catalog:
                    raise ValueError('SESSION_REFRESH_INVALID')
                self.server.catalog.titles.request()
                self.reply(200, dict(status=self.server.catalog.titles.status))
            elif path == '/api/manual':
                self.reply(200, create(data))
            elif path == '/api/config':
                from .user_config import save_config
                if set(data) != {'values','expected_revision'}:
                    raise ValueError('DASHBOARD_CONFIG_INVALID')
                self.reply(200, save_config(**data))
            else:
                self.send_error(404); return
            if self.server.catalog:
                self.server.catalog.wake.set()
        except ValueError as exc:
            self.reply(409 if 'CONFLICT' in str(exc) else 400,
                       dict(error='版本冲突，请刷新后重试。' if 'CONFLICT' in str(exc) else '操作未保存，请检查参数与记录状态。'))
        except (OSError, sqlite3.Error):
            self.reply(503, dict(error='保存暂时不可用，请稍后重试。'))


def serve(ready=None, *, shared=False):
    from .dashboard_service import endpoint, save_endpoint
    from .dashboard_catalog import Catalog
    catalog = Catalog()
    server = Server(endpoint() if shared else None, catalog=catalog)
    catalog.start()
    if shared:
        save_endpoint(server.server_port, server.token)
    url = f'{server.origin}/{server.token}/'
    if ready is not None:
        Path(ready).write_text(url, encoding='utf-8')
    else:
        print(url, flush=True)
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally:
        catalog.close()
        server.server_close()


def launch():
    from .dashboard_service import ensure
    # Explicit user request: bounded wait, healthy service returns immediately.
    value = ensure(timeout=3)
    return f"http://127.0.0.1:{value['port']}/{value['token']}/"


if __name__ == '__main__':
    serve()
