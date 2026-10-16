"""Owned, detached preparation; resume saved closeouts through ordinary MCP.

No project discovery, alternate downloader, Hook invocation or repair grant.
Only closeouts explicitly registered while this preparation is active are run.
"""
from __future__ import annotations

import asyncio
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import time
import uuid

from .closeout_state import digest, readonly_uri
from .download_estimate import DownloadEstimate
from .hook_state import HookStateStore, no_links
from .install_progress import InstallationProgress, STAGES, validate_preparation_event
from .install_readiness import prepare_installation_readiness, validate_readiness_receipt
from .storage import SQLiteStore
from .progress import ProgressReporter, ScanCancelled, progress_context

ACTIVE = {'QUEUED', 'PREPARING', 'RESUMING'}
LEASE_SECONDS = 120
MAX_PENDING = 128
RESUME_SECONDS = 300


def runtime_command(executable=None):
    # Never use a command read from the host's editable configuration.
    if executable is not None or getattr(sys, 'frozen', False):
        return [str(executable or sys.executable)]
    return [sys.executable, '-m', 'security_runtime.cli']


class PreparationStore:
    def __init__(self, path=None, *, now=time.time):
        self.path = Path(path or SQLiteStore.default_path().parent / 'preparation.db')
        self.now = now

    def _write(self):
        no_links(self.path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(self.path, timeout=1)
        db.execute('CREATE TABLE IF NOT EXISTS preparation (id INTEGER PRIMARY KEY, data TEXT NOT NULL)')
        db.execute('CREATE TABLE IF NOT EXISTS waiting (workspace TEXT, ref TEXT, data TEXT, mac TEXT, '
                   'PRIMARY KEY(workspace, ref))')
        db.commit()
        db.execute('BEGIN IMMEDIATE')
        return db

    def _load(self, db):
        row = db.execute('SELECT data FROM preparation WHERE id=1').fetchone()
        if row is None:
            return None
        if len(row[0]) > 256_000:
            raise ValueError('Preparation state invalid')
        value = json.loads(row[0])
        if (not isinstance(value, dict) or value.get('contract') != 'background-preparation-v1'
                or value.get('status') not in ACTIVE | {'READY', 'PARTIAL', 'FAILED'}):
            raise ValueError('Preparation state invalid')
        return value

    def _save(self, db, value):
        db.execute('INSERT OR REPLACE INTO preparation VALUES(1,?)', (json.dumps(value),))

    def status(self):
        no_links(self.path)
        if not self.path.is_file():
            return {'status': 'NOT_STARTED', 'ready': False, 'message': '尚未开始后台准备。'}
        with closing(sqlite3.connect(readonly_uri(self.path), uri=True)) as db:
            value = self._load(db)
        if value is None:
            return {'status': 'NOT_STARTED', 'ready': False}
        if value['status'] in ACTIVE and value['lease_until'] <= self.now():
            value.update(status='INTERRUPTED', ready=False, reason='WORKER_LEASE_EXPIRED')
        if self.now() - value.get('progress_at', 0) > 10:
            value['estimate'] = None
        # A receipt proves readiness at verification time, not forever.
        database = (value.get('receipt') or {}).get('vulnerability_db', {})
        if value.get('ready') and database.get('next_update'):
            from datetime import datetime
            if datetime.fromisoformat(database['next_update']).timestamp() <= self.now():
                value.update(status='STALE', ready=False, reason='DATABASE_EXPIRED')
        value.pop('ticket', None)
        return value

    def reserve(self, command, build):
        with closing(self._write()) as db, db:
            previous = self._load(db)
            if previous and previous['status'] in ACTIVE and previous['lease_until'] > self.now():
                return previous, False
            value = dict(contract='background-preparation-v1', job_id=uuid.uuid4().hex,
                ticket=uuid.uuid4().hex, status='QUEUED', ready=False, build_id=build,
                command=command, started_at=self.now(), updated_at=self.now(), lease_until=self.now()+LEASE_SECONDS,
                stage=None, progress=None, estimate=None, receipt=None, reason=None)
            value['queue_epoch'] = 0
            self._save(db, value)
            return value, True

    def update(self, job_id, ticket, **changes):
        with closing(self._write()) as db, db:
            value = self._load(db)
            if value is None or value['job_id'] != job_id or value['ticket'] != ticket:
                return False
            if value['status'] not in ACTIVE:
                return False
            value.update(changes, updated_at=self.now(), lease_until=self.now()+LEASE_SECONDS)
            self._save(db, value)
            return True

    def claim(self, job_id, ticket, command, build):
        with closing(self._write()) as db, db:
            value = self._load(db)
            if (not value or value['job_id'] != job_id or value['ticket'] != ticket
                    or value['status'] != 'QUEUED' or value['lease_until'] <= self.now()
                    or value['command'] != command or value['build_id'] != build):
                return False
            value.update(status='PREPARING', updated_at=self.now(), lease_until=self.now()+LEASE_SECONDS)
            self._save(db, value)
            return True

    def enqueue(self, root, ref, hooks, build, state_dir, generation=1):
        root = Path(root).resolve(strict=True)
        key = hooks.key(root)
        value = {'workspace': str(root), 'closeout_ref': ref, 'hooks_dir': str(hooks.directory.absolute()),
                 'state_dir': str(Path(state_dir).absolute()), 'build_id': build,
                 'generation': generation, 'status': 'WAITING', 'attempts': 0}
        with closing(self._write()) as db, db:
            job = self._load(db)
            if not job or job['status'] not in ACTIVE or job['lease_until'] <= self.now():
                return False
            if job['build_id'] != build:
                return False
            old = db.execute('SELECT data FROM waiting WHERE workspace=? AND ref=?', (str(root), ref)).fetchone()
            if old:
                previous = json.loads(old[0])
                if previous['status'] == 'WAITING' and previous.get('generation') == generation:
                    return True
            count = db.execute("SELECT count(*) FROM waiting WHERE json_extract(data,'$.status')='WAITING'").fetchone()[0]
            if count >= MAX_PENDING:
                raise ValueError('Preparation continuation budget exceeded')
            db.execute('INSERT OR REPLACE INTO waiting VALUES(?,?,?,?)',
                (str(root), ref, json.dumps(value), digest(key, value)))
            job['queue_epoch'] = job.get('queue_epoch', 0)+1
            self._save(db, job)
            return True

    def finish_if_epoch(self, job_id, ticket, epoch):
        # Closing the queue and accepting a late arrival share one transaction.
        with closing(self._write()) as db, db:
            value = self._load(db)
            if (not value or value['job_id'] != job_id or value['ticket'] != ticket
                    or value['status'] != 'RESUMING' or value.get('queue_epoch', 0) != epoch):
                return False
            value.update(status='READY', ready=True, updated_at=self.now())
            self._save(db, value)
            return True

    def waiters(self):
        no_links(self.path)
        if not self.path.is_file():
            return []
        with closing(sqlite3.connect(readonly_uri(self.path), uri=True)) as db:
            rows = db.execute('SELECT data, mac FROM waiting ORDER BY rowid LIMIT ?', (MAX_PENDING,)).fetchall()
        result = []
        for raw, mac in rows:
            try:
                if len(raw) > 16_000:
                    continue
                value = json.loads(raw)
                if value['status'] != 'WAITING':
                    continue
                hooks = HookStateStore(Path(value['hooks_dir']))
                root = Path(value['workspace'])
                key_path = hooks.workspace_directory(root) / 'snapshot.key'
                no_links(key_path)
                key = key_path.read_bytes()  # Read-only: never invent a missing key.
                import hmac
                if len(key) == 32 and hmac.compare_digest(mac, digest(key, value)):
                    result.append(value)
            except (ValueError, KeyError, TypeError, OSError):
                continue
        return result

    def finish_waiter(self, item, status):
        hooks = HookStateStore(Path(item['hooks_dir']))
        key_path = hooks.workspace_directory(Path(item['workspace'])) / 'snapshot.key'
        no_links(key_path)
        key = key_path.read_bytes()
        # Compare-and-swap: a newer registration cannot be cleared by an old runner.
        with closing(self._write()) as db, db:
            row = db.execute('SELECT data,mac FROM waiting WHERE workspace=? AND ref=?',
                             (item['workspace'], item['closeout_ref'])).fetchone()
            if row and json.loads(row[0]) == item and row[1] == digest(key, item):
                updated = dict(item, status=status, attempts=item['attempts']+1)
                db.execute('UPDATE waiting SET data=?,mac=? WHERE workspace=? AND ref=?',
                    (json.dumps(updated), digest(key, updated), item['workspace'], item['closeout_ref']))


def start_background_preparation(executable=None, *, store=None, build=None):
    store = store or PreparationStore()
    if os.getenv('SECURITY_RUNTIME_OFFLINE') == '1':
        return {'status': 'OFFLINE', 'ready': False, 'message': '离线安装未启动下载；已有缓存和待检任务保留。'}
    if build is None:
        if executable is not None:
            # Caller supplied only the just-verified activated slot, never a
            # host config command. Newer bundle pins belong to that slot.
            metadata_path = Path(executable).parent / 'version.json'
            no_links(metadata_path)
            build = json.loads(metadata_path.read_bytes())['build_id']
        else:
            from .build_identity import build_identity
            build = build_identity().get('build_id')
    if not isinstance(build, str) or len(build) != 64:
        raise ValueError('Background build cannot be identified')
    command = runtime_command(executable)
    value, launch = store.reserve(command, build)
    if launch:
        argv = command + ['preparation-worker', '--job', value['job_id'], '--ticket', value['ticket']]
        # No inherited console/protocol handles. On Windows, DETACHED_PROCESS
        # would make CREATE_NO_WINDOW ineffective; Python's venv launcher can
        # then create a console for its child interpreter.
        options = {'creationflags': subprocess.CREATE_NO_WINDOW} if os.name == 'nt' else {'start_new_session': True}
        try:
            subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, close_fds=True, cwd=str(store.path.parent), **options)
        except OSError:
            store.update(value['job_id'], value['ticket'], status='FAILED', reason='WORKER_START_FAILED')
    return store.status() | {'reused': not launch}


async def _resume_one(command, item, *, timeout=120):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    env = dict(os.environ, SECURITY_RUNTIME_OFFLINE='1', SECURITY_RUNTIME_BACKGROUND_RESUME='1',
               SECURITY_RUNTIME_WORKSPACE=item['workspace'], SECURITY_RUNTIME_MCP_SELF_TEST='1',
               SECURITY_RUNTIME_STATE_DIR=item['state_dir'])
    env.pop('SECURITY_RUNTIME_GLOBAL', None)
    if Path(item['hooks_dir']) != Path(item['state_dir']) / 'hooks':
        return 'NEEDS_RETRY'
    params = StdioServerParameters(command=command[0], args=command[1:]+['mcp'],
        env=env, cwd=Path(item['workspace']))
    with open(os.devnull, 'w') as stderr:
        async with asyncio.timeout(timeout):
            async with stdio_client(params, errlog=stderr) as (read, write):
                async with ClientSession(read, write) as client:
                    await client.initialize()
                    info_result = await client.call_tool('get_runtime_info', {})
                    info = info_result.structuredContent or json.loads(info_result.content[0].text)
                    info = info.get('result', info)
                    if info_result.isError or info['build_identity']['build_id'] != item['build_id']:
                        return 'NEEDS_RETRY'
                    response = await client.call_tool('run_closeout_check',
                        {'workspace_path': item['workspace'], 'closeout_ref': item['closeout_ref']})
                    if response.isError:
                        return 'NEEDS_RETRY'
                    data = response.structuredContent or json.loads(response.content[0].text)
                    data = data.get('result', data)
                    return 'COMPLETED' if data['status'] == 'COMPLETED' and data['current_version'] else 'NEEDS_RETRY'


def run_worker(job_id, ticket, *, store=None, prepare=None, resume=None, command=None, build=None):
    store = store or PreparationStore()
    command = command or runtime_command()
    if build is None:
        from .build_identity import build_identity
        build = build_identity().get('build_id')
    if not store.claim(job_id, ticket, command, build):
        return 2
    stop = threading.Event()
    estimate = DownloadEstimate()
    def heartbeat():
        while not stop.wait(20):
            if not store.update(job_id, ticket):
                return
    thread = threading.Thread(target=heartbeat, daemon=True)
    thread.start()
    reporter = ProgressReporter()
    ceiling = threading.Timer(1800, reporter.cancel)
    ceiling.daemon = True
    ceiling.start()
    last_write = 0
    def progress(event):
        nonlocal last_write
        if isinstance(event, str):
            if event in STAGES:
                store.update(job_id, ticket, stage=event)
            return
        value = validate_preparation_event(event)
        if value is None:
            return
        now = time.monotonic()
        if value['event'] == 'DOWNLOAD_PROGRESS':
            estimate.update(value['received_bytes'], value['total_bytes'], now)
            if now-last_write < 1:
                return
        else:
            estimate.reset()
        store.update(job_id, ticket, progress=value, progress_at=store.now(), estimate=estimate.estimate(now))
        last_write = now
    try:
        with progress_context(reporter):
            receipt = (prepare or prepare_installation_readiness)(progress=progress, offline=False,
                adaptive=True, timeout_seconds=300, max_wait_seconds=1800, idle_seconds=30, retries=0)
            reporter.checkpoint()
        ceiling.cancel()
        if not validate_readiness_receipt(receipt):
            raise ValueError('Invalid preparation receipt')
        from .component_health import component_feedback
        component_feedback(receipt['tools'], consume=False)
        if not store.update(job_id, ticket, status='RESUMING' if receipt['ready'] else 'PARTIAL',
                receipt=receipt, ready=receipt['ready'], reason=None if receipt['ready'] else 'SCANNERS_NOT_READY'):
            return 2
        if receipt['ready']:
            deadline = time.monotonic()+RESUME_SECONDS
            # One bounded pass; risks/coverage limits never create an infinite
            # retry loop. A BUSY/new-edit/timeout remains in its original job.
            attempted = set()
            while time.monotonic() < deadline:
                epoch = store.status().get('queue_epoch', 0)
                pending = [i for i in store.waiters() if (i['workspace'], i['closeout_ref'], i['generation']) not in attempted
                           and i['build_id'] == build]
                if not pending:
                    if store.finish_if_epoch(job_id, ticket, epoch):
                        break
                    continue
                for item in pending:
                    if time.monotonic() >= deadline:
                        break
                    attempted.add((item['workspace'], item['closeout_ref'], item['generation']))
                    try:
                        if resume:
                            result = resume(command, item)
                        else:
                            result = asyncio.run(_resume_one(command, item,
                                timeout=min(120, max(1, deadline-time.monotonic()))))
                    except Exception:
                        result = 'NEEDS_RETRY'
                    store.finish_waiter(item, result)
            store.update(job_id, ticket, status='READY', ready=True)
        return 0 if receipt['ready'] else 2
    except ScanCancelled:
        store.update(job_id, ticket, status='FAILED', ready=False, reason='PREPARATION_BUDGET_EXHAUSTED')
        return 2
    except Exception:
        store.update(job_id, ticket, status='FAILED', ready=False, reason='BACKGROUND_PREPARATION_FAILED')
        return 2
    finally:
        ceiling.cancel()
        stop.set()
        thread.join(timeout=1)


def preparation_message(value):
    if value.get('current_readiness'):
        message = value['current_readiness']['message']
        if value['status'] in ACTIVE:
            background = {k: v for k, v in value.items() if k != 'current_readiness'}
            message = preparation_message(background) + '\n' + message
        health = value.get('component_health') or {}
        if health.get('notify'):
            message += '\n' + health['message']
        return message
    status = value['status']
    if status == 'READY':
        return '扫描能力已准备完成；已登记的待检任务按各自收尾回执确认结果。'
    if status == 'RESUMING':
        return '扫描能力已准备完成，正在通过普通 MCP 接续已登记的收尾检查。'
    if status not in ACTIVE:
        receipt = value.get('receipt') or {}
        return receipt.get('message') or '扫描能力尚未就绪；已有缓存和待检任务保留。请查询组件状态查看具体原因，先不要重复安装。'
    message = '扫描能力正在后台准备，安装已完成，无需手动执行前置命令。'
    event = value.get('progress') or {}
    if event.get('event') == 'DOWNLOAD_PROGRESS':
        done, total = event['received_bytes'], event['total_bytes']
        filled = min(20, done*20//total)
        message += ' 下载 [' + '#'*filled + '-'*(20-filled) + f'] {done/total*100:.1f}%'
        if value.get('estimate'):
            message += f"，预计剩余 {value['estimate']['remaining_seconds']} 秒。"
        else:
            message += '，剩余时间估算中。'
    return message


def current_preparation():
    """Advisory read: corrupt/locked state never blocks a local quick check."""
    try:
        value = PreparationStore().status()
        if getattr(sys, 'frozen', False) and value.get('build_id'):
            from .build_identity import build_identity
            current = build_identity().get('build_id')
            value['build_match'] = current == value['build_id']
            if not value['build_match']:
                value['ready'] = False
                if value['status'] not in ACTIVE:
                    value.update(status='OTHER_BUILD', reason='PREPARATION_BUILD_MISMATCH')
        return value
    except (OSError, ValueError, sqlite3.DatabaseError, KeyError, TypeError):
        return {'status': 'UNKNOWN', 'ready': False, 'reason': 'PREPARATION_STATE_UNAVAILABLE'}


def read_preparation_status():
    """Explicit status query: current availability plus one-time health notices.

    The historical worker receipt is retained, so a manual repair cannot be
    mistaken for execution of old pending scans or closeouts.
    """
    value = current_preparation()
    receipt = prepare_installation_readiness(offline=True)
    from .component_health import component_feedback
    value.update(background_receipt=value.get('receipt'), background_reason=value.get('reason'),
                 receipt=receipt, current_readiness=receipt, receipt_current=True,
                 component_health=component_feedback(receipt['tools']),
                 components_ready=all(item['ready'] for item in receipt['tools'].values()),
                 background_status=value['status'])
    if value['status'] not in ACTIVE and value.get('build_match') is not False:
        value.update(status=receipt['status'], ready=receipt['ready'],
                     reason=None if receipt['ready'] else 'COMPONENTS_NOT_READY')
    value['message'] = preparation_message(value)
    return value


def watch_preparation(store=None):
    read = store.status if store is not None else current_preparation
    store = store or PreparationStore()
    previous = None
    with InstallationProgress(preparation=True, adaptive=True) as progress:
        while True:
            value = read()
            if value.get('stage'):
                progress(value['stage'])
            event = value.get('progress')
            if event and event != previous:
                progress(event)
                previous = event
            if value['status'] not in ACTIVE:
                progress.finish(value.get('ready', False))
                return value
            time.sleep(1)
