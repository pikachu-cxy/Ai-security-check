"""Per-installation release discovery and explicitly authorized full-package updates."""
from contextlib import closing, contextmanager, nullcontext
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.parse import urlsplit
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener
import zipfile

from .delivery import EXE, StableDelivery, bundle_link_name, is_digest, package_metadata, stable_command
from .hook_state import no_links

REPOSITORY = 'pikachu-cxy/Ai-security-check'
LATEST = f'https://api.github.com/repos/{REPOSITORY}/releases/latest'
DOWNLOAD = f'https://github.com/{REPOSITORY}/releases/download'
PLATFORMS = {'windows-x64': '.zip', 'macos-arm64': '.tar.gz', 'macos-x64': '.tar.gz'}
FRESH = 6 * 3600
RETRY = 1800
MAX_ARCHIVE = 128 * 1024 * 1024
MAX_EXPANDED = 512 * 1024 * 1024
BUSY = ('QUEUED', 'DOWNLOADING', 'VERIFYING', 'ACTIVATING', 'SYNCING_CODEX')
MAX_UPDATE_LOG_EVENTS = 512


def version_key(version):
    if not isinstance(version, str) or not re.fullmatch(r'(0|[1-9][0-9]{0,8})(\.(0|[1-9][0-9]{0,8})){2}', version):
        raise ValueError('UPDATE_VERSION_INVALID')
    return tuple(map(int, version.split('.')))


class ReleaseRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urlsplit(newurl)
        if (target.scheme != 'https' or target.netloc not in {
                'release-assets.githubusercontent.com', 'objects.githubusercontent.com'}):
            raise ValueError('UPDATE_REDIRECT_REJECTED')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def update_error(error, fallback):
    if isinstance(error, HTTPError):
        return 'UPDATE_HTTP_ERROR'
    cause = error.reason if isinstance(error, URLError) else error
    if isinstance(cause, TimeoutError):
        return 'UPDATE_SOCKET_TIMEOUT'
    if isinstance(error, URLError):
        return 'UPDATE_NETWORK_ERROR'
    code = str(error)
    return code if re.fullmatch(r'(UPDATE|DELIVERY)_[A-Z_]+', code) else fallback


def transfer(url, limit, destination=None, *, telemetry=None):
    budget = 120 if destination is not None else 12
    deadline = time.monotonic() + budget
    if telemetry is not None:
        telemetry.update(byte_limit=limit, timeout_s=budget, bytes_received=0)
    request = Request(url, headers={'User-Agent': 'AI-Security-Runtime', 'Accept': 'application/vnd.github+json'}
                      if url == LATEST else {'User-Agent': 'AI-Security-Runtime'})
    digest = hashlib.sha256()
    chunks = []
    size = 0
    with build_opener(ReleaseRedirects()).open(request, timeout=6) as response:
        if telemetry is not None:
            telemetry['http_status'] = response.status
        with (destination.open('xb') if destination is not None else nullcontext()) as output:
            while block := response.read1(65536):
                size += len(block)
                if telemetry is not None:
                    telemetry['bytes_received'] = size
                if size > limit:
                    raise ValueError('UPDATE_TRANSFER_SIZE_LIMIT')
                if time.monotonic() > deadline:
                    raise ValueError('UPDATE_TRANSFER_DEADLINE')
                if destination is None:
                    chunks.append(block)
                else:
                    output.write(block)
                    digest.update(block)
    return b''.join(chunks) if destination is None else digest.hexdigest()


def discover(current_version, platform, fetch=transfer):
    if platform not in PLATFORMS:
        return None
    release = json.loads(fetch(LATEST, 256 * 1024))
    tag = release.get('tag_name', '')
    if (release.get('draft') is not False or release.get('prerelease') is not False
            or not release.get('published_at') or not isinstance(tag, str) or not tag.startswith('v')
            or version_key(tag[1:]) <= version_key(current_version)):
        return None
    version = tag[1:]
    base = f'{DOWNLOAD}/{tag}'
    archive = f'ai-security-runtime-{tag}-{platform}{PLATFORMS[platform]}'
    assets = {item['name']: item for item in release['assets'] if item.get('state') == 'uploaded'}
    for name in ('release-manifest.json', archive, archive + '.sha256'):
        if assets.get(name, {}).get('browser_download_url') != base + '/' + name:
            return None
    manifest_bytes = fetch(base + '/release-manifest.json', 64 * 1024)
    manifest_digest = 'sha256:' + hashlib.sha256(manifest_bytes).hexdigest()
    if assets['release-manifest.json'].get('digest') not in {None, manifest_digest}:
        return None
    manifest = json.loads(manifest_bytes)
    item = manifest.get('artifacts', {}).get(platform, {})
    digest = item.get('sha256')
    source = manifest.get('source_commit', '')
    if (manifest.get('version') != version or not isinstance(source, str)
            or not re.fullmatch('[0-9a-f]{40}', source) or not is_digest(digest)
            or item.get('url') != base + '/' + archive):
        return None
    checksum = fetch(base + '/' + archive + '.sha256', 1024).decode().split()
    if checksum != [digest, archive] or assets[archive].get('digest') not in {None, 'sha256:' + digest}:
        return None
    candidate = dict(version=version, platform=platform, archive=archive, sha256=digest, source_commit=source)
    candidate['id'] = hashlib.sha256(json.dumps(candidate, sort_keys=True).encode()).hexdigest()
    return candidate


def unpack(archive, target, platform):
    zipped = platform == 'windows-x64'
    with (zipfile.ZipFile(archive) if zipped else tarfile.open(archive, 'r:gz')) as package:
        members = []
        expanded = 0
        names = set()
        links = []
        for member in package.infolist() if zipped else package:
            size = member.file_size if zipped else member.size
            expanded += size
            if len(members) >= 15000 or size < 0 or expanded > MAX_EXPANDED:
                raise ValueError('UPDATE_ARCHIVE_LIMIT')
            members.append(member)
            raw = (member.filename if zipped else member.name).rstrip('/')
            path = PurePosixPath(raw)
            name = raw.casefold() if zipped else raw
            if (not path.parts or path.parts[0] != 'security-check' or path.as_posix() != raw
                    or name in names or any(part in {'.', '..'} for part in path.parts)
                    or any(c in raw for c in '\\:<>|"*?') or any(ord(c) < 32 for c in raw)
                    or zipped and any(part.endswith((' ', '.')) or Path(part).is_reserved() for part in path.parts)):
                raise ValueError('UPDATE_ARCHIVE_PATH_INVALID')
            names.add(name)
            if zipped:
                if stat.S_ISLNK(member.external_attr >> 16):
                    raise ValueError('UPDATE_ARCHIVE_LINK_INVALID')
            elif member.issym():
                bundle_link_name('/'.join(path.parts[1:]), member.linkname)
                links.append(path)
            elif not (member.isfile() or member.isdir()):
                raise ValueError('UPDATE_ARCHIVE_TYPE_INVALID')
        if links and any(any(str(parent) in names and parent in links for parent in PurePosixPath(name).parents)
                         for name in names):
            raise ValueError('UPDATE_ARCHIVE_LINK_PARENT')
        if zipped:
            package.extractall(target)
        else:
            package.extractall(target, members=members, filter='data')
    return target / 'security-check'


def sync_managed_codex(target):
    from .global_integration import GlobalCodexIntegration
    integration = GlobalCodexIntegration()
    if integration._manifest(integration.home) is None:
        return
    # The new executable must sign the receipt with its own build identity.
    result = subprocess.run(
        [str(target / EXE), 'repair', '--json'], cwd=integration.home,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=120, check=False,
        **({'creationflags': subprocess.CREATE_NO_WINDOW} if os.name == 'nt' else {}))
    if result.returncode != 0 or json.loads(result.stdout).get('overall') != 'CONFIGURED':
        raise ValueError('UPDATE_CODEX_SYNC_FAILED')


class RuntimeUpdate:
    def __init__(self, delivery, running_build, platform, *, now=time.time, fetch=transfer, sync_codex=None):
        self.delivery = delivery
        self.running_build = running_build
        self.platform = platform
        self.now = now
        self.fetch = fetch
        self.sync_codex = sync_codex
        self.db = delivery.root / 'runtime-updates.db'

    def log(self, operation_id, stage, outcome, **details):
        event = dict(at=self.now(), operation_id=operation_id, stage=stage,
                     outcome=outcome, **details)
        try:
            with self.connection(write=True) as db:
                db.execute('CREATE TABLE IF NOT EXISTS update_log (id INTEGER PRIMARY KEY, event TEXT NOT NULL)')
                db.execute('INSERT INTO update_log (event) VALUES (?)', (json.dumps(event),))
                db.execute('DELETE FROM update_log WHERE id <= '
                           '(SELECT max(id) FROM update_log) - ?', (MAX_UPDATE_LOG_EVENTS,))
        except (OSError, ValueError, sqlite3.Error):
            # Diagnostics must never prevent the update or change its result.
            pass

    @contextmanager
    def stage(self, operation_id, stage, **details):
        start = time.monotonic()
        self.log(operation_id, stage, 'STARTED', **details)
        try:
            yield details
        except Exception as error:
            if isinstance(error, HTTPError):
                details['http_status'] = error.code
            self.log(operation_id, stage, 'FAILED', **details,
                     elapsed_ms=round((time.monotonic() - start) * 1000),
                     reason=update_error(error, 'UPDATE_STAGE_FAILED'))
            raise
        else:
            self.log(operation_id, stage, 'SUCCEEDED', **details,
                     elapsed_ms=round((time.monotonic() - start) * 1000))

    def traced_fetch(self, operation_id):
        def fetch(url, limit, destination=None):
            if destination is not None:
                stage = 'archive_download'
            elif url == LATEST:
                stage = 'release_metadata'
            elif url.endswith('/release-manifest.json'):
                stage = 'release_manifest'
            else:
                stage = 'archive_checksum'
            with self.stage(operation_id, stage) as details:
                if self.fetch is transfer:
                    return transfer(url, limit, destination, telemetry=details)
                if destination is None:
                    return self.fetch(url, limit)
                return self.fetch(url, limit, destination)
        return fetch

    @contextmanager
    def connection(self, *, write=False):
        no_links(self.db)
        path = self.db if write else self.db.as_uri() + '?mode=ro'
        with closing(sqlite3.connect(path, uri=not write, timeout=.03)) as db, db:
            if write:
                db.execute('BEGIN IMMEDIATE')
                db.execute('CREATE TABLE IF NOT EXISTS updates (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
            yield db

    @staticmethod
    def get(db, key):
        row = db.execute('SELECT value FROM updates WHERE key=?', (key,)).fetchone()
        return json.loads(row[0]) if row else {}

    @staticmethod
    def put(db, key, value):
        db.execute('INSERT OR REPLACE INTO updates VALUES (?, ?)', (key, json.dumps(value)))

    def cached(self, db):
        result = self.get(db, 'release')
        return result.get('candidate') if self.now() < result.get('expires', 0) else None

    def active(self):
        pointer = self.delivery.pointer()
        if not pointer:
            raise ValueError('UPDATE_INSTALLATION_UNVERIFIED')
        # The signed pointer names an installed slot. Full byte verification is
        # repeated by StableDelivery before switching, outside the reporting path.
        path = self.delivery.slot(pointer['active']) / 'version.json'
        no_links(path)
        if path.stat().st_size > 4 * 1024 * 1024:
            raise ValueError('UPDATE_INSTALLATION_UNVERIFIED')
        body = path.read_bytes()
        metadata = json.loads(body)
        if (metadata.get('build_id') != pointer['active']
                or hashlib.sha256(body).hexdigest() != pointer.get('manifest_sha256')):
            raise ValueError('UPDATE_INSTALLATION_UNVERIFIED')
        return metadata

    def status(self):
        active = self.active()
        candidate, job, release = None, {}, {}
        if self.db.is_file():
            with self.connection() as db:
                candidate, job = self.cached(db), self.get(db, 'job')
                release = self.get(db, 'release')
        if candidate and version_key(candidate['version']) <= version_key(active['version']):
            candidate = None
        if job.get('status') in BUSY and self.now() > job['deadline']:
            job = dict(job, status='FAILED', reason='UPDATE_INTERRUPTED')
        retry_at = release.get('retry_at', 0)
        release_check = release.get('state', 'NOT_CHECKED')
        if self.now() < release.get('expires', 0):
            release_check = 'FRESH'
        elif release_check == 'CHECKING' and self.now() >= retry_at:
            release_check = 'STALE'
        return dict(status='AVAILABLE' if candidate else 'NO_CANDIDATE',
                    active_version=active['version'], active_build=active['build_id'],
                    service_build=self.running_build, current_mcp_build=None,
                    release_check=release_check, release_check_retry_at=retry_at,
                    candidate={k: candidate[k] for k in ('id', 'version')} if candidate else None,
                    job={k: job[k] for k in ('status', 'reason', 'version') if k in job})

    def refresh(self):
        with self.connection(write=True) as db:
            if self.now() < self.get(db, 'release').get('retry_at', 0):
                return
            self.put(db, 'release', dict(retry_at=self.now() + RETRY, state='CHECKING'))
        operation_id = secrets.token_hex(8)
        try:
            with self.stage(operation_id, 'release_check', platform=self.platform) as details:
                details['active_version'] = self.active()['version']
                candidate = discover(details['active_version'], self.platform, self.traced_fetch(operation_id))
                details['candidate_version'] = candidate['version'] if candidate else None
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            with self.connection(write=True) as db:
                self.put(db, 'release', dict(retry_at=self.now() + RETRY, state='UNAVAILABLE'))
            return
        with self.connection(write=True) as db:
            self.put(db, 'release', dict(candidate=candidate, state='STALE',
                 expires=self.now() + FRESH, retry_at=self.now() + FRESH))

    def apply(self, candidate_id, launcher):
        if not is_digest(candidate_id):
            raise ValueError('UPDATE_CANDIDATE_INVALID')
        with self.connection(write=True) as db:
            active = self.active()
            job = self.get(db, 'job')
            if job.get('status') in BUSY and self.now() <= job['deadline']:
                if job['candidate_id'] != candidate_id:
                    raise ValueError('UPDATE_JOB_CONFLICT')
                return {'status': job['status'], 'deduplicated': True}
            candidate = self.cached(db)
            if (not candidate or candidate['id'] != candidate_id
                    or version_key(candidate['version']) <= version_key(active['version'])):
                raise ValueError('UPDATE_CANDIDATE_STALE')
            ticket = secrets.token_hex(32)
            operation_id = secrets.token_hex(8)
            self.put(db, 'job', dict(status='QUEUED', ticket=ticket, candidate_id=candidate_id,
                                     version=candidate['version'], active=active['build_id'],
                                     operation_id=operation_id,
                                     deadline=self.now() + 600))
        try:
            with self.stage(operation_id, 'install_worker_launch', target_version=candidate['version']):
                launcher(ticket)
        except OSError:
            self.transition(ticket, 'FAILED', 'UPDATE_START_FAILED')
            return {'status': 'FAILED', 'reason': 'UPDATE_START_FAILED'}
        return {'status': 'QUEUED', 'deduplicated': False}

    def transition(self, ticket, status, reason=None):
        with self.connection(write=True) as db:
            job = self.get(db, 'job')
            if job.get('ticket') != ticket or (status == 'ACTIVATING' and self.now() > job['deadline']):
                return False
            self.put(db, 'job', dict(job, status=status, reason=reason))
            return True

    def install(self, ticket):
        with self.connection(write=True) as db:
            job = self.get(db, 'job')
            if job.get('ticket') != ticket or job.get('status') != 'QUEUED' or self.now() > job['deadline']:
                return False
            self.put(db, 'job', dict(job, status='DOWNLOADING'))
        operation_id = job.get('operation_id') or secrets.token_hex(8)
        fetch = self.traced_fetch(operation_id)
        try:
            with self.stage(operation_id, 'candidate_revalidation', target_version=job['version']):
                active = self.active()
                candidate = discover(active['version'], self.platform, fetch)
                if active['build_id'] != job['active'] or not candidate or candidate['id'] != job['candidate_id']:
                    raise ValueError('UPDATE_CANDIDATE_STALE')
            # Keep staging outside the installation and near the short stable
            # root. Desktop-host TEMP can exceed Windows archive path limits.
            with tempfile.TemporaryDirectory(prefix='asr-update-', dir=self.delivery.root.parent) as temporary:
                staging = Path(temporary).resolve(strict=True)
                archive = staging / 'bundle'
                url = f"{DOWNLOAD}/v{candidate['version']}/{candidate['archive']}"
                digest = fetch(url, MAX_ARCHIVE, archive)
                with self.stage(operation_id, 'archive_digest_verification'):
                    if digest != candidate['sha256']:
                        raise ValueError('UPDATE_CHECKSUM_MISMATCH')
                self.transition(ticket, 'VERIFYING')
                with self.stage(operation_id, 'archive_unpack'):
                    bundle = unpack(archive, staging, self.platform)
                with self.stage(operation_id, 'package_identity_verification'):
                    meta = package_metadata(bundle)
                    if (meta['version'] != candidate['version'] or meta['source_commit'] != candidate['source_commit']
                            or meta['source_dirty']):
                        raise ValueError('UPDATE_PACKAGE_IDENTITY_MISMATCH')
                with self.stage(operation_id, 'activation'):
                    if not self.transition(ticket, 'ACTIVATING'):
                        raise ValueError('UPDATE_JOB_CONFLICT')
                    self.delivery.activate(bundle, expected_active=job['active'])
        except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, zipfile.BadZipFile,
                subprocess.SubprocessError) as error:
            reason = update_error(error, 'UPDATE_INSTALL_FAILED')
            self.transition(ticket, 'FAILED', reason)
            self.log(operation_id, 'install_result', 'FAILED', reason=reason)
            return False
        if self.sync_codex is not None:
            self.transition(ticket, 'SYNCING_CODEX')
            try:
                with self.stage(operation_id, 'codex_integration_sync'):
                    self.sync_codex(self.delivery.slot(meta['build_id']))
            except (OSError, ValueError, AttributeError, subprocess.SubprocessError):
                reason = 'UPDATE_CODEX_SYNC_FAILED'
                self.transition(ticket, 'INSTALLED_CODEX_REPAIR_REQUIRED', reason)
                self.log(operation_id, 'install_result', 'INSTALLED_CODEX_REPAIR_REQUIRED', reason=reason)
                return False
        from .mcp_update_proxy import compatible
        status = ('INSTALLED_AWAITING_CONNECTION' if compatible(active, meta)
                  else 'INSTALLED_RECONNECT_REQUIRED')
        self.transition(ticket, status)
        self.log(operation_id, 'install_result', status)
        return True


def installed_update():
    if not getattr(sys, 'frozen', False):
        return None
    try:
        launcher = stable_command()
        if launcher is None:
            return None
        from .toolchain import platform_key
        return RuntimeUpdate(StableDelivery(Path(launcher).parents[1]),
                             Path(sys.executable).absolute().parents[1].name, '-'.join(platform_key()),
                             sync_codex=sync_managed_codex)
    except (OSError, ValueError):
        return None


def spawn_update(action, ticket=None):
    argv = [sys.executable, 'update', action]
    if ticket is not None:
        argv.extend(('--ticket', ticket))
    options = {'creationflags': subprocess.CREATE_NO_WINDOW} if os.name == 'nt' else {'start_new_session': True}
    subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     close_fds=True, **options)


def schedule_refresh():
    if os.getenv('SECURITY_RUNTIME_OFFLINE') == '1':
        return 'OFFLINE'
    try:
        service = installed_update()
        if service is None:
            return 'UNAVAILABLE'
        if service.db.is_file():
            with service.connection() as db:
                release = service.get(db, 'release')
                if service.now() < release.get('retry_at', 0):
                    if service.now() < release.get('expires', 0):
                        return 'FRESH'
                    return 'CHECKING' if release.get('state') == 'CHECKING' else 'BACKOFF'
        with service.stage(secrets.token_hex(8), 'release_worker_launch'):
            spawn_update('_refresh')
        return 'CHECKING'
    except (OSError, ValueError, sqlite3.Error):
        return 'UNAVAILABLE'


def update_status():
    service = installed_update()
    return service.status() if service else {'status': 'UNMANAGED_INSTALLATION'}


def apply_update(candidate_id):
    service = installed_update()
    if service is None:
        raise ValueError('UPDATE_INSTALLATION_UNVERIFIED')
    return service.apply(candidate_id, lambda ticket: spawn_update('_install', ticket))


def report_notice(report):
    """Return optional update metadata for the final page of a current report."""
    complete = (report.get('host_review_completed')
                or (report.get('review_progress') or {}).get('host_review_completed'))
    if (not report.get('scan_id') or not report.get('report_text') or report.get('next_action')
            or report.get('next_offset') is not None or not complete or report.get('closeout_mode') == 'INCOMPLETE'
            or report.get('delivery_status') or not (report.get('total') or report.get('gaps'))):
        return None
    try:
        service = installed_update()
        if service is None or not service.db.is_file():
            return None
        with service.connection() as db:
            candidate = service.cached(db)
        if not candidate or version_key(candidate['version']) <= version_key(service.active()['version']):
            return None
        from .dashboard_service import update_url
        url = update_url()
        batch = hashlib.sha256(json.dumps([report.get('check_ref'), report.get('dirty_seq'),
                                          report.get('scan_id')]).encode()).hexdigest()
        with service.connection(write=True) as db:
            if service.cached(db) != candidate:
                return None
            if service.get(db, 'report:' + batch):
                return None
            notice_key = ('notice:' if url else 'fallback-notice:') + candidate['version']
            report_key = ('report:' if url else 'fallback-report:') + batch
            previous = service.get(db, notice_key)
            if previous.get('batch') == batch or service.now() < previous.get('until', 0):
                return None
            if not url and service.get(db, report_key):
                return None
            service.put(db, notice_key, dict(batch=batch, until=service.now() + 86400))
            service.put(db, report_key, dict(offered=True))
        service.log(secrets.token_hex(8), 'update_notice', 'LINK' if url else 'FALLBACK',
                    target_version=candidate['version'])
        from ._version import __version__
        label = '查看并更新'
        return dict(current_version=__version__, target_version=candidate['version'], candidate_id=candidate['id'],
                    url=url, label=label, markdown=f'存在新版本是否更新：[{label}]({url})' if url else None,
                    fallback=None if url else '存在新版本是否更新：请在风险管理页面打开「工具更新」。')
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error):
        return None
