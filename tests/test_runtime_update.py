import hashlib
from http.client import HTTPConnection
import json
from pathlib import Path
from threading import Thread
import zipfile

import pytest

from security_runtime import dashboard_service, runtime_update as update
from security_runtime.delivery import StableDelivery, encode
from security_runtime.review_delivery import attach_runtime_update, report_page
from test_delivery import bundle


def package(path, version):
    bundle(path)
    meta = path / 'version.json'
    values = json.loads(meta.read_bytes())
    del values['build_id']
    values.update(version=version, source_dirty=False)
    values['build_id'] = hashlib.sha256(encode(values)).hexdigest()
    meta.write_text(json.dumps(values))
    return values['build_id']


class FakeRelease:
    def __init__(self, tmp_path, version='0.3.15'):
        self.version = version
        target = tmp_path / 'target'
        self.build = package(target, version)
        path = tmp_path / 'release.zip'
        with zipfile.ZipFile(path, 'w') as archive:
            for file in target.iterdir():
                archive.write(file, 'security-check/' + file.name)
        self.archive = path.read_bytes()
        self.digest = hashlib.sha256(self.archive).hexdigest()
        self.name = f'ai-security-runtime-v{version}-windows-x64.zip'
        self.base = f'{update.DOWNLOAD}/v{version}/'
        self.downloads = 0
        self.failure = ''
        self.release = dict(tag_name=f'v{version}', published_at='now', draft=False, prerelease=False,
            assets=[dict(name=name, state='uploaded', browser_download_url=self.base + name)
                    for name in ('release-manifest.json', self.name, self.name + '.sha256')])

    def __call__(self, url, limit, destination=None):
        if self.failure in {'offline', 'limited'}:
            from urllib.error import HTTPError
            if self.failure == 'limited':
                raise HTTPError(url, 429, 'limited', {}, None)
            raise OSError('offline')
        if url == update.LATEST:
            return json.dumps(self.release).encode()
        if url == self.base + 'release-manifest.json':
            return json.dumps(dict(version=self.version, source_commit='a' * 40,
                artifacts={'windows-x64': dict(url=self.base + self.name, sha256=self.digest)})).encode()
        if url == self.base + self.name + '.sha256':
            return f'{self.digest}  {self.name}\n'.encode()
        assert destination is not None and url == self.base + self.name
        self.downloads += 1
        if self.failure == 'interrupted':
            raise OSError('download cut off')
        destination.write_bytes(self.archive)
        return '0' * 64 if self.failure == 'checksum' else hashlib.sha256(self.archive).hexdigest()


@pytest.fixture
def installation(tmp_path):
    old = package(tmp_path / 'old', '0.3.14')
    fake = FakeRelease(tmp_path)
    probe = {'status': 'OK'}
    delivery = StableDelivery(tmp_path / 'install', probe=lambda _: probe)
    delivery.activate(tmp_path / 'old')
    clock = [100]
    return update.RuntimeUpdate(delivery, old, 'windows-x64', fetch=fake, now=lambda: clock[0]), fake, probe, clock


@pytest.mark.parametrize('case', ['draft', 'same', 'missing', 'offline', 'limited'])
def test_invalid_release_stays_quiet(installation, case):
    service, fake, _, _ = installation
    if case == 'draft':
        fake.release['draft'] = True
    elif case == 'same':
        fake.release['tag_name'] = 'v0.3.14'
    elif case == 'missing':
        fake.release['assets'].pop()
    else:
        fake.failure = case
    service.refresh()
    assert service.status()['candidate'] is None and fake.downloads == 0


@pytest.mark.parametrize('case', ['success', 'checksum', 'interrupted', 'probe'])
def test_apply_uses_explicit_job_and_preserves_previous(installation, case):
    service, fake, probe, _ = installation
    service.refresh()
    candidate = service.status()['candidate']['id']
    assert fake.downloads == 0
    private = [service.delivery.root / name for name in ('settings', 'history', 'scanners')]
    for path in private:
        path.write_bytes(b'preserve me')
    tickets = []
    assert service.apply(candidate, tickets.append)['status'] == 'QUEUED'
    assert service.apply(candidate, tickets.append)['deduplicated']
    assert len(tickets) == 1 and fake.downloads == 0
    fake.failure = case
    if case == 'probe':
        probe['status'] = 'FAILED'
    assert service.install(tickets[0]) == (case == 'success')
    assert not service.install(tickets[0]) and fake.downloads == 1
    status = service.status()
    assert status['active_build'] == (fake.build if case == 'success' else service.running_build)
    assert status['current_mcp_build'] is None
    assert all(path.read_bytes() == b'preserve me' for path in private)
    assert service.delivery.slot(service.running_build).is_dir()


@pytest.mark.parametrize('failure', [None, 'version', 'build'])
def test_cross_version_update_probes_verified_target(tmp_path, monkeypatch, failure):
    from security_runtime import codex_integration
    from security_runtime.guidance.host_guidance import runtime_info

    monkeypatch.setattr(codex_integration, '__version__', '0.3.15')
    old = package(tmp_path / 'old', '0.3.15')
    release = FakeRelease(tmp_path, version='0.3.16')
    delivery = StableDelivery(tmp_path / 'install')
    delivery.activate(tmp_path / 'old', defer_capability_check=True)

    def probe(runtime, root, env, **expectation):
        slot = Path(runtime['command']).parent
        manifest = json.loads((slot / 'version.json').read_bytes())
        version = '0.3.15' if failure == 'version' else manifest['version']
        build_id = old if failure == 'build' else manifest['build_id']
        info = dict(runtime_info(), version=version, build_identity=dict(version=version, build_id=build_id))
        return codex_integration.check_capabilities(info, codex_integration.REQUIRED_TOOLS, **expectation)

    monkeypatch.setattr(codex_integration, 'probe_runtime', probe)
    service = update.RuntimeUpdate(delivery, old, 'windows-x64', fetch=release)
    service.refresh()
    tickets = []
    service.apply(service.status()['candidate']['id'], tickets.append)
    assert service.install(tickets[0]) == (failure is None)
    status = service.status()
    if failure:
        assert status['active_build'] == old
        assert status['job']['reason'] == f'DELIVERY_PROBE_{failure.upper()}_MISMATCH'
    else:
        assert status['active_build'] == release.build
        monkeypatch.setattr(codex_integration, '__version__', '0.3.16')
        assert delivery.rollback()['active_build'] == old


def test_report_and_last_page_preserve_digest_and_deduplicate(installation, monkeypatch):
    service, fake, _, clock = installation
    service.refresh()
    monkeypatch.setattr(update, 'installed_update', lambda: service)
    monkeypatch.setattr(dashboard_service, 'update_url', lambda: 'http://127.0.0.1:54321/updates')
    fake.failure = 'offline'  # Report assembly uses only the installation cache.
    sample = dict(view='final_report', check_ref='check', dirty_seq=1, scan_id='scan',
                  risks=[], total=1, gaps=[], scope_unknown=False,
                  review_progress={'host_review_completed': True}, report_text='a' * 100000)
    first = report_page(sample, {}, Path('.'))
    assert 'runtime_update_notice' not in attach_runtime_update(first)
    current = first
    while current['next_offset'] is not None:
        current = report_page(sample, {}, Path('.'), current['next_offset'], first['report_digest'])
    final = attach_runtime_update(current)
    assert final['runtime_update_notice']['url'].endswith('/updates')
    assert final['runtime_update_notice']['markdown'] == '存在新版本是否更新：[查看并更新](http://127.0.0.1:54321/updates)'
    assert {k: final[k] for k in current} == current
    assert attach_runtime_update(current) == current
    clock[0] += update.FRESH + 1
    assert 'runtime_update_notice' not in attach_runtime_update(dict(current, dirty_seq=2))


@pytest.mark.parametrize('mode', ['static', 'review', 'incomplete', 'empty'])
def test_report_delivery_scope_and_text_fallback(installation, monkeypatch, mode):
    service, _, _, _ = installation
    service.refresh()
    monkeypatch.setattr(update, 'installed_update', lambda: service)
    monkeypatch.setattr(dashboard_service, 'update_url', lambda: None)
    report = dict(check_ref='check', dirty_seq=1, scan_id='scan', host_review_completed=True,
                  report_text='saved report', total=1, gaps=[])
    if mode == 'static':
        report['closeout_mode'] = 'REPORT'
    elif mode == 'incomplete':
        report['closeout_mode'] = 'INCOMPLETE'
    elif mode == 'empty':
        report['total'] = 0
    result = attach_runtime_update(report)
    if mode in {'static', 'review'}:
        assert result['runtime_update_notice']['fallback']
        assert result['report_text'] == 'saved report'
    else:
        assert result == report


def test_update_page_accepts_same_origin_post_without_dashboard_authorization(installation, monkeypatch):
    from security_runtime.risk_dashboard import Server
    service, fake, _, _ = installation
    service.refresh()
    candidate = service.status()['candidate']['id']
    monkeypatch.setattr(update, 'installed_update', lambda: service)
    jobs = []
    monkeypatch.setattr(update, 'spawn_update', lambda action, ticket: jobs.append(ticket))
    server = Server()
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    client = HTTPConnection('127.0.0.1', server.server_port, timeout=3)
    monkeypatch.setattr(dashboard_service, 'endpoint',
                        lambda: {'port': server.server_port, 'token': server.token})

    def request(method, path, headers=None, body=None):
        client.request(method, path, body=body, headers=headers or {})
        response = client.getresponse()
        response.read()
        return response.status, response.read()

    try:
        assert dashboard_service.update_url() == server.origin + '/updates'
        with monkeypatch.context() as mismatched:
            mismatched.setattr(dashboard_service, 'code_id', lambda: 'other-build')
            assert dashboard_service.update_url() is None
        assert request('GET', '/updates')[0] == 200
        assert request('GET', '/api/updates')[0] == 200
        assert not jobs and not fake.downloads
        body = json.dumps({'candidate_id': candidate})
        headers = {'Origin': server.origin, 'Content-Type': 'application/json'}
        assert request('POST', '/api/updates', dict(headers, Origin='https://example.invalid'), body)[0] == 403
        assert request('POST', '/api/updates', dict(headers, Host='example.invalid'), body)[0] == 403
        assert request('POST', '/api/updates', {'Content-Type': 'application/json'}, body)[0] == 403
        assert request('POST', '/api/updates', {'Origin': server.origin, 'Content-Type': 'text/plain'}, body)[0] == 400
        assert request('POST', '/api/updates', headers, json.dumps({'candidate_id': '0' * 64}))[0] == 400
        assert request('POST', '/api/updates', headers, json.dumps({'url': 'https://example.invalid'}))[0] == 400
        assert request('POST', '/api/actions', headers, '{}')[0] == 403
        assert request('POST', '/api/config', headers, '{}')[0] == 403
        assert request('POST', '/shutdown', headers, '{}')[0] == 403
        assert not jobs and not fake.downloads
        assert request('POST', '/api/updates', headers, body)[0] == 202
        assert request('POST', '/api/updates', headers, body)[0] == 202
        assert len(jobs) == 1 and not fake.downloads
    finally:
        client.close()
        server.shutdown()
        server.server_close()
        thread.join(2)


def test_refresh_scheduler_never_fetches_in_scan_process(installation, monkeypatch):
    service, _, _, _ = installation
    launches = []
    monkeypatch.delenv('SECURITY_RUNTIME_OFFLINE', raising=False)
    monkeypatch.setattr(update, 'installed_update', lambda: service)
    monkeypatch.setattr(update, 'spawn_update', launches.append)
    service.fetch = lambda *args: pytest.fail('network ran in the scan process')
    update.schedule_refresh()
    assert launches == ['_refresh']


def test_archive_path_validation_rejects_traversal(tmp_path):
    path = tmp_path / 'bad.zip'
    with zipfile.ZipFile(path, 'w') as archive:
        archive.writestr('security-check/../escaped', 'invalid')
    with pytest.raises(ValueError, match='UPDATE_ARCHIVE_PATH_INVALID'):
        update.unpack(path, tmp_path, 'windows-x64')
    assert not (tmp_path / 'escaped').exists()


def test_activation_conflict_and_late_validation_leave_old_build(installation, monkeypatch, tmp_path):
    service, _, _, _ = installation
    candidate = tmp_path / 'target'
    old = service.running_build
    with pytest.raises(ValueError, match='DELIVERY_ACTIVE_CONFLICT'):
        service.delivery.activate(candidate, expected_active='0' * 64)
    assert service.delivery.pointer()['active'] == old

    def refuse():
        raise ValueError('post-activation read failed')

    monkeypatch.setattr(service.delivery, 'status', refuse)
    with pytest.raises(ValueError, match='post-activation read failed'):
        service.delivery.activate(candidate, expected_active=old)
    assert service.delivery.pointer()['active'] == old


def test_mac_archive_rejects_escaping_link(tmp_path):
    import io
    import tarfile
    path = tmp_path / 'mac.tar.gz'
    with tarfile.open(path, 'w:gz') as archive:
        item = tarfile.TarInfo('security-check/_internal/item')
        item.size = 1
        archive.addfile(item, io.BytesIO(b'x'))
        link = tarfile.TarInfo('security-check/_internal/sub/alias')
        link.type, link.linkname = tarfile.SYMTYPE, '../../../outside'
        archive.addfile(link)
    with pytest.raises(ValueError):
        update.unpack(path, tmp_path, 'macos-arm64')
    assert not (tmp_path / 'security-check').exists()
