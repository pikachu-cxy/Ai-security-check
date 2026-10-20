"""Source policy v2 preserves code meaning while removing synthetic credentials."""
import hashlib
import json
import sqlite3

import pytest

from security_runtime.local_evidence import safe_source, legacy_safe_source
from security_runtime.source_redaction import task_version
from security_runtime.task_preimages import TaskPreimageUnavailable
from test_task_preimages import sample, FIRST
from test_task_security import service
from task_review_helpers import review_all


@pytest.mark.parametrize('source,path', [
    ('if status == "REVIEWED":\n    return record["review_ledger"]', 'a.py'),
    ('# SQLite\'s transaction preserves ownership\nvalue = "normal text"', 'a.py'),
    ('// @ts-ignore\nconst pattern = /[//]value/;\nconst label = `hello ${name}`;', 'a.ts'),
    ('url = "https://example.invalid/api?sort=name"', 'a.py'),
    ('digest = "' + 'abcdef0123456789'*4 + '"', 'a.py'),
    ('def test_a_very_long_descriptive_function_name():\n    return True', 'a.py'),
    ('password = request.password\ntoken = obtain_token()\nkey = os.getenv("API_KEY")', 'a.py'),
    ('password = ""\napi_key = "${API_KEY}"', 'a.py'),
    ('<!-- public note -->\n<path>/data/public</path>', 'a.xml'),
])
def test_ordinary_source_remains_readable(source, path):
    assert safe_source(source, source_path=path) == source.splitlines()


@pytest.mark.parametrize('source,path', [
    ('password = "synthetic-private-value"; verify(user)', 'a.py'),
    ('config = {"api_key": "synthetic-private-value"}', 'a.py'),
    ('headers["Authorization"] = "synthetic-private-value"', 'a.py'),
    ('client(secret_key="synthetic-private-value")', 'a.py'),
    ('token = os.getenv("TOKEN", "synthetic-private-value")', 'a.py'),
    ('args = ["--password", "synthetic-private-value"]', 'a.py'),
    ('String dbPassword = "synthetic-private-value";', 'A.java'),
    ('API_KEY=synthetic-private-value\nMODE=development', '.env'),
    ('api_key: synthetic-private-value\nmode: development', 'a.yml'),
    ('# api_key=synthetic-private-value\nverify_control()', 'a.py'),
    ('url = "postgres://user:synthetic-private-value@localhost/db"', 'a.py'),
    ('url = "https://host/api?token=synthetic-private-value&sort=name"', 'a.py'),
    ('<password>synthetic-private-value</password>', 'a.xml'),
    ('<property name="db.password" value="synthetic-private-value"/>', 'a.xml'),
    ('config = {"pass\\u0077ord": "synthetic-private-value"}', 'a.py'),
    ('const apiKey: string = "synthetic-private-value";', 'a.ts'),
    ('password: str = "synthetic-private-value"', 'a.py'),
    ('client.setPassword("synthetic-private-value")', 'a.java'),
    ('password = ("synthetic-" + "private-value")', 'a.py'),
    ('# password="synthetic-\\"private-value"', 'a.py'),
    ('password: |\n  synthetic-private-value\nmode: development', 'a.yml'),
    ('Use token = synthetic-private-value\nPublic documentation.', 'README.md'),
    ('"password": >-\n  synthetic-private-value\nmode: development', 'a.yml'),
    ('<property value="synthetic-private-value" name="db.password"/>', 'a.xml'),
])
def test_credential_values_hidden_without_losing_all_surrounding_code(source, path):
    lines = safe_source(source, source_path=path)
    result = '\n'.join(lines)
    assert 'synthetic-private-value' not in result
    assert '[REDACTED_SECRET]' in result
    assert len(lines) == len(source.splitlines())
    assert safe_source(result, source_path=path) == lines


@pytest.mark.parametrize('value', [
    'sk-' + 'syntheticOnly12345', 'ghp_' + 'A'*24,
    'AKIA' + 'A'*16, 'github_pat_' + 'a'*30,
    'eyJ' + 'a'*12 + '.' + 'b'*12 + '.' + 'c'*12,
    'sk\\u002d' + 'syntheticOnly12345',
])
def test_known_token_shapes_hidden_even_in_an_ordinary_literal(value):
    source = 'label = "' + value + '"'
    result = '\n'.join(safe_source(source, source_path='a.py'))
    assert value not in result and '[REDACTED_SECRET]' in result


@pytest.mark.parametrize('newline', ['\n', '\r\n', '\r'])
@pytest.mark.parametrize('closed', [False, True])
def test_private_key_blocks_and_multiline_credential_values_keep_line_numbers(newline, closed):
    source = newline.join(['value = """-----BEGIN PRIVATE KEY-----', 'synthetic-middle', 'synthetic-tail'])
    if closed:
        source += newline + '-----END PRIVATE KEY-----"""'
    result = safe_source(source, source_path='a.py')
    assert len(result) == len(source.splitlines())
    assert 'synthetic-middle' not in '\n'.join(result) and 'synthetic-tail' not in '\n'.join(result)
    credential = 'password = """' + newline + 'synthetic-middle' + newline + '"""'
    assert 'synthetic-middle' not in '\n'.join(safe_source(credential, source_path='a.py'))


def test_scanner_secret_ranges_still_override_readable_code():
    assert safe_source('normal = "public"\nsecret_material\nverify()', [(2, 2)], source_path='a.py') == [
        'normal = "public"', '[REDACTED_SECRET]', 'verify()']


def test_large_ordinary_identifier_is_only_truncated_not_secret_redacted():
    source = 'x' * 250_000
    truncated = []
    assert safe_source(source, source_path='a.py', truncation_lines=truncated) == ['x' * 600]
    assert truncated == [1]


@pytest.mark.parametrize('version', [True, False, 0, 3, '2', None])
def test_unsupported_policy_never_silently_falls_back(version):
    with pytest.raises(ValueError, match='Unsupported source redaction policy'):
        safe_source('password = "synthetic-private-value"', redaction_version=version)


def test_new_preimages_label_v2_keep_ordinary_literals_and_never_persist_credentials(sample):
    store, _ = sample
    raw = b'role = "reader"\npassword = "synthetic-private-value"\n'
    with store.writer(FIRST) as writer:
        ref = writer.put_source('a.py', raw)['reference']
    assert ref['redaction_version'] == 2
    before = store.path.read_bytes()
    assert store.read(FIRST, 'a.py', ref['raw_sha256'], ref)[0] == 'role = "reader"'
    assert b'synthetic-private-value' not in before
    assert store.path.read_bytes() == before


def test_signed_legacy_preimages_are_read_as_stored_not_reconstructed(sample):
    from security_runtime.closeout_state import digest, encode
    store, _ = sample
    raw = b'role = "reader"\npassword = "synthetic-private-value"\n'
    with store.writer(FIRST) as writer:
        current = writer.put_source('a.py', raw)['reference']
    body = json.dumps(legacy_safe_source(raw.decode(), source_path='a.py'), ensure_ascii=False, separators=(',', ':')).encode()
    metadata = {k:v for k,v in current.items() if k != 'mac'}
    metadata.update(redaction_version=1, body_sha256=hashlib.sha256(body).hexdigest(), body_bytes=len(body))
    mac = digest(store._key(), metadata)
    legacy = dict(metadata, mac=mac)
    with sqlite3.connect(store.path) as db:
        db.execute('UPDATE task_preimages SET metadata=?,mac=?,body=?', (encode(metadata).decode(), mac, body))
        db.execute('DELETE FROM task_preimage_semantics')
    before = store.path.read_bytes()
    assert store.read(FIRST, 'a.py', legacy['raw_sha256'], legacy) == legacy_safe_source(raw.decode(), source_path='a.py')
    assert store.path.read_bytes() == before
    assert task_version({'baseline': {}}) == 1
    assert task_version({'baseline': {'redaction_version': 2}}) == 2


@pytest.mark.parametrize('version', [True, False, 0, 3, '2', None])
def test_even_authenticated_reference_rejects_unsupported_policy(sample, version):
    from security_runtime.closeout_state import digest
    store, _ = sample
    with store.writer(FIRST) as writer:
        current = writer.put_source('a.py', b'role = "reader"\n')['reference']
    metadata = {k: v for k, v in current.items() if k != 'mac'}
    metadata['redaction_version'] = version
    invalid = dict(metadata, mac=digest(store._key(), metadata))
    with pytest.raises(TaskPreimageUnavailable) as error:
        store.read(FIRST, 'a.py', current['raw_sha256'], invalid)
    assert error.value.reason_code == 'TASK_PREIMAGE_REFERENCE_UNVERIFIED'
    assert store.read(FIRST, 'a.py', current['raw_sha256'], current) == ['role = "reader"']


def test_visible_status_string_change_can_complete_all_task_review_units(service):
    tasks, root, runtime = service
    (root / 'visible.py').write_text('if status == "OLD":\n    allow()\n')
    ref = tasks.begin(root, 'visible-literal-change')['task_ref']
    (root / 'visible.py').write_text('if status == "NEW":\n    allow()\n')
    packet = tasks.prepare(root, ref, protocol_version=3)
    delivered, units = review_all(tasks, root, ref, packet)
    text = json.dumps(delivered)
    assert 'OLD' in text and 'NEW' in text
    result = tasks.submit(root, ref, packet['review_session'], [], 'REVIEWED', [])
    assert result['result_saved'] and result['review_progress']['coverage'] == 'REVIEWED'
    assert len(runtime.calls) == 1


def test_existing_task_pins_legacy_policy_for_current_and_added_files(service):
    from security_runtime.closeout_state import digest, encode
    tasks, root, _ = service
    old = b'role = "reader"\n'
    (root / 'a.py').write_bytes(old)
    ref = tasks.begin(root, 'legacy-policy-in-progress')['task_ref']
    record = tasks.load(root, ref)
    private = tasks.preimages(root)
    current = record['baseline']['preimages']['a.py']
    body = json.dumps(legacy_safe_source(old.decode(), source_path='a.py'), separators=(',', ':')).encode()
    metadata = {k: v for k, v in current.items() if k != 'mac'}
    metadata.update(redaction_version=1, body_sha256=hashlib.sha256(body).hexdigest(), body_bytes=len(body))
    mac = digest(private._key(), metadata)
    with sqlite3.connect(private.path) as db:
        db.execute('UPDATE task_preimages SET metadata=?,mac=?,body=? WHERE task_ref=? AND path=?',
                   (encode(metadata).decode(), mac, body, ref, 'a.py'))
        db.execute('DELETE FROM task_preimage_semantics WHERE task_ref=? AND path=?', (ref, 'a.py'))
    record['baseline'].pop('redaction_version')
    legacy = dict(metadata, mac=mac)
    record['baseline']['preimages']['a.py'] = legacy
    tasks.store(root).save(record)
    (root / 'a.py').write_text('role = "admin"\n')
    (root / 'added.py').write_text('status = "HELLO"\n')
    packet = tasks.prepare(root, ref, protocol_version=3)
    delivered, _ = review_all(tasks, root, ref, packet)
    text = json.dumps(delivered)
    assert 'reader' not in text and 'admin' not in text and 'HELLO' not in text
    assert '[REDACTED_LITERAL]' in text
    assert tasks.load(root, ref)['baseline']['preimages']['a.py'] == legacy
    assert tasks.load(root, ref)['baseline'].get('redaction_version') is None


def test_all_parts_of_concatenated_and_escaped_credentials_are_hidden():
    for source in ['password = ("synthetic-first" + "synthetic-tail")',
                   '# password="synthetic-first\\"synthetic-tail"']:
        result = '\n'.join(safe_source(source, source_path='a.py'))
        assert 'synthetic-first' not in result and 'synthetic-tail' not in result
