"""Task evidence retains long sanitized lines without widening finding excerpts."""
import hashlib

import pytest

from security_runtime.hook_state import HookStateStore
from security_runtime.local_evidence import (
    LocalEvidenceService, MAX_LINE_CHARS, legacy_safe_source, safe_source,
    snapshot_fingerprint,
)
from security_runtime.task_preimages import TaskPreimageStore, TaskPreimageUnavailable
from security_runtime.task_snapshot import SnapshotPolicy, collect_snapshot
from security_runtime import task_preimages
from security_runtime import task_preimage_fingerprints as fingerprints


TASK = 'ts1-' + 'c' * 32
CANARY = 'long-line-private-credential'


def source():
    return ('checked = auth.check(user); ' * 50
            + f"password = '{CANARY}'; tail = auth.allow(user)\n")


def private_store(tmp_path, root):
    hooks = HookStateStore(tmp_path / 'private-state')
    hooks.key(root)
    return TaskPreimageStore(hooks, root)


@pytest.mark.parametrize('version', [1, 2])
def test_full_source_redacts_credentials_before_returning_the_long_tail(version):
    truncated = []
    bounded = safe_source(source(), source_path='app.py', redaction_version=version,
                          truncation_lines=truncated)
    assert len(bounded[0]) == MAX_LINE_CHARS
    assert truncated == [1]
    assert 'tail = auth.allow(user)' not in bounded[0]

    complete_truncations = []
    complete = safe_source(source(), source_path='app.py', redaction_version=version,
                           max_line_chars=None, truncation_lines=complete_truncations)
    assert len(complete[0]) > MAX_LINE_CHARS
    assert 'tail = auth.allow(user)' in complete[0]
    assert CANARY not in complete[0]
    assert '[REDACTED_' in complete[0]
    assert complete_truncations == []


@pytest.mark.parametrize('sanitizer', [safe_source, legacy_safe_source])
def test_line_budget_is_optional_and_applied_after_whole_file_redaction(sanitizer):
    text = 'checked(); ' * 100 + '\n' + f"password = '{CANARY}'\n"
    truncated = []
    lines = sanitizer(text, source_path='app.py', max_line_chars=32,
                      truncation_lines=truncated)
    assert len(lines[0]) == 32 and truncated == [1]
    assert CANARY not in '\n'.join(lines)
    assert sanitizer(text, secret_ranges=[(1, 1)], source_path='app.py',
                     max_line_chars=None)[0] == '[REDACTED_SECRET]'
    for invalid in (0, -1, True, 12.5, '600'):
        with pytest.raises(ValueError, match='Invalid source line budget'):
            sanitizer(text, max_line_chars=invalid)


def test_finding_context_still_uses_the_default_line_cap(tmp_path):
    path = tmp_path / 'app.py'
    path.write_text(source(), encoding='utf-8')
    finding = dict(category='command-injection', file_path='app.py', line_start=1,
        line_end=1, technical_details={'evidence_locator': snapshot_fingerprint(tmp_path, 'app.py')},
        scanner_sources=['semgrep'], fingerprint='synthetic')
    service = LocalEvidenceService(dict(target_profile={'path': str(tmp_path)}, findings=[finding]))
    detail = service.detail(finding, context_lines=0)
    assert detail['evidence_status'] == 'EXACT'
    assert len(detail['original_evidence']['matched_code']) == MAX_LINE_CHARS
    assert 'tail = auth.allow(user)' not in detail['original_evidence']['matched_code']


def test_private_preimage_retains_complete_sanitized_long_line_after_edit(tmp_path):
    root = tmp_path / 'project'
    root.mkdir()
    store = private_store(tmp_path, root)
    raw = source().encode('utf-8')
    (root / 'app.py').write_bytes(raw)
    with store.writer(TASK) as writer:
        prepared = writer.put_source('app.py', raw)
    reference = prepared['reference']
    assert prepared['truncated_lines'] == []
    expected = safe_source(source(), source_path='app.py', max_line_chars=None)
    assert len(expected[0]) > MAX_LINE_CHARS
    assert store.read(TASK, 'app.py', hashlib.sha256(raw).hexdigest(), reference) == expected
    (root / 'app.py').write_text('changed_after_capture = True\n', encoding='utf-8')
    assert store.read(TASK, 'app.py', reference['raw_sha256'], reference) == expected
    assert CANARY.encode() not in store.path.read_bytes()
    assert b'tail = auth.allow(user)' in store.path.read_bytes()


@pytest.mark.parametrize('kind', ['inline', 'private', 'legacy-writer'])
def test_snapshot_preserves_long_lines_without_claiming_display_truncation(tmp_path, kind):
    root = tmp_path / 'project'
    root.mkdir()
    raw = source().encode('utf-8')
    (root / 'app.py').write_bytes(raw)
    store = private_store(tmp_path, root)
    if kind == 'inline':
        snapshot = collect_snapshot(root, inventory=['app.py'])
        lines = snapshot['texts']['app.py']
    else:
        with store.writer(TASK) as writer:
            class LegacyWriter:
                def put(self, *args):
                    return writer.put(*args)
            selected = LegacyWriter() if kind == 'legacy-writer' else writer
            snapshot = collect_snapshot(root, inventory=['app.py'], preimage_writer=selected)
        lines = store.read(TASK, 'app.py', snapshot['hashes']['app.py'], snapshot['preimages']['app.py'])
    assert 'tail = auth.allow(user)' in lines[0]
    assert CANARY not in lines[0]
    assert not snapshot['text_truncations']
    assert snapshot['capture_stats']['body_complete']


def test_complete_long_line_still_obeys_existing_private_and_inline_body_quotas(tmp_path, monkeypatch):
    root = tmp_path / 'project'
    root.mkdir()
    raw = source().encode('utf-8')
    (root / 'app.py').write_bytes(raw)
    store = private_store(tmp_path, root)
    monkeypatch.setattr(task_preimages, 'MAX_FILE_BODY_BYTES', MAX_LINE_CHARS + 100)
    with store.writer(TASK) as writer:
        with pytest.raises(TaskPreimageUnavailable, match='TASK_PREIMAGE_FILE_BUDGET'):
            writer.put_source('app.py', raw)
    snapshot = collect_snapshot(root, inventory=['app.py'],
        policy=SnapshotPolicy(max_inline_text_bytes=MAX_LINE_CHARS + 100))
    assert not snapshot['texts']
    assert snapshot['text_unavailable']['app.py'] == 'SNAPSHOT_INLINE_TEXT_BYTE_BUDGET'
    assert not snapshot['capture_stats']['body_complete']


def test_long_public_lines_do_not_gain_hidden_semantics_from_display_slicing():
    raw = (('checked = auth.check(user); ' * 50) + 'tail = allow(user)\n').encode()
    proof = fingerprints.make_proof(b'key', 'workspace', TASK, 'app.py', raw)
    assert proof['complete'] and proof['semantic_lines'] == {}
    # Removing an inert comment invokes the second sanitizer path. A long
    # retained code prefix must still remain public through its entire tail.
    with_comment = raw.rstrip(b'\n') + b' # explanation\n'
    comment_proof = fingerprints.make_proof(b'key', 'workspace', TASK, 'app.py', with_comment)
    assert comment_proof['complete'] and comment_proof['semantic_lines'] == {}
