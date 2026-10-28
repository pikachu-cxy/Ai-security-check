"""Fixed-byte capture and source applicability; no external scanner or project execution."""
from dataclasses import FrozenInstanceError, replace
import hashlib
import os
from pathlib import Path
import stat

import pytest

from security_runtime import scan_input
from security_runtime.scan_input import ScanInputLimits, capture_scan_input
from security_runtime.scan_request import ScanBinding, ScanInputError, ScanRequest, SourceKind

KEY = b'k' * 32


@pytest.fixture
def workspace(tmp_path):
    root = tmp_path / 'project'
    root.mkdir()
    (root / 'app.py').write_bytes(b'original\n')
    (root / 'package.json').write_bytes(b'{"version":"1"}\n')
    private = tmp_path / 'private'
    private.mkdir()
    return root, private


def request(root, **kwargs):
    return ScanRequest(root, 'quick', SourceKind.WORKTREE, ('app.py',), **kwargs)


def capture(value, private, **kwargs):
    return capture_scan_input(value, identity_key=KEY, private_parent=private, **kwargs)


@pytest.mark.parametrize('path', ['../x', '/x', 'a/../x', 'a//x', './x', 'C:/x', 'a\\x',
                                  'a\0x', 'a\nx', 'a. /x', 'CON.py', 'a/NUL', 'a/COM1.txt'])
def test_request_rejects_unsafe_paths(workspace, path):
    root, _ = workspace
    with pytest.raises(ScanInputError, match='SCAN_INPUT_PATH_INVALID'):
        ScanRequest(root, 'quick', 'WORKTREE', (path,))


def test_request_is_frozen_and_preserves_removed_dependency_trigger(workspace):
    root, _ = workspace
    value = request(root, absent_files=('package-lock.json',),
                    dependency_changes=('package-lock.json',))
    assert value.dependency_changes == ('package-lock.json',)
    assert value.absent_files == ('package-lock.json',)
    with pytest.raises(FrozenInstanceError):
        value.files = ()
    with pytest.raises(ScanInputError, match='SCAN_INPUT_DEPENDENCY_SCOPE_INVALID'):
        request(root, dependency_changes=('unrelated.json',))
    with pytest.raises(ScanInputError, match='SCAN_INPUT_PATH_DUPLICATE'):
        request(root, context_files=('app.py',))


@pytest.mark.parametrize('kwargs', [dict(mode='release', source_kind='INDEX'),
                                   dict(source_kind='UNKNOWN'), dict(contract='other')])
def test_request_protocol_and_index_mode_are_exact(workspace, kwargs):
    root, _ = workspace
    values = dict(workspace_root=root, mode='quick', source_kind='WORKTREE', files=('app.py',))
    with pytest.raises(ScanInputError):
        ScanRequest(**dict(values, **kwargs))


def test_private_view_is_fixed_and_does_not_claim_current_after_source_change(workspace):
    root, private = workspace
    with capture(request(root, context_files=('package.json',)), private) as view:
        assert view.execution_root != root and not view.execution_root.is_relative_to(root)
        assert (view.execution_root / 'app.py').read_bytes() == b'original\n'
        assert {entry.role for entry in view.manifest} == {'TARGET', 'CONTEXT'}
        assert view.check_current().state == 'CURRENT'
        assert view.check_current().scope == 'CAPTURED_INPUT'
        (root / 'app.py').write_bytes(b'new current bytes\n')
        assert (view.execution_root / 'app.py').read_bytes() == b'original\n'
        assert view.check_current().state == 'STALE'
        assert view.check_current().reason_code == 'SCAN_INPUT_SOURCE_CHANGED'
        view.assert_intact()
        directory = view.execution_root.parent
    assert not directory.exists() and list(private.iterdir()) == []
    assert view.check_current().state == 'UNVERIFIABLE'
    assert view.check_current().reason_code == 'SCAN_INPUT_CLOSED'


def test_missing_context_fails_without_fallback_or_retained_raw_data(workspace):
    root, private = workspace
    with pytest.raises(ScanInputError, match='SCAN_INPUT_REQUIRED_FILE_MISSING'):
        with capture(request(root, context_files=('missing.py',)), private):
            pytest.fail('missing context must never produce an execution view')
    assert list(private.iterdir()) == []


def test_absence_is_explicit_and_recreated_input_is_stale(workspace):
    root, private = workspace
    value = request(root, absent_files=('package-lock.json',), dependency_changes=('package-lock.json',))
    with capture(value, private) as view:
        assert next(entry for entry in view.manifest if entry.path == 'package-lock.json').role == 'ABSENT'
        assert not (view.execution_root / 'package-lock.json').exists()
        (root / 'package-lock.json').write_bytes(b'new lock')
        assert view.check_current().reason_code == 'SCAN_INPUT_ABSENCE_CHANGED'
    with pytest.raises(ScanInputError, match='SCAN_INPUT_ABSENCE_CHANGED'):
        with capture(value, private):
            pytest.fail('present bytes are not a deleted input')


def test_project_inventory_additions_are_detected_without_copying_them(workspace):
    root, private = workspace
    reader = lambda: tuple(path.name for path in root.iterdir() if path.is_file())
    with capture(request(root), private, inventory_reader=reader) as view:
        (root / 'later.py').write_bytes(b'new unscanned code')
        assert not (view.execution_root / 'later.py').exists()
        assert view.check_current().reason_code == 'SCAN_INPUT_INVENTORY_CHANGED'


def test_cross_file_change_during_capture_rejects_the_whole_view(workspace, monkeypatch):
    root, private = workspace
    original = scan_input._read_file

    def mutate_after_second(path, maximum):
        raw = original(path, maximum)
        if path == root / 'package.json':
            (root / 'app.py').write_bytes(b'changed while other input copied')
        return raw

    monkeypatch.setattr(scan_input, '_read_file', mutate_after_second)
    with pytest.raises(ScanInputError, match='SCAN_INPUT_SOURCE_CHANGED'):
        with capture(request(root, context_files=('package.json',)), private):
            pytest.fail('mixed capture must not reach any provider')
    assert list(private.iterdir()) == []


def test_inventory_movement_during_capture_is_rejected(workspace):
    root, private = workspace
    calls = []

    def reader():
        calls.append(True)
        return ('app.py',) if len(calls) == 1 else ('app.py', 'later.py')

    with pytest.raises(ScanInputError, match='SCAN_INPUT_INVENTORY_CHANGED'):
        with capture(request(root), private, inventory_reader=reader):
            pytest.fail('moving input inventory')
    assert list(private.iterdir()) == []


@pytest.mark.parametrize('limits,code', [
    (ScanInputLimits(file_bytes=2), 'SCAN_INPUT_FILE_BUDGET'),
    (ScanInputLimits(bytes=2), 'SCAN_INPUT_BYTE_BUDGET'),
    (ScanInputLimits(files=1), 'SCAN_INPUT_FILE_COUNT_BUDGET'),
])
def test_budgets_fail_closed_and_remove_partial_copies(workspace, limits, code):
    root, private = workspace
    with pytest.raises(ScanInputError, match=code):
        with capture(request(root, context_files=('package.json',)), private, limits=limits):
            pytest.fail('no partially captured input')
    assert list(private.iterdir()) == []


@pytest.mark.parametrize('change', ['replace', 'add', 'delete'])
def test_modified_execution_view_is_never_current(workspace, change):
    root, private = workspace
    with capture(request(root), private) as view:
        target = view.execution_root / 'app.py'
        if change == 'replace':
            target.chmod(stat.S_IREAD | stat.S_IWRITE)
            target.write_bytes(b'tampered bytes')
        elif change == 'add':
            (view.execution_root / 'unexpected.py').write_bytes(b'unmanifested code')
        else:
            target.chmod(stat.S_IREAD | stat.S_IWRITE)
            target.unlink()
        assert view.check_current().state == 'UNVERIFIABLE'
        assert view.check_current().reason_code == 'SCAN_INPUT_VIEW_CHANGED'


def test_source_symlink_is_rejected(workspace):
    root, private = workspace
    target = root / 'linked.py'
    try:
        target.symlink_to(root / 'app.py')
    except OSError:
        pytest.skip('OS account does not permit creating a test symlink')
    with pytest.raises(ValueError):
        with capture(ScanRequest(root, 'quick', 'WORKTREE', ('linked.py',)), private):
            pytest.fail('linked source must never enter a view')
    assert list(private.iterdir()) == []


def test_private_parent_cannot_be_inside_scanned_workspace(workspace):
    root, _ = workspace
    with pytest.raises(ScanInputError, match='SCAN_INPUT_PRIVATE_DIRECTORY_IN_WORKSPACE'):
        with capture(request(root), root):
            pytest.fail('snapshot must not become source inventory')


def test_identity_is_keyed_binds_input_and_does_not_disclose_content(workspace):
    root, private = workspace
    with capture(request(root), private) as first:
        source_revision = first.source_revision
        content_id = first.manifest[0].content_id
        first_input = first.input_id
    with capture(request(root), private) as second:
        assert second.source_revision == source_revision
        assert second.input_id != first_input
    with capture_scan_input(request(root), identity_key=b'z' * 32, private_parent=private) as third:
        assert third.source_revision != source_revision
        assert third.manifest[0].content_id != content_id
    assert content_id != hashlib.sha256(b'original\n').hexdigest()


def test_execution_bindings_require_actual_matching_identities(workspace):
    root, private = workspace
    bindings = (ScanBinding('RULES', 'core', 'rules-checksum'), ScanBinding('TOOL', 'native', 'build1'),
                ScanBinding('DATA', 'vulnerabilities', 'db-digest'))
    with capture(request(root, bindings=bindings), private) as view:
        assert view.validate_bindings(tuple(reversed(bindings))) is None
        changed = (*bindings[:-1], ScanBinding('DATA', 'vulnerabilities', 'db-new'))
        with pytest.raises(ScanInputError, match='SCAN_INPUT_BINDING_CHANGED'):
            view.validate_bindings(changed)
        with pytest.raises(ScanInputError, match='SCAN_INPUT_BINDING_CHANGED'):
            view.validate_bindings(())


@pytest.mark.parametrize('binding', [([], 'name', 'id'), ('TOOL', 'name', ''), ('OTHER', 'name', 'id')])
def test_binding_has_typed_fixed_diagnostics(binding):
    with pytest.raises(ScanInputError, match='SCAN_INPUT_BINDING_INVALID'):
        ScanBinding(*binding)


def test_rules_are_fixed_and_new_rule_is_not_silently_read_live(workspace):
    root, private = workspace
    rules = private / 'custom-rules'
    rules.mkdir()
    (rules / 'one.yml').write_bytes(b'rules: []\n')
    (rules / 'catalog.json').write_bytes(b'{}')
    (rules / 'irrelevant.secret').write_bytes(b'not-needed-by-rule-reader')
    with capture(request(root, rules_path=rules), private) as view:
        assert view.rules_path != rules and view.rules_path.parent == view.execution_root.parent
        assert (view.rules_path / 'one.yml').read_bytes() == b'rules: []\n'
        assert not (view.rules_path / 'irrelevant.secret').exists()
        (rules / 'two.yml').write_bytes(b'new rules')
        assert not (view.rules_path / 'two.yml').exists()
        assert view.check_current().reason_code == 'SCAN_INPUT_RULES_CHANGED'


def test_rule_overlay_keeps_source_root_and_finishes_new_identity_before_execution(workspace):
    root, private = workspace
    rules = private / 'rules'
    rules.mkdir()
    (rules / 'one.yml').write_bytes(b'rules: []\n')
    with capture(request(root), private) as source:
        original_id = source.input_id
        with source.with_rules(rules) as final:
            assert final.execution_root == source.execution_root
            assert final.input_id != original_id and final.source_revision != source.source_revision
            assert final.request.rules_path == rules
            assert (final.execution_root / 'app.py').read_bytes() == b'original\n'
            assert (final.rules_path / 'one.yml').read_bytes() == b'rules: []\n'
            assert final.check_current().state == 'CURRENT'
            (root / 'app.py').write_bytes(b'new workspace bytes')
            assert final.check_current().state == 'STALE'
            assert (final.execution_root / 'app.py').read_bytes() == b'original\n'


@pytest.mark.skipif(os.name != 'nt', reason='Windows extended-path regression')
def test_rule_overlay_preserves_readonly_files_beyond_max_path(workspace, monkeypatch):
    import json
    import yaml
    from security_runtime.findings import FindingNormalizer
    from security_runtime.models import ScanContext
    from security_runtime.processes import ProcessResult
    from security_runtime.rulepacks import RulePackManager
    from security_runtime.scanners import SemgrepAdapter

    root, private = workspace
    rules = private / 'rules'
    rules.mkdir()
    # The deferred overlay adds a second UUID directory, as in Codex's
    # redirected LocalCache state directory. Keep parents short and make the
    # final filename cross MAX_PATH without exceeding the component limit.
    with capture(request(root), private) as source:
        overlay_prefix = source.execution_root.parent / ('i-' + '0' * 32) / 'rules'
        name = 'r' * max(1, 265 - len(str(overlay_prefix)) - 5) + '.yml'
        raw = (b'rules:\n- id: long-path-test\n  languages: [python]\n'
               b'  message: test\n  severity: WARNING\n  pattern: print(...)\n')
        scan_input.native_io_path(rules / name).write_bytes(raw)
        manager = RulePackManager()
        pack = manager.resolve(user_path=rules)
        with source.with_rules(rules) as final:
            target = final.rules_path / name
            assert len(str(target)) > 260
            native = scan_input.native_io_path(target)
            assert native.read_bytes() == raw
            assert native.stat().st_file_attributes & stat.FILE_ATTRIBUTE_READONLY
            assert final.check_current().state == 'CURRENT'
            bound = manager.bind_input(pack, final.rules_path)
            assert bound.checksum == pack.checksum
            adapter = SemgrepAdapter(rule_packs=manager)
            context = ScanContext(str(source.execution_root), 'feature', ('app.py',),
                input_view=final, bound_rule_pack=bound, logical_root=str(root))
            context = replace(context, rule_plan=adapter.plan_rules(None, context))
            calls = []

            def execute(argv, cwd, timeout):
                config = Path(argv[argv.index('--config') + 1])
                ids = [r['id'] for r in yaml.safe_load(config.read_text())['rules']]
                assert ids == ['long-path-test']
                calls.append(ids)
                return ProcessResult(0, json.dumps({'results': [], 'errors': [],
                    'paths': {'scanned': ['app.py']}, 'time': {'rules': ids}}), '', 1)

            monkeypatch.setattr('security_runtime.scanners._execute', execute)
            assert adapter._scan('fixture-engine', context, FindingNormalizer(root)) == []
            assert len(calls) == 1
            overlay = final.rules_path.parent
        assert not overlay.exists()
        assert (source.execution_root / 'app.py').read_bytes() == b'original\n'
    assert not source.execution_root.parent.exists()


def test_source_change_while_rules_are_captured_rejects_overlay(workspace, monkeypatch):
    root, private = workspace
    rules = private / 'rules'
    rules.mkdir()
    (rules / 'one.yml').write_bytes(b'rules: []\n')
    original = scan_input._read_file

    def changing(path, maximum):
        raw = original(path, maximum)
        if path == rules / 'one.yml':
            (root / 'app.py').write_bytes(b'changed during rule overlay')
        return raw

    with capture(request(root), private) as source:
        monkeypatch.setattr(scan_input, '_read_file', changing)
        with pytest.raises(ScanInputError, match='SCAN_INPUT_SOURCE_CHANGED'):
            with source.with_rules(rules):
                pytest.fail('no provider may start with an unverified overlay')
        assert source.check_current().state == 'STALE'


@pytest.mark.parametrize('error', [ValueError('caller validation'), RuntimeError('provider failure')])
def test_capture_does_not_reclassify_caller_failure_and_still_cleans(workspace, error):
    root, private = workspace
    with pytest.raises(type(error)) as caught:
        with capture(request(root), private):
            raise error
    assert caught.value is error
    assert list(private.iterdir()) == []


class Index:
    def __init__(self, root, contents):
        self.root = root
        self.blobs = {}
        self.entries = b''
        self.on_blob = None
        self.set(contents)

    def set(self, contents):
        records = []
        for name, content in sorted(contents.items()):
            oid = hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest()
            self.blobs[oid] = content
            records.append(f'100644 {oid} 0\t{name}'.encode() + b'\0')
        self.entries = b''.join(records)

    def _run_bytes(self, *args, maximum):
        if args == ('ls-files', '--stage', '-z'):
            return self.entries
        assert args[:2] == ('cat-file', 'blob')
        raw = self.blobs[args[2]]
        if self.on_blob:
            self.on_blob()
        return raw


def test_index_uses_blob_version_and_ignores_worktree_changes(workspace):
    root, private = workspace
    git = Index(root, {'app.py': b'index bytes\n'})
    value = replace(request(root), source_kind=SourceKind.INDEX)
    with capture(value, private, git=git) as view:
        assert (view.execution_root / 'app.py').read_bytes() == b'index bytes\n'
        entry = view.manifest[0]
        assert entry.source_oid in git.blobs and entry.source_mode == '100644'
        (root / 'app.py').write_bytes(b'different worktree')
        assert view.check_current().state == 'CURRENT'
        git.set({'app.py': b'new index bytes'})
        assert view.check_current().reason_code == 'SCAN_INPUT_INDEX_CHANGED'
        assert (view.execution_root / 'app.py').read_bytes() == b'index bytes\n'


def test_index_absence_is_independent_of_existing_worktree_copy(workspace):
    root, private = workspace
    git = Index(root, {'app.py': b'index bytes\n'})
    value = replace(request(root, absent_files=('package.json',), dependency_changes=('package.json',)),
                    source_kind=SourceKind.INDEX)
    with capture(value, private, git=git) as view:
        assert (root / 'package.json').is_file()
        assert not (view.execution_root / 'package.json').exists()
        assert view.check_current().state == 'CURRENT'


def test_index_change_during_capture_cannot_reach_provider(workspace):
    root, private = workspace
    git = Index(root, {'app.py': b'index bytes'})
    git.on_blob = lambda: git.set({'app.py': b'newer index'})
    with pytest.raises(ScanInputError, match='SCAN_INPUT_INDEX_CHANGED'):
        with capture(replace(request(root), source_kind=SourceKind.INDEX), private, git=git):
            pytest.fail('moving index')
    assert list(private.iterdir()) == []


@pytest.mark.parametrize('entry', [b'120000 ' + b'a' * 40 + b' 0\tlink\0',
                                  b'100644 ' + b'a' * 40 + b' 1\tapp.py\0',
                                  b'100644 ' + b'a' * 40 + b' 0\t../outside\0',
                                  b'100644 invalid 0\tapp.py\0'])
def test_unsupported_index_entry_fails_closed(workspace, entry):
    root, private = workspace
    git = Index(root, {})
    git.entries = entry
    with pytest.raises(ScanInputError, match='SCAN_INPUT_INDEX_ENTRY_UNSUPPORTED'):
        with capture(replace(request(root), source_kind=SourceKind.INDEX), private, git=git):
            pytest.fail('unsupported index input')
    assert list(private.iterdir()) == []


def test_private_directory_permissions_are_applied_before_first_source_write(workspace, monkeypatch):
    root, private = workspace
    original = scan_input._write
    observed = []

    def inspect_and_write(directory, name, raw):
        if os.name == 'nt':
            import ctypes
            from ctypes import wintypes
            advapi = ctypes.WinDLL('advapi32', use_last_error=True)
            kernel = ctypes.WinDLL('kernel32', use_last_error=True)
            get = advapi.GetNamedSecurityInfoW
            get.argtypes = [wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD,
                            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                            ctypes.POINTER(ctypes.c_void_p)]
            get.restype = wintypes.DWORD
            descriptor = ctypes.c_void_p()
            assert get(str(directory.parent), 1, 5, None, None, None, None,
                       ctypes.byref(descriptor)) == 0
            value = wintypes.LPWSTR()
            convert = advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW
            convert.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                ctypes.POINTER(wintypes.LPWSTR), ctypes.c_void_p]
            kernel.LocalFree.argtypes = [ctypes.c_void_p]
            try:
                assert convert(descriptor, 1, 5, ctypes.byref(value), None)
                security = value.value
                assert 'D:P' in security
                assert security.count('(A;') == 2
                # Windows canonicalizes the current built-in Administrator SID
                # as LA; compare the ACL grantee with the actual object owner.
                owner = security.split('O:', 1)[1].split('D:', 1)[0]
                assert ';;;SY)' in security and f';;;{owner})' in security
                assert ';;;WD)' not in security and ';;;BU)' not in security
            finally:
                if value:
                    kernel.LocalFree(value)
                kernel.LocalFree(descriptor)
        else:
            assert stat.S_IMODE(directory.parent.stat().st_mode) == 0o700
        observed.append(name)
        original(directory, name, raw)

    monkeypatch.setattr(scan_input, '_write', inspect_and_write)
    with capture(request(root), private):
        assert observed == ['app.py']
