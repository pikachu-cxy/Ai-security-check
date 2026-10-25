"""Discovery budget boundaries and useful CLI/MCP failures, without running engines."""
import asyncio
import json

import pytest

from security_runtime import cli
from security_runtime.integration_state import WorkspaceBinding
from security_runtime.mcp_server import create_server
from security_runtime.target import DiscoveryLimitError, TargetDetector, LIMIT_SETTINGS
from test_global_integration import structured
from test_target_selection import runtime_at


@pytest.fixture(autouse=True)
def isolated_limits(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path / 'state'))
    for name in (*LIMIT_SETTINGS.values(), 'SECURITY_RUNTIME_SCAN_LIMITS_FILE'):
        monkeypatch.delenv(name, raising=False)


def nested(root, depth):
    directory = root
    for _ in range(depth):
        directory = directory / 'child'
    directory.mkdir(parents=True)
    (directory / 'App.java').write_text('class App {}')
    return directory


def test_default_depth_allows_32_and_reports_33(tmp_path):
    root = tmp_path / 'project'
    directory = nested(root, 32)
    assert TargetDetector().detect(root).files == [(directory / 'App.java').relative_to(root).as_posix()]
    (directory / 'one_more').mkdir()
    with pytest.raises(DiscoveryLimitError) as error:
        TargetDetector().detect(root)
    value = error.value.to_dict()
    assert value['limit_kind'] == 'max_depth'
    assert value['limit'] == 32 and value['observed'] == 33
    assert value['observed_is_lower_bound'] is True
    assert value['relative_path'].endswith('/one_more')
    assert 'deeper than 32' in value['message']
    assert value['configuration']['environment_variable'] == 'SECURITY_RUNTIME_MAX_DEPTH'


def test_file_count_boundary_and_explicit_scope(tmp_path):
    (tmp_path / 'a.py').write_text('pass')
    (tmp_path / 'b.py').write_text('pass')
    assert len(TargetDetector(max_files=2).detect(tmp_path).files) == 2
    for selected, lower_bound in ((None, True), (['a.py', 'b.py'], False)):
        with pytest.raises(DiscoveryLimitError) as error:
            TargetDetector(max_files=1).detect(tmp_path, selected)
        value = error.value.to_dict()
        assert value['limit_kind'] == 'max_files'
        assert value['limit'] == 1 and value['observed'] == 2
        assert value['observed_is_lower_bound'] is lower_bound
        assert 'more than 1 files' in value['detail']
        assert value['configuration']['file_key'] == 'discovery.max_files'
        assert value['scanner_run'] is False


def test_directory_and_size_limits_are_distinct(tmp_path):
    (tmp_path / 'child').mkdir()
    with pytest.raises(DiscoveryLimitError) as error:
        TargetDetector(max_directories=1).detect(tmp_path)
    assert error.value.to_dict()['limit_kind'] == 'max_directories'
    assert error.value.to_dict()['observed'] == 2  # Root counts as a directory.
    (tmp_path / 'app.py').write_bytes(b'12345')
    with pytest.raises(DiscoveryLimitError) as error:
        TargetDetector(max_file_size=4).detect(tmp_path, select_scan_targets=True)
    value = error.value.to_dict()
    assert value['reason_code'] == 'TARGET_FILE_SIZE_LIMIT_EXCEEDED'
    assert value['limit_kind'] == 'max_file_size'
    assert value['observed'] == 5 and value['observed_is_lower_bound'] is False
    assert value['relative_path'] == 'app.py'


def test_user_file_environment_and_constructor_precedence(tmp_path, monkeypatch):
    config = tmp_path / 'state' / 'scan-limits.toml'
    config.parent.mkdir()
    config.write_text('[discovery]\nmax_depth=40\nmax_files=123\nmax_directories=456\nmax_file_size=789\n')
    detector = TargetDetector()
    assert (detector.max_depth, detector.max_files, detector.max_directories, detector.max_file_size) == (40, 123, 456, 789)
    monkeypatch.setenv('SECURITY_RUNTIME_MAX_DEPTH', '41')
    assert TargetDetector().max_depth == 41
    assert TargetDetector(max_depth=42).max_depth == 42
    monkeypatch.delenv('SECURITY_RUNTIME_MAX_DEPTH')
    config.write_text('[discovery]\nmax_depth=43\n')
    assert TargetDetector().max_depth == 43  # Reread for the next operation.


def test_explicit_config_and_no_project_config(tmp_path, monkeypatch):
    root = tmp_path / 'project'; root.mkdir()
    (root / 'scan-limits.toml').write_text('[discovery]\nmax_depth=999\n')
    monkeypatch.chdir(root)
    assert TargetDetector().max_depth == 32
    config = tmp_path / 'limits.toml'
    config.write_text('[discovery]\nmax_depth=50\n')
    monkeypatch.setenv('SECURITY_RUNTIME_SCAN_LIMITS_FILE', str(config))
    assert TargetDetector().max_depth == 50


@pytest.mark.parametrize('content', [
    '[discovery]\nmax_files=0', '[discovery]\nmax_depth=-1',
    '[discovery]\nmax_depth=true', '[discovery]\nmax_depth="32"',
    '[discovery]\nmax_depth=1.5', '[discovery]\nmax_dept=32',
    '[other]\nmax_files=100', 'not valid TOML', 'x' * 65_537,
])
def test_invalid_file_config_has_safe_typed_diagnostic(tmp_path, content):
    config = tmp_path / 'state' / 'scan-limits.toml'
    config.parent.mkdir(); config.write_text(content)
    with pytest.raises(DiscoveryLimitError) as error:
        TargetDetector()
    value = error.value.to_dict()
    assert value['reason_code'] == 'TARGET_DISCOVERY_CONFIG_INVALID'
    assert value['message'] and value['remediation']
    assert not value['scanner_run'] and not value['source_modified']


@pytest.mark.parametrize('setting', list(LIMIT_SETTINGS.values()))
@pytest.mark.parametrize('value', ['0', '-1', 'no-number'])
def test_invalid_environment_reports_setting(setting, value, monkeypatch):
    monkeypatch.setenv(setting, value)
    with pytest.raises(DiscoveryLimitError) as error:
        TargetDetector()
    assert setting in error.value.to_dict()['detail']
    assert error.value.to_dict()['reason_code'] == 'TARGET_DISCOVERY_CONFIG_INVALID'


@pytest.mark.parametrize('path', ['', 'relative.toml', '/nonexistent/discovery-limits-fixture.toml'])
def test_explicit_config_must_be_absolute_and_readable(path, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_SCAN_LIMITS_FILE', path)
    with pytest.raises(DiscoveryLimitError) as error:
        TargetDetector()
    assert error.value.to_dict()['reason_code'] == 'TARGET_DISCOVERY_CONFIG_INVALID'


@pytest.mark.parametrize('kind', ['max_files', 'max_depth', 'max_directories', 'max_file_size', 'invalid_config'])
def test_mcp_returns_failure_details_and_never_calls_scanner(tmp_path, monkeypatch, kind):
    root = tmp_path / 'project'; root.mkdir()
    (root / 'App.java').write_text('class App {}')
    if kind == 'max_files':
        (root / 'Other.java').write_text('class Other {}')
    elif kind in {'max_depth', 'max_directories'}:
        nested(root, 2)
    monkeypatch.setenv(LIMIT_SETTINGS.get(kind, 'SECURITY_RUNTIME_MAX_FILES'),
                       'invalid' if kind == 'invalid_config' else '1')
    runtime, scanner = runtime_at(root, tmp_path / 'state')
    binding = WorkspaceBinding('fixture', str(root), '', 'generic-mcp', 'PROJECT', '')
    server = create_server(runtime, workspace_binding=binding, global_mode=False)
    value = structured(asyncio.run(server.call_tool('scan_project', {'summary': True})))
    assert value['message'] and value['detail'] and value['remediation']
    assert value['coverage'] == 'UNKNOWN' and not value['scanner_run']
    if kind != 'invalid_config':
        assert value['limit_kind'] == kind and value['observed'] > value['limit']
    else:
        assert value['reason_code'] == 'TARGET_DISCOVERY_CONFIG_INVALID'
    assert not scanner.calls and runtime.store.latest_scan(root) is None


def test_cli_file_count_failure_has_nonzero_exit_and_actionable_json(tmp_path, monkeypatch, capsys):
    root = tmp_path / 'project'; root.mkdir()
    (root / 'one.py').write_text('pass'); (root / 'two.py').write_text('pass')
    monkeypatch.setenv('SECURITY_RUNTIME_MAX_FILES', '1')
    assert cli.main(['scan', '--path', str(root), '--mode', 'release', '--json', '--no-progress']) == 2
    value = json.loads(capsys.readouterr().out)
    assert value['limit_kind'] == 'max_files' and value['limit'] == 1
    assert value['observed'] == 2 and value['observed_is_lower_bound']
    assert value['message'] and not value['scanner_run']
