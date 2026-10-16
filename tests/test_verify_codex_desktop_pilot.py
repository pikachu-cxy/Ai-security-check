"""Native acceptance driver projections; no real Codex or model is launched."""
import importlib.util
import json
from pathlib import Path
import tomllib

import pytest


@pytest.fixture
def driver():
    path = Path(__file__).parents[1] / "scripts/verify_codex_desktop_pilot.py"
    spec = importlib.util.spec_from_file_location("native_desktop_driver_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_effective_overrides_disable_other_mcp_without_writing_global_trust(driver, tmp_path):
    home = tmp_path / "codex-home"
    home.mkdir()
    raw = b'''model = "existing-user-model"
[mcp_servers.ai_security_runtime]
command = "formal-runtime"
[mcp_servers.other]
command = "other-command"
[mcp_servers.endor-cli-tools]
command = "other-plain-name"
'''
    path = home / "config.toml"
    path.write_bytes(raw)
    overrides, before = driver.config_overrides(tmp_path / "new-project", home)
    assert before == driver._hash(path) and path.read_bytes() == raw
    assert 'approval_policy="never"' in overrides and "agents.enabled=false" in overrides
    assert 'mcp_servers.other.enabled=false' in overrides
    assert 'mcp_servers.endor-cli-tools.enabled=false' in overrides
    assert not any("ai_security_runtime" in value for value in overrides)
    trust = tomllib.loads(overrides[0])
    assert trust["projects"][str(tmp_path / "new-project")]["trust_level"] == "trusted"
    assert not (home / "auth.json").exists()


def test_inherited_mcp_name_with_literal_dot_is_rejected_before_native_dispatch(driver, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    (home / "config.toml").write_text('[mcp_servers."a.b"]\ncommand="existing"\n')
    with pytest.raises(ValueError):
        driver.config_overrides(tmp_path / "project", home)


def test_missing_global_config_is_unknown_not_empty_hash(driver, tmp_path):
    overrides, digest = driver.config_overrides(tmp_path / "project", tmp_path / "absent-home")
    assert digest is None and len(overrides) == 3


def test_native_event_projection_never_stores_command_args_response_or_auth_text(driver):
    secret = "arbitrary-auth-or-source-material"
    ref = "ts1-" + "a" * 32
    event = dict(type="item.completed", item=dict(id="tool-1", type="mcp_tool_call",
        server="ai_security_runtime", tool="mcp__ai_security_runtime__prepare_security_batch",
        arguments=dict(task_ref=ref, review_session=secret, prompt=secret),
        result=dict(structuredContent=dict(status="REVIEW_REQUIRED", secret=secret)),
        command=secret, aggregated_output=secret, error=dict(message=secret)))
    value = driver.project_event(event, 12.5)
    assert value["tool"] == "prepare_security_batch" and value["task_ref"] == ref
    assert value["response_status"] == "REVIEW_REQUIRED" and value["error_present"]
    assert secret not in json.dumps(value) and "review_session" not in json.dumps(value)


def test_event_projection_keeps_file_changes_and_only_known_usage_counters(driver):
    value = driver.project_event(dict(type="item.completed", usage=dict(input_tokens=10,
        output_tokens=2, cached_input_tokens=0, unsafe="arbitrary", negative=-1),
        item=dict(type="file_change", changes=[dict(path="orderdesk/service.py", kind="update",
            diff="omitted source text")])), 23)
    assert value["changed_files"] == [dict(path="orderdesk/service.py", kind="update")]
    assert value["usage"] == dict(input_tokens=10, output_tokens=2, cached_input_tokens=0)
    assert "omitted source text" not in json.dumps(value)


def test_event_projection_rejects_binding_lookalike_text(driver):
    value = driver.project_event(dict(type="item.completed", item=dict(type="mcp_tool_call",
        arguments=dict(task_ref="../../private-auth", batch_ref="not-an-id"))), 0)
    assert "task_ref" not in value and "batch_ref" not in value


def test_prompt_requests_real_development_continuation_and_no_manufactured_overlap(driver):
    assert "不要回放预设补丁" in driver.TASK
    assert "首次修改源代码或配置前 begin_security_task" in driver.TASK
    assert "然后立即继续开发" in driver.TASK
    assert "不要为制造并行效果插入sleep" in driver.TASK
    assert "integration_review" in driver.TASK


def test_child_environment_drops_inherited_native_session_but_keeps_existing_home(driver):
    environment = {key: "parent-only-sensitive-session-value" for key in driver.SESSION_ENV}
    environment.update(CODEX_HOME="existing-native-home", PATH="existing-path")
    value = driver.child_environment(environment)
    assert not set(value) & driver.SESSION_ENV
    assert value == dict(CODEX_HOME="existing-native-home", PATH="existing-path")
    assert len(environment) == len(driver.SESSION_ENV) + 2


@pytest.mark.parametrize("text,category", [
    ("error: unexpected argument '--ephemeral' found", "UNSUPPORTED_CLI_ARGUMENT"),
    ("No prompt provided via stdin", "EMPTY_STDIN_PROMPT"),
    ("Error: stdin is not a terminal", "INTERACTIVE_TERMINAL_REQUIRED"),
    ("Codex cannot run inside another nested session", "INHERITED_OR_NESTED_SESSION_REJECTED"),
    ("Authentication failed: arbitrary-secret", "AUTHENTICATION_ERROR_TEXT_OMITTED"),
    ("error: arbitrary-secret", "CLI_ERROR_TEXT_OMITTED"),
])
def test_stderr_diagnostics_keep_safe_categories_and_hashes_without_error_text(driver, text, category):
    value = driver.stderr_diagnostic(text)
    assert value["category"] == category and len(value["sha256"]) == 64
    assert "arbitrary-secret" not in json.dumps(value)
