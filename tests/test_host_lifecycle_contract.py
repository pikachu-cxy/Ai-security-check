"""Connector capability projections preserve each implemented transport mode."""
import ast
from dataclasses import asdict
from pathlib import Path

import pytest

from security_runtime.codex_event_adapter import CodexEventAdapter
from security_runtime.cursor_event_adapter import CursorHostEventAdapter
from security_runtime.host_connectors import connector
from security_runtime.host_events import HostCapabilities
from security_runtime.host_lifecycle import connector_profile, LifecyclePhase, StopIntent


def test_product_capabilities_share_profiles_without_inventing_a_codex_pre_hook():
    codex = connector_profile('codex')
    cursor = connector_profile('cursor')
    assert CodexEventAdapter.capabilities == codex.capabilities
    assert CursorHostEventAdapter(automatic=True).capabilities == cursor.capabilities
    assert connector('codex') == codex.connector
    assert connector('cursor') == cursor.connector
    assert LifecyclePhase.BEFORE_MUTATION not in codex.phases
    assert LifecyclePhase.BEFORE_MUTATION in cursor.phases
    assert codex.stop_intent == StopIntent.APPROVED_REPAIR
    assert cursor.stop_intent == StopIntent.TASK_REPORT
    assert codex.capabilities.supports_invocation_id
    assert not cursor.capabilities.supports_invocation_id


def test_cursor_legacy_does_not_inherit_automatic_feedback_or_continuation():
    legacy = CursorHostEventAdapter()
    automatic = CursorHostEventAdapter(automatic=True)
    assert legacy.capabilities == automatic.capabilities
    assert legacy.transport_capabilities == connector_profile('cursor', 'legacy').transport_capabilities
    assert not legacy.transport_capabilities.supports_user_visible_feedback
    assert not legacy.transport_capabilities.supports_stop_followup
    assert automatic.transport_capabilities.supports_post_edit_context
    assert automatic.transport_capabilities.supports_stop_followup
    assert not automatic.transport_capabilities.supports_live_remediation_continuation
    assert not automatic.transport_capabilities.supports_remote_workspace


@pytest.mark.parametrize('host,mode', [('unknown', None), ('cursor', 'product'), ('codex', 'automatic'),
    ('cursor', ''), ([], None)])
def test_unimplemented_modes_do_not_fall_back_to_product_capabilities(host, mode):
    with pytest.raises(ValueError, match='UNSUPPORTED_HOST_CONNECTOR'):
        connector_profile(host, mode)


def test_capability_compatibility_shape_and_dependency_direction():
    # Existing state/diagnostics retain the v1 capability schema.
    assert set(asdict(HostCapabilities())) == {
        'supports_session_start', 'supports_workspace_open', 'supports_native_file_edit',
        'supports_shell_post_event', 'supports_tool_input', 'supports_invocation_id',
        'supports_stop', 'supports_global_install', 'supports_setup_seed'}
    from security_runtime import host_events, host_lifecycle
    for module in (host_events, host_lifecycle):
        tree = ast.parse(Path(module.__file__).read_text(encoding='utf-8'))
        imports = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        assert not {'hook_runtime', 'runtime', 'mcp_server', 'scanners'} & imports
    with pytest.raises(ValueError, match='capability contract'):
        HostCapabilities(supports_stop=1)
