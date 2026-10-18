"""Implemented connector contracts, independent of transport and scanner code.

Profiles describe product capabilities, not a live connection attestation or an
authorization. Existing adapter capability objects are compatibility projections.
"""
from dataclasses import asdict, dataclass
from enum import StrEnum


HOSTS = ('codex', 'cursor', 'kiro', 'workbuddy', 'codebuddy', 'qoder', 'generic')


class LifecyclePhase(StrEnum):
    SESSION_OPEN = 'SESSION_OPEN'
    BEFORE_MUTATION = 'BEFORE_MUTATION'
    WORKSPACE_ACTIVITY = 'WORKSPACE_ACTIVITY'
    CONTEXT_DELIVERY = 'CONTEXT_DELIVERY'
    TASK_CLOSEOUT = 'TASK_CLOSEOUT'
    SESSION_STOP = 'SESSION_STOP'


class StopIntent(StrEnum):
    NONE = 'NONE'
    APPROVED_REPAIR = 'APPROVED_REPAIR'
    TASK_REPORT = 'TASK_REPORT'


@dataclass(frozen=True)
class HostCapabilities:
    supports_session_start: bool = False
    supports_workspace_open: bool = False
    supports_native_file_edit: bool = False
    supports_shell_post_event: bool = False
    supports_tool_input: bool = False
    supports_invocation_id: bool = False
    supports_stop: bool = False
    supports_global_install: bool = False
    supports_setup_seed: bool = False

    def __post_init__(self):
        if any(type(value) is not bool for value in asdict(self).values()):
            raise ValueError('Invalid host capability contract')


@dataclass(frozen=True)
class TransportCapabilities:
    supports_detection: bool = True
    supports_advisory_remediation: bool = True
    supports_user_visible_feedback: bool = False
    supports_agent_continuation: bool = False
    supports_stop_followup: bool = False
    supports_post_edit_context: bool = False
    supports_mcp: bool = True
    supports_live_remediation_continuation: bool = False
    supports_remote_workspace: bool = False


@dataclass(frozen=True)
class HostConnector:
    host: str
    command_hooks: bool
    post_edit_context: bool
    stop_followup: bool
    global_mcp: bool


@dataclass(frozen=True)
class ConnectorProfile:
    host: str
    mode: str
    command_hooks: bool
    phases: frozenset[LifecyclePhase]
    stop_intent: StopIntent = StopIntent.NONE
    invocation_id: bool = False
    setup_seed: bool = False
    live_remediation_continuation: bool = False

    @property
    def capabilities(self):
        activity = LifecyclePhase.WORKSPACE_ACTIVITY in self.phases
        return HostCapabilities(
            supports_session_start=LifecyclePhase.SESSION_OPEN in self.phases,
            supports_native_file_edit=activity, supports_shell_post_event=activity,
            supports_tool_input=activity, supports_invocation_id=self.invocation_id,
            supports_stop=LifecyclePhase.SESSION_STOP in self.phases,
            supports_global_install=True, supports_setup_seed=self.setup_seed)

    @property
    def transport_capabilities(self):
        context = LifecyclePhase.CONTEXT_DELIVERY in self.phases
        followup = self.stop_intent != StopIntent.NONE
        return TransportCapabilities(
            supports_user_visible_feedback=context,
            supports_agent_continuation=followup, supports_stop_followup=followup,
            supports_post_edit_context=context,
            supports_live_remediation_continuation=self.live_remediation_continuation)

    @property
    def connector(self):
        transport = self.transport_capabilities
        return HostConnector(self.host, self.command_hooks,
            transport.supports_post_edit_context, transport.supports_stop_followup,
            transport.supports_mcp)


_BASE_PHASES = frozenset({LifecyclePhase.SESSION_OPEN,
    LifecyclePhase.WORKSPACE_ACTIVITY, LifecyclePhase.SESSION_STOP})
_PROFILES = {
    ('codex', 'product'): ConnectorProfile('codex', 'product', False,
        _BASE_PHASES | {LifecyclePhase.CONTEXT_DELIVERY, LifecyclePhase.TASK_CLOSEOUT},
        StopIntent.APPROVED_REPAIR, invocation_id=True, setup_seed=True,
        live_remediation_continuation=True),
    ('cursor', 'legacy'): ConnectorProfile('cursor', 'legacy', True, _BASE_PHASES),
    ('cursor', 'automatic'): ConnectorProfile('cursor', 'automatic', True,
        _BASE_PHASES | {LifecyclePhase.BEFORE_MUTATION, LifecyclePhase.CONTEXT_DELIVERY,
                        LifecyclePhase.TASK_CLOSEOUT}, StopIntent.TASK_REPORT),
}


def connector_profile(host, mode=None):
    """Return an implemented mode; unknown modes never inherit product abilities."""
    try:
        if mode is None:
            mode = {'codex': 'product', 'cursor': 'automatic'}.get(host)
        return _PROFILES[(host, mode)]
    except (KeyError, TypeError):
        raise ValueError('UNSUPPORTED_HOST_CONNECTOR') from None
