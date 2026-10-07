"""Internal Host Event Normalization v1. Not an MCP input or repair authority."""
from __future__ import annotations

import math
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from .hook_state import identity, no_links

CONTRACT = 'host-event-v1'
CLOCK_SCOPE = uuid.uuid4().hex


class EventKind(StrEnum):
    SESSION_START = 'SESSION_START'
    WORKSPACE_ACTIVITY = 'WORKSPACE_ACTIVITY'
    SESSION_STOP = 'SESSION_STOP'


class OperationClass(StrEnum):
    READ_ONLY = 'READ_ONLY'
    DIRECT_FILE_MUTATION = 'DIRECT_FILE_MUTATION'
    POSSIBLE_WORKSPACE_MUTATION = 'POSSIBLE_WORKSPACE_MUTATION'
    UNKNOWN = 'UNKNOWN'


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
        if any(type(v) is not bool for v in asdict(self).values()):
            raise ValueError('Invalid host capability contract')


@dataclass(frozen=True)
class VerifiedHostContext:
    """Binding consistency only, never cryptographic host authentication.

    The private session value preserves existing state/receipt namespaces. It is
    neither repr output nor diagnostic data, and must never be serialized.
    Construction is trusted embedding code, not a remotely supplied assertion.
    """
    host: str
    workspace: Path = field(repr=False)
    workspace_identity: str
    session_binding: str
    invocation_binding: str | None
    capabilities: HostCapabilities
    _session: str = field(repr=False)
    validation_status: str = 'BINDING_CONSISTENT'

    def __post_init__(self):
        from .hook_runtime import HOSTS
        if (self.host not in HOSTS or not isinstance(self.workspace, Path)
                or not self.workspace.is_absolute()
                or self.workspace_identity != identity(os.path.normcase(str(self.workspace)))
                or not isinstance(self._session, str) or not 0 < len(self._session) <= 500
                or any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in self._session)
                or self.session_binding != identity(self._session)
                or self.validation_status != 'BINDING_CONSISTENT'
                or not isinstance(self.capabilities, HostCapabilities)):
            raise ValueError('Invalid verified host binding')
        if self.invocation_binding is not None and (not isinstance(self.invocation_binding, str)
                or len(self.invocation_binding) != 64
                or any(c not in '0123456789abcdef' for c in self.invocation_binding)):
            raise ValueError('Invalid invocation binding')
        no_links(self.workspace)


@dataclass(frozen=True)
class NormalizedHostEvent:
    kind: EventKind
    context: VerifiedHostContext
    operation: OperationClass = OperationClass.UNKNOWN
    mutation_hint: bool | None = None
    sequence_identity: str = field(default_factory=lambda: uuid.uuid4().hex)
    observed_monotonic: float = field(default_factory=time.monotonic)
    clock_scope: str = CLOCK_SCOPE
    stop_guard_active: bool | None = None
    schema_version: str = CONTRACT

    def __post_init__(self):
        if (not isinstance(self.kind, EventKind) or not isinstance(self.operation, OperationClass)
                or not isinstance(self.context, VerifiedHostContext)
                or self.schema_version != CONTRACT
                or self.mutation_hint is not None and type(self.mutation_hint) is not bool
                or type(self.observed_monotonic) not in (int, float)
                or not math.isfinite(self.observed_monotonic) or self.observed_monotonic < 0
                or len(self.sequence_identity) != 32
                or any(c not in '0123456789abcdef' for c in self.sequence_identity)
                or self.clock_scope != CLOCK_SCOPE):
            raise ValueError('Invalid normalized host event')
        if self.kind == EventKind.SESSION_STOP:
            if type(self.stop_guard_active) is not bool:
                raise ValueError('Missing normalized stop guard state')
        elif self.stop_guard_active is not None:
            raise ValueError('Unexpected stop guard state')
        if self.kind != EventKind.WORKSPACE_ACTIVITY and self.operation != OperationClass.UNKNOWN:
            raise ValueError('Unexpected lifecycle operation')

    def diagnostics(self):
        return dict(host=self.context.host, host_event_contract=CONTRACT,
            normalized_event_kind=self.kind.value, normalized_operation_class=self.operation.value,
            workspace_binding_status=self.context.validation_status,
            host_capabilities=asdict(self.context.capabilities))


class HostEventAdapter(Protocol):
    host: str
    capabilities: HostCapabilities

    def normalize(self, arguments: dict, root: Path, *, binding_diagnostics: dict) -> NormalizedHostEvent: ...

    def validate_claims(self, arguments: dict, expected: str, schema: dict | None = None) -> dict: ...
