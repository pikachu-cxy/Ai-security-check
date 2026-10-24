"""Bounded path/routing diagnostics without admission or lazy state creation."""
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import time

from .global_workspace import workspace_rejection, workspace_state
from .hook_state import HookStateStore, no_links
from .tasks.ownership import valid_owner, SESSION_TTL


def _routing_owner(pool, root, token):
    """Verify an existing routing credential without observation callbacks."""
    if not isinstance(token, str) or len(token) > 1024 or not token.startswith('so1-'):
        raise ValueError('Invalid routing context')
    body, signature = token[4:].split('.')
    keypath = HookStateStore(workspace_state(root, pool.base)/'hooks').workspace_directory(root)/'snapshot.key'
    no_links(keypath)
    if keypath.stat().st_size != 32 or keypath.stat().st_nlink != 1:
        raise ValueError('Invalid routing context')
    key = keypath.read_bytes()
    if not hmac.compare_digest(signature, hmac.new(key, body.encode(), hashlib.sha256).hexdigest()):
        raise ValueError('Invalid routing context')
    data = json.loads(base64.b64decode(body+'='*(-len(body)%4), altchars=b'-_', validate=True))
    now = time.time()
    if (set(data) != {'v', 'workspace', 'owner', 'issued', 'expires'} or data['v'] != 1
            or data['workspace'] != hashlib.sha256(os.path.normcase(str(root)).encode()).hexdigest()
            or not valid_owner(data['owner']) or data['owner']['host'] != pool.host
            or type(data['issued']) not in (int, float) or type(data['expires']) not in (int, float)
            or not data['issued'] <= now < data['expires'] <= data['issued']+SESSION_TTL):
        raise ValueError('Invalid routing context')
    return data['owner']


def inspect_binding(pool, workspace_path, session_ref=None):
    result = dict(contract='workspace-binding-status-v1', path_status='UNKNOWN',
        resolution_stage='RESOLVING_ROOT', reason_code=None, resolved_workspace=None,
        session_binding_status='UNKNOWN', registered_workspace=None,
        identity_evidence='UNAVAILABLE', current_host_verified=False,
        execution_root_match=None, binding_confirmed=False, task_target_match=None,
        baseline_status='NOT_QUERIED', scan_status='NOT_QUERIED',
        binding_generation=None, verified_at=time.time(), scanner_run=False,
        state_modified=False, source_modified=False, security_proof=False)
    try:
        root = pool.root(workspace_path)
    except (ValueError, OSError, RuntimeError) as exc:
        result.update(path_status='REJECTED', reason_code=workspace_rejection(exc, 'RESOLVING_ROOT'))
        return result
    result.update(path_status='ALLOWED', resolved_workspace=str(root), resolution_stage='BINDING_SESSION')
    if session_ref is None:
        result['reason_code'] = 'SESSION_CONTEXT_REQUIRED'
        return result
    try:
        owner = _routing_owner(pool, root, session_ref)
    except (ValueError, OSError, TypeError, KeyError, UnicodeError):
        result['reason_code'] = 'SESSION_CONTEXT_UNVERIFIED'
        return result
    # A signed token authorizes observing this owner's existing routing record.
    # It does not attest which chat is issuing this request or its current cwd.
    with pool.lock:
        bound = pool.sessions.get(owner['session'])
    result['identity_evidence'] = 'SIGNED_ROUTING_CONTEXT_ONLY'
    if bound is None:
        result['reason_code'] = 'SESSION_BINDING_NOT_OBSERVED'
    elif Path(bound) != root:
        # Do not disclose a different root through a credential bound to this one.
        result.update(session_binding_status='MISMATCH', reason_code='SESSION_WORKSPACE_MISMATCH')
    else:
        result.update(session_binding_status='MATCH', registered_workspace=str(root),
                      reason_code='CURRENT_HOST_ATTESTATION_UNAVAILABLE')
    return result
