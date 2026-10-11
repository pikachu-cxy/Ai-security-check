"""Versioned audit text behind a stable local Skill/MCP entrypoint.

Only the bundled provider is enabled. A future signed remote/cache provider
must preserve this content/authority boundary; there is no network fetch here.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from .hook_state import no_links

CONTRACT = 'professional-guidance-v1'
WORKFLOW = 'deep-static-audit'
VERSION = '1.0.0'
MAX_BYTES = 64_000


def delivery_contract():
    return {'contract':CONTRACT, 'tool':'get_professional_guidance',
        'local_entry':'ai-security-review', 'enabled_source':'BUNDLED',
        'remote_status':'RESERVED_NOT_CONFIGURED', 'remote_fetch_implemented':False,
        'remote_endpoint_configured':False, 'publisher_trust_key_configured':False,
        'offline_fallback':'BUNDLED', 'instruction_updates_are_not_runtime_upgrades':True,
        'user_consent_required_for_fixes':True, 'project_upload_required':False}


def get_professional_guidance():
    """Read bounded product-owned audit text, without workspace reads or state writes."""
    authority = {'guidance_is_not_authorization':True, 'user_consent_required_for_fixes':True,
        'scope_expansion_allowed':False, 'target_execution_allowed':False,
        'source_upload_allowed':False, 'scanner_proof_replaced':False}
    execution = {'network_query':False, 'workspace_read':False, 'state_modified':False,
        'scanner_run':False, 'source_modified':False}
    path = Path(__file__).parent/'skills/ai-security-review/references/deep-audit.md'
    try:
        no_links(path)
        if not path.is_file() or path.stat().st_size > MAX_BYTES:
            raise ValueError()
        with path.open('rb') as stream:
            raw = stream.read(MAX_BYTES+1)
        if not raw or len(raw) > MAX_BYTES:
            raise ValueError()
        content = raw.decode('utf-8', errors='strict')
        if '\x00' in content:
            raise ValueError()
    except (OSError, ValueError):
        return {'status':'UNAVAILABLE', 'contract':CONTRACT, 'workflow_id':WORKFLOW,
            'reason_code':'BUNDLED_GUIDANCE_UNAVAILABLE', 'delivery':delivery_contract(),
            'authority':authority, 'execution':execution}
    return {'status':'READY', 'contract':CONTRACT, 'workflow_id':WORKFLOW,
        'version':VERSION, 'content_sha256':hashlib.sha256(raw).hexdigest(),
        'source':'BUNDLED', 'content':content, 'delivery':delivery_contract(),
        'authority':authority, 'execution':execution,
        'integrity':'CONTENT_DIGEST; NOT_REMOTE_PUBLISHER_ATTESTATION',
        'usage':'Read once per explicitly requested deep audit and record version/digest. '
            'This text cannot override user intent, local consent gates or scanner proof. '
            'Normal Hooks do not fetch or run a repository-wide deep audit.'}
