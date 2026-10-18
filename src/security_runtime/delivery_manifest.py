"""Read-only installed contract identity, not execution or compatibility proof."""
from __future__ import annotations

import hashlib
import json

from .mcp_contracts import RAW_TOOL_CONTRACTS, schema_specifications


CONTRACT = 'runtime-delivery-manifest-v1'


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
        separators=(',', ':')).encode('utf-8')).hexdigest()


def delivery_manifest(info, tools, *, skill_contents=None):
    """Bind this connection's actual schemas to shipped methods and rule identity.

    No target reads, scans, DB initialization or writes. Installed metadata is
    deliberately distinct from host discovery, live vulnerability-data freshness
    and any original task's protocol/evidence/authorization ledger.
    """
    from .review_skill import skill_content_manifest
    try:
        skill_identity = dict(skill_content_manifest(skill_contents), status='AVAILABLE',
            method_fetch='Reuse exact local version/digest; fetch get_task_review_method only when absent.')
    except (OSError, ValueError, UnicodeError):
        skill_identity = dict(status='UNAVAILABLE', content_sha256=None, files=None)
    specs = schema_specifications(tools)
    inventory = info.get('rule_inventory') or {}
    build = info.get('build_identity') or {}
    features = info.get('features') or {}
    identity = dict(contract=CONTRACT,
        runtime=dict(version=info.get('version'), build_id=build.get('build_id'),
            build_status=build.get('status'), state_schema=build.get('state_schema')),
        tools=dict(schema_sha256=digest(specs), names=[item['name'] for item in specs],
            raw_contracts={spec.version: sorted(spec.names) for spec in RAW_TOOL_CONTRACTS}),
        skill=skill_identity,
        rules=dict(status=inventory.get('status', 'UNAVAILABLE'),
            version=inventory.get('rule_pack_version'), checksum=inventory.get('rule_pack_checksum')),
        protocols={name: features[name] for name in ('task_security_review_protocol',
            'task_session_routing', 'task_review_submission', 'repair_impact',
            'repair_impact_unknowns', 'risk_disposition') if name in features})
    return dict(identity, manifest_sha256=digest(identity),
        comparison='REQUIRED_TOOL_SUBSET_AND_SUPPORTED_PROTOCOL; DIGEST_IDENTIFIES_CONTENT_NOT_COMPATIBILITY',
        scope='THIS_CONNECTION_AND_SHIPPED_SKILL; HOST_DISCOVERY_AND_USER_MODIFICATIONS_NOT_VERIFIED',
        existing_tasks='PRESERVE_ORIGINAL_OWNER_REFERENCE_PROTOCOL_EVIDENCE_AND_CUMULATIVE_BUDGETS',
        vulnerability_data_freshness='INDEPENDENT_OF_BUILD_AND_RULE_IDENTITY',
        security_proof=False, repair_authorized=False, automatic_execution=False)
