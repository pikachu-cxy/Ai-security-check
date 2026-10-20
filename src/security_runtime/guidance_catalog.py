"""Bounded product guidance topics; no workspace, execution or authority input."""
from __future__ import annotations

import hashlib
from pathlib import Path

from .hook_state import no_links

CONTRACT = 'runtime-guidance-v1'
MAX_BYTES = 256_000
TOPICS = ('core', 'runtime-workflow', 'task-review', 'risk-decisions', 'repair-impact', 'deep-audit')
_VERSIONS = dict(zip(TOPICS, ('runtime-guidance-core-v1', 'runtime-workflow-v2', 'quick-task-review-v3',
                            'risk-decisions-v2', 'repair-impact-v1', '1.0.0')))
_REFERENCES = dict(zip(TOPICS, ('SKILL.md', 'references/runtime-workflow.md',
    'references/quick-task-review-v3.md', 'references/risk-decisions.md',
    'references/repair-impact.md', 'references/deep-audit.md')))


def _content(topic):
    if topic == 'core':
        from .review_skill import skill_entrypoint
        return skill_entrypoint()
    if topic == 'runtime-workflow':
        from .host_guidance import RUNTIME_WORKFLOW
        return ('# Canonical Runtime workflow\n\n' + RUNTIME_WORKFLOW + '\n').encode('utf-8')
    if topic == 'risk-decisions':
        from .host_guidance import RISK_DECISION_WORKFLOW
        return ('# 风险交互与用户处置\n\n' + RISK_DECISION_WORKFLOW).encode('utf-8')
    if topic == 'repair-impact':
        from .review_skill import repair_impact_reference
        return repair_impact_reference().encode('utf-8')
    path = Path(__file__).parent/'skills'/'ai-security-review'/_REFERENCES[topic]
    no_links(path)
    if not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError('Bundled guidance unavailable')
    with path.open('rb') as stream:
        raw = stream.read(MAX_BYTES+1)
    # Existing task method hashes normalized text. Audit's existing provider
    # hashes exact bundled bytes; preserve both original delivery contracts.
    return raw.decode('utf-8').replace('\r\n', '\n').replace('\r', '\n').encode('utf-8') if topic == 'task-review' else raw


def get_runtime_guidance(topic):
    """Read one fixed bundled topic. Unknown names never become file/URL input."""
    if not isinstance(topic, str) or topic not in TOPICS:
        raise ValueError('Unsupported runtime guidance topic')
    common = dict(contract=CONTRACT, topic=topic, version=_VERSIONS[topic],
        local_reference=_REFERENCES[topic], source='BUNDLED',
        authority=dict(guidance_is_not_authorization=True, repair_authorized=False, scanner_proof=False),
        execution=dict(workspace_read=False, state_modified=False, scanner_run=False, network_query=False))
    try:
        raw = _content(topic)
        if not raw or len(raw) > MAX_BYTES:
            raise ValueError()
        content = raw.decode('utf-8', errors='strict')
        if '\x00' in content:
            raise ValueError()
    except (OSError, ValueError, RecursionError):
        return dict(common, status='UNAVAILABLE', sha256=None, content=None,
                    reason='BUNDLED_GUIDANCE_UNAVAILABLE')
    return dict(common, status='READY', sha256=hashlib.sha256(raw).hexdigest(), content=content,
        bytes=len(raw), reuse='EXACT_VERSION_SHA256; SAME_RUNTIME_BUILD; READ_REQUIRED_TOPIC_ONCE')


def manifest():
    """Pure delivery metadata; neither installed discovery nor execution proof."""
    topics = {}
    for topic in TOPICS:
        result = get_runtime_guidance(topic)
        topics[topic] = {key: result.get(key) for key in ('status', 'version', 'sha256', 'bytes', 'local_reference')}
    return dict(contract=CONTRACT, topics=topics, source='BUNDLED',
        reuse='EXACT_VERSION_SHA256; SAME_RUNTIME_BUILD',
        missing_catalog_fallback='SAME_VERSION_DIGEST_LOCAL_COMPLETE_REFERENCE_ONLY',
        legacy_protocol_fallback=False, security_proof=False, repair_authorized=False)
