"""Versioned finding families, independent of historical occurrence fingerprints."""
import hashlib
import json
from pathlib import PurePosixPath


def equivalence_key(finding) -> str:
    row = finding if isinstance(finding, dict) else vars(finding)
    details = row.get('technical_details') or {}
    path = str(row.get('file_path', '')).replace('\\', '/')
    parsed = PurePosixPath(path)
    if not path or parsed.is_absolute() or '..' in parsed.parts or ':' in path or path.startswith('['):
        return ''
    path = parsed.as_posix()
    category = row.get('category', '')
    if category == 'dependency':
        # The dependency normalizer already identifies an advisory at a concrete
        # package/version/manifest. Do not reduce it to a SAST rule/path family.
        identity = [details.get(k) for k in ('ecosystem', 'package', 'package_version',
                                            'canonical_vulnerability_id', 'manifest')]
        if not all(isinstance(value, str) and value for value in identity):
            return ''
        identity[0] = identity[0].lower()
        identity[-1] = path
        fields = ['dependency', *identity]
    else:
        rule = details.get('rule_id')
        # Normalized capability anchors retain eq-v1 and the historical TLS
        # identity. Secret families retain scanner detector identity because
        # its absence cannot be proven from a generic capability claim.
        if category != 'secret' and details.get('capability_program_version') and details.get('capability_family_anchor'):
            rule = details['capability_family_anchor']
        sources = row.get('scanner_sources') or []
        if not category or not isinstance(rule, str) or not rule or not sources:
            return ''
        if any(not isinstance(value, str) or not value for value in sources):
            return ''
        # Secret identity contains detector metadata only, never a credential,
        # matching line, evidence, title or unkeyed credential digest.
        fields = [category, sorted(set(sources)), rule, path]
    return 'eq-v1:' + hashlib.sha256(json.dumps(fields, ensure_ascii=False,
        separators=(',', ':')).encode('utf-8')).hexdigest()
