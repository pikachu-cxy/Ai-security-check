"""Package/advisory reminder identity independent of synthetic scanner lines.

Only declared data is read. There is no dependency resolution, installation or
claim that a package API is reachable. Unsupported declarations require a fresh
scanner snapshot before their concrete version/advisory can be reassessed.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import tomllib
from urllib.parse import unquote

from packaging.requirements import InvalidRequirement, Requirement

from .finding_quality import digest, relative_file
from .local_evidence import WorkspaceReader, evidence_locator


def _package(ecosystem, value):
    value = str(value).strip()
    if ecosystem == 'pypi':
        return re.sub(r'[-_.]+', '-', value).lower()
    return value.lower() if ecosystem == 'npm' else value


def _requirements(entries, ecosystem, package):
    found = []
    for entry in entries:
        if not isinstance(entry, str) or len(entry) > 4096:
            continue
        try:
            requirement = Requirement(entry)
        except InvalidRequirement:
            continue
        if _package(ecosystem, requirement.name) == package:
            found.append(dict(specifier=str(requirement.specifier), extras=sorted(requirement.extras),
                              marker=str(requirement.marker) if requirement.marker else '',
                              url=requirement.url or ''))
    return sorted(found, key=lambda row: json.dumps(row, sort_keys=True))


def _canonical(value):
    if isinstance(value, dict):
        return {key: _canonical(item) for key, item in value.items()}
    if isinstance(value, list):
        return sorted((_canonical(item) for item in value), key=lambda item: json.dumps(item, sort_keys=True))
    return value


def _advisory_material(md):
    records = [md, *(row for row in (md.get('remediation_evidence') or []) if isinstance(row, dict))]
    material = []
    for record in records:
        row = {field: _canonical(record.get(field) or []) for field in ('affected_ranges', 'fixed_versions')}
        row['fixed_version_text'] = ' '.join(str(record.get('fixed_version_text', '')).split())
        if any(row.values()):
            material.append(row)
    return sorted({json.dumps(row, sort_keys=True) for row in material})


def _declarations(name, text, ecosystem, package):
    """Return only this package's declarations; None means unsupported/unknown."""
    filename = Path(name).name.lower()
    if ecosystem == 'pypi' and (filename.startswith('requirements') and filename.endswith('.txt')):
        rows = [line.split(' #', 1)[0].strip() for line in text.splitlines()
                if line.strip() and not line.lstrip().startswith(('#', '-'))]
        return _requirements(rows, ecosystem, package)
    if ecosystem == 'pypi' and filename == 'pyproject.toml':
        data = tomllib.loads(text)
        project, build = data.get('project', {}), data.get('build-system', {})
        if not isinstance(project, dict) or not isinstance(build, dict):
            return None
        groups = [project.get('dependencies', []), build.get('requires', [])]
        optional = project.get('optional-dependencies', {})
        if not isinstance(optional, dict) or any(not isinstance(group, list) for group in groups):
            return None
        groups.extend(optional.values())
        if any(not isinstance(group, list) for group in groups):
            return None
        return _requirements([item for group in groups for item in group], ecosystem, package)
    if ecosystem == 'npm' and filename == 'package.json':
        data = json.loads(text)
        if not isinstance(data, dict):
            return None
        found = []
        for group in ('dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'):
            values = data.get(group, {})
            if not isinstance(values, dict):
                return None
            for key, value in values.items():
                if _package(ecosystem, key) == package and isinstance(value, str):
                    found.append(dict(group=group, specifier=value))
        return found
    return None


def dependency_scope(workspace, finding):
    md = finding.get('technical_details', {})
    ecosystem = str(md.get('ecosystem', '')).lower()
    ecosystem = {'pip': 'pypi', 'python': 'pypi', 'node-pkg': 'npm',
                 'jar': 'maven', 'pom': 'maven', 'gomod': 'go'}.get(ecosystem, ecosystem)
    name = md.get('package')
    if not name and isinstance(md.get('purl'), str) and md['purl'].startswith('pkg:'):
        body = md['purl'][4:].split('?', 1)[0].split('#', 1)[0]
        kind, _, body = body.partition('/')
        ecosystem = ecosystem or {'pypi': 'pypi', 'npm': 'npm', 'maven': 'maven'}.get(kind, kind)
        if body.rfind('@') > body.rfind('/'):
            body = body.rsplit('@', 1)[0]
        name = unquote(body)
        if ecosystem == 'maven' and '/' in name:
            namespace, _, artifact = name.rpartition('/')
            name = namespace + ':' + artifact
    package = _package(ecosystem, name or '')
    advisory = md.get('canonical_vulnerability_id') or md.get('vulnerability_id') or md.get('rule_id')
    version = md.get('package_version') or md.get('installed_version')
    if not ecosystem or not package or not advisory or not isinstance(version, str) or not version:
        raise ValueError('Dependency handling requires one concrete package, version and advisory')
    file = relative_file(md.get('manifest') or finding['file_path'])
    if file != relative_file(finding['file_path']):
        raise ValueError('Dependency manifest must match the stored finding')
    raw, text = WorkspaceReader(workspace).read(file)
    file_hash = hashlib.sha256(raw).hexdigest()
    try:
        declarations = _declarations(file, text, ecosystem, package)
    except (ValueError, TypeError, tomllib.TOMLDecodeError):
        declarations = None
    # Different unresolved copies of one package must not borrow each other's
    # user decision. With no unique declaration, bind the observed version too.
    ambiguous = declarations is not None and len(declarations) > 1
    occurrence = version if ambiguous else 'package'
    key = 'rdd1-' + digest(['dependency-disposition-v1', file, ecosystem, package, advisory, occurrence])
    evidence = dict(package_version=version, declarations=declarations,
                    advisory_material=_advisory_material(md))
    # A supported empty result is not proof that a transitive package vanished.
    # Such findings can still be handled from an exact scanner snapshot, but
    # source changes require a new scan rather than a guessed declaration.
    declaration_known = bool(declarations)
    snapshot_exact = evidence_locator(finding)['file_sha256'] == file_hash
    revision = digest(evidence) if declaration_known or snapshot_exact else None
    return dict(issue_key=key, evidence_revision=revision, file_sha256=file_hash,
        metadata=dict(file=file, category='dependency', ecosystem=ecosystem,
            package=package, advisory=advisory, occurrence=occurrence,
            evidence_scope='DEPENDENCY_PACKAGE_ADVISORY',
            material_change_confirmable=bool(revision),
            declaration_available=declaration_known))
