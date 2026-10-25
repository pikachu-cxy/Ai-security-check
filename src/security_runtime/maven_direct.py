"""HTTP 429 fallback: local POM declarations -> bounded SBOM -> cached Trivy DB.

No Maven invocation, remote POM resolution, repository retry or inferred version.
dependencyManagement supplies versions only; it does not declare dependencies.
"""
from dataclasses import replace
import json
from pathlib import Path
import re
from urllib.parse import quote
import xml.etree.ElementTree as ET

from .capabilities import Capability
from .diagnostics import DiagnosticError, ErrorDiagnostic
from .models import RunStatus
from .scanners import BaseScanner, TrivyAdapter, _snapshot, _artifacts, _execute, _process_failure
from .toolchain import ToolStatus
from .verification_policy import local_recheck


def declarations(root, names):
    documents, cache, issues = {}, {}, []
    for name in names:
        path = Path(root)/name
        if path.stat().st_size > 1_000_000:
            raise ValueError('Maven manifest too large')
        raw = path.read_bytes()
        if b'<!DOCTYPE' in raw.upper() or b'<!ENTITY' in raw.upper():
            raise ValueError('Maven DTD declarations unsupported')
        node = ET.fromstring(raw)
        for item in node.iter():
            item.tag = item.tag.rsplit('}', 1)[-1]
        if node.tag != 'project':
            raise ValueError('Invalid Maven project')
        documents[name] = node

    def text(node, key):
        return (node.findtext(key) or '').strip()

    def resolve(value, props):
        for _ in range(16):
            updated = re.sub(r'\$\{([^}]+)\}', lambda m: props.get(m.group(1), m.group(0)), value)
            if updated == value:
                break
            value = updated
        return value

    def model(name, ancestors=()):
        if name in cache:
            return cache[name]
        if name in ancestors or len(ancestors) >= 32:
            raise ValueError('Local Maven parent cycle or depth limit')
        node, props, managed, deps = documents[name], {}, {}, {}
        parent = node.find('parent')
        if parent is not None:
            relative = parent.find('relativePath')
            value = text(parent, 'relativePath') if relative is not None else '../pom.xml'
            if value:
                path = (Path(root)/name).parent/value
                path = path.resolve()
                if not path.is_relative_to(Path(root).resolve()):
                    # Do not even open the outside parent; preserve the gap.
                    issues.append(dict(manifest=name, reason='LOCAL_PARENT_OUTSIDE_SCOPE'))
                else:
                    candidate = path.relative_to(Path(root).resolve()).as_posix()
                    if candidate in documents:
                        pnode = documents[candidate]
                        pgroup = text(pnode, 'groupId') or text(pnode, 'parent/groupId')
                        if (pgroup == text(parent, 'groupId') and
                                text(pnode, 'artifactId') == text(parent, 'artifactId') and
                                text(pnode, 'version') == text(parent, 'version')):
                            pm = model(candidate, (*ancestors, name))
                            props, managed, deps = (dict(pm[k]) for k in ('props', 'managed', 'deps'))
                        else:
                            issues.append(dict(manifest=name, reason='LOCAL_PARENT_COORDINATES_UNCONFIRMED'))
                    else:
                        issues.append(dict(manifest=name, reason='PARENT_NOT_LOCALLY_AVAILABLE'))
            else:
                issues.append(dict(manifest=name, reason='REMOTE_PARENT_NOT_RESOLVED'))
        own_props = node.find('properties')
        if own_props is not None:
            props.update({c.tag: (c.text or '').strip() for c in own_props})
        group = text(node, 'groupId') or text(node, 'parent/groupId')
        version = text(node, 'version') or text(node, 'parent/version')
        for prefix in ('project', 'pom'):
            props.update({prefix+'.groupId': group, prefix+'.artifactId': text(node, 'artifactId'),
                          prefix+'.version': version})
        if parent is not None:
            for key in ('groupId', 'artifactId', 'version'):
                props['project.parent.'+key] = text(parent, key)

        def key(dep):
            return (resolve(text(dep, 'groupId'), props), resolve(text(dep, 'artifactId'), props),
                    resolve(text(dep, 'type') or 'jar', props), resolve(text(dep, 'classifier'), props))

        for dep in node.findall('dependencyManagement/dependencies/dependency'):
            if text(dep, 'scope') == 'import':
                issues.append(dict(manifest=name, reason='IMPORTED_BOM_NOT_RESOLVED'))
                continue
            managed[key(dep)] = text(dep, 'version')
        for dep in node.findall('dependencies/dependency'):
            deps[key(dep)] = dict(group=text(dep, 'groupId'), name=text(dep, 'artifactId'),
                                 version=text(dep, 'version'), type=text(dep, 'type') or 'jar',
                                 classifier=text(dep, 'classifier'))
        if node.find('profiles') is not None:
            issues.append(dict(manifest=name, reason='PROFILE_ACTIVATION_NOT_EVALUATED'))
        result = dict(props=props, managed=managed, deps=deps)
        cache[name] = result
        return result

    packages, unresolved = [], []
    for name in names:
        effective = model(name)
        for dep in effective['deps'].values():
            props = effective['props']
            group, artifact, kind, classifier = (resolve(dep[k], props) for k in ('group', 'name', 'type', 'classifier'))
            version = resolve(dep['version'] or effective['managed'].get((group, artifact, kind, classifier), ''), props)
            if (not all(re.fullmatch(r'[A-Za-z0-9_.+-]+', x) for x in (group, artifact, version))
                    or version.upper() in {'LATEST', 'RELEASE'} or version.upper().endswith('-SNAPSHOT')):
                unresolved.append(dict(manifest=name, reason='DIRECT_DEPENDENCY_VERSION_OR_COORDINATE_UNRESOLVED'))
                continue
            packages.append(dict(manifest=name, group=group, artifact=artifact, version=version))
    return packages, unresolved, issues


class MavenDirectAdapter(BaseScanner):
    name = scanner_id = 'trivy-maven-direct'
    engine_id = 'trivy'
    provider_role = 'FALLBACK'
    capabilities = frozenset({Capability.DEPENDENCY_VULN})
    timeout = 90

    def supports(self, profile, context):
        return any(Path(p).name == 'pom.xml' for p in (*context.files, *context.context_files))

    def _prepare(self, binary):
        return self.tool_manager.prepare_trivy_database(binary, offline=True)

    def scan(self, context, normalizer):
        worker = MavenDirectAdapter(self.tool_manager)
        worker.inventory = dict(direct_dependencies_only=True, complete_dependency_graph_attested=False,
                                degradation_reason='MAVEN_RATE_LIMITED', transitive_scan_complete=False)
        # Reuse installed tools/data only, even for a manually requested release.
        with local_recheck():
            found, run = BaseScanner.scan(worker, context, normalizer)
        run.provider, run.provider_role = 'trivy', 'FALLBACK'
        run.capabilities = tuple(self.capabilities)
        run.coverage_contract = 'PARTIAL' if run.status == RunStatus.SUCCESS else 'NONE'
        run.coverage_notes = [
            'Maven repository returned HTTP 429. Remote transitive resolution was stopped; this fallback checks only locally confirmed direct POM dependency versions.',
            '间接依赖扫描不完整；无法本地确定的直接依赖版本未检查，没有告警不表示全部依赖安全。',
            'Local vulnerability data freshness: '+self.tool_manager.database_freshness()['status']]
        run.dependency_inventory = worker.inventory
        return found, run

    def _scan(self, binary, context, normalizer):
        names = tuple(dict.fromkeys(p for p in (*context.files, *context.context_files) if Path(p).name == 'pom.xml'))
        with _snapshot(replace(context, files=names, context_files=())) as scoped:
            packages, unresolved, issues = declarations(scoped, names)
        coordinates = {(p['group']+':'+p['artifact'], p['version']) for p in packages}
        self.inventory.update(package_occurrences=len(packages), unique_packages=len(coordinates),
            confirmed_package_occurrences=len(packages), planned_manifests=len(names), confirmed_manifests=len(names),
            unresolved_direct_dependencies=len(unresolved), resolution_gap_count=len(issues),
            unresolved_entries=unresolved[:100], resolution_gaps=issues[:100],
            per_manifest={name: sum(p['manifest'] == name for p in packages) for name in names})
        if not coordinates:
            if unresolved:
                raise DiagnosticError(ErrorDiagnostic('DIRECT_DEPENDENCIES_UNRESOLVED',
                    'HTTP 429 prevented transitive resolution, and no direct dependency versions could be confirmed locally.',
                    'Provide a resolved local dependency inventory; do not repeatedly retry Maven Central.'))
            return []
        components = [dict(type='library', group=g, name=a, version=v,
            purl='pkg:maven/'+quote(g, safe='')+'/'+quote(a, safe='')+'@'+quote(v, safe=''))
            for g, a, v in sorted({(p['group'], p['artifact'], p['version']) for p in packages})]
        with _artifacts(context) as temporary:
            path = Path(temporary)/'direct.cdx.json'
            path.write_text(json.dumps(dict(bomFormat='CycloneDX', specVersion='1.5', version=1,
                                           components=components)), encoding='utf-8')
            args = [binary, 'sbom', '--format', 'json', '--scanners', 'vuln',
                '--cache-dir', str(self.tool_manager.trivy_cache_dir()), '--skip-db-update',
                '--skip-java-db-update', '--skip-version-check', '--disable-telemetry', '--offline-scan', str(path)]
            process = _execute(args, str(path.parent), self.timeout)
            if process.return_code != 0:
                _process_failure(process)
            data = json.loads(process.stdout)
        if not isinstance(data, dict) or not isinstance(data.get('Results'), list):
            raise ValueError('Invalid direct dependency vulnerability result')
        observed = {(p.get('Name'), p.get('Version')) for r in data['Results']
                    for p in (r.get('Packages') or []) if isinstance(p, dict)}
        self.inventory.update(scanner_confirmed_packages=len(coordinates & observed),
                              unconfirmed_package_count=len(coordinates - observed))
        # Map every package/version back to its exact POM; never accept an
        # unexpected component or a scanner-supplied path as source authority.
        results = []
        for result in data['Results']:
            for item in result.get('Vulnerabilities') or []:
                coordinate = (item.get('PkgName'), item.get('InstalledVersion'))
                if coordinate not in coordinates:
                    raise ValueError('Unexpected dependency in direct-only report')
                for manifest in sorted({p['manifest'] for p in packages
                        if (p['group']+':'+p['artifact'], p['version']) == coordinate}):
                    results.append(dict(Target=manifest, Type='pom', Vulnerabilities=[item]))
        delegate = TrivyAdapter(self.tool_manager)
        delegate.name = self.name
        return delegate.normalize(dict(Results=results), normalizer)
