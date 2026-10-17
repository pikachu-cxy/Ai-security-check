"""On-demand, manifest-only OSV scan. No target builds or call analysis."""
import json
import os
from dataclasses import replace
from pathlib import Path

from .capabilities import Capability
from .diagnostics import DiagnosticError, ErrorDiagnostic
from .models import RunStatus, ScannerRun
from .scanners import BaseScanner, _snapshot, _process_failure
from .toolchain import tool_environment, external_tool_loader
from .processes import run_process, OutputLimitError
from .progress import emit
from .verification_policy import offline_scanning, scanner_process_observed

# Lockfiles describe a bounded inventory. POM/requirements/go.mod can need
# resolution; successful extraction alone does not prove a complete graph.
LOCKFILES = {'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'gradle.lockfile', 'buildscript-gradle.lockfile'}
MANIFESTS = LOCKFILES | {'pom.xml', 'requirements.txt', 'go.mod', 'pyproject.toml'}
DEPENDENCY_INPUTS = MANIFESTS | {'package.json', 'pyproject.toml', 'build.gradle', 'build.gradle.kts', 'go.sum', 'poetry.lock', 'Pipfile.lock'}


class OSVDependencyAdapter(BaseScanner):
    name = scanner_id = engine_id = 'osv-scanner'
    display_name = 'OSV-Scanner dependency fallback'
    provider_role = 'FALLBACK'
    capabilities = frozenset({Capability.DEPENDENCY_VULN})
    timeout = 120

    def supports(self, profile, context):
        return any(Path(f).name in MANIFESTS for f in (*context.files, *context.context_files))

    def scan(self, context, normalizer):
        # Per-invocation contract state, also safe when a Runtime is reused.
        worker = OSVDependencyAdapter(self.tool_manager)
        worker.coverage = 'PARTIAL'
        worker.notes = []
        worker.inventory = {}
        emit('FALLBACK_PREPARING',scanner=self.name,capability=tuple(self.capabilities))
        found, run = BaseScanner.scan(worker, context, normalizer)
        if run.error_code == 'OFFLINE_MODE':
            run.status = RunStatus.UNAVAILABLE
        run.provider = self.engine_id
        run.provider_role = 'FALLBACK'
        run.capabilities = tuple(self.capabilities)
        run.coverage_contract = worker.coverage if run.status == RunStatus.SUCCESS else 'NONE'
        run.coverage_notes = worker.notes
        run.coverage_notes = list(dict.fromkeys(run.coverage_notes))
        run.dependency_inventory = worker.inventory
        emit('FALLBACK_COMPLETED' if run.status == RunStatus.SUCCESS else 'FALLBACK_FAILED',
            scanner=self.name,capability=run.capabilities,duration_ms=run.duration_ms,
            finding_count=run.finding_count,error_code=run.error_code,
            message='覆盖：'+run.coverage_contract)
        return found, run

    def _scan(self, binary, context, normalizer):
        scope = tuple(dict.fromkeys(f for f in (*context.files, *context.context_files) if Path(f).name in DEPENDENCY_INPUTS))
        supported = [f for f in scope if Path(f).name in MANIFESTS]
        if not supported:
            raise DiagnosticError(ErrorDiagnostic('DEPENDENCY_SCOPE_UNSUPPORTED', 'No supported dependency inventory is in the planned scope.', 'Provide a supported manifest or lockfile.'))
        offline = offline_scanning()
        db_root = self.tool_manager.root / 'data' / 'osv'
        environment = tool_environment(Path(binary))
        if offline:
            environment['SECURITY_RUNTIME_OFFLINE'] = '1'
        environment['OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY'] = str(db_root)
        if offline:
            ecosystems = {'Maven' if Path(f).name.endswith('.xml') or 'gradle' in Path(f).name else 'Go' if Path(f).name=='go.mod' else 'PyPI' if Path(f).name in {'requirements.txt', 'pyproject.toml'} else 'npm' for f in supported}
            if any(not (db_root/'osv-scalibr'/eco/'all.zip').is_file() for eco in ecosystems):
                raise DiagnosticError(ErrorDiagnostic('OFFLINE_MODE', 'OSV local vulnerability data is unavailable in offline mode.', 'Prepare local OSV ecosystem databases online before offline scanning.'))
        with _snapshot(replace(context, files=scope, context_files=())) as scoped:
            from .python_manifest import stage_python_manifests, manifest_target
            aliases, python_reports = stage_python_manifests(scoped, scope)
            # POM parents can use relativePath to read local files. Confine
            # declared local parents to the snapshot; suppress an implicit
            # root parent lookup outside it. Network resolution remains deps.dev.
            import xml.etree.ElementTree as ET
            for name in supported:
                if Path(name).name != 'pom.xml':
                    continue
                pom=scoped/name
                try:
                    tree=ET.parse(pom)
                except ET.ParseError:
                    raise ValueError('Malformed Maven manifest in dependency scope') from None
                root=tree.getroot()
                namespace=root.tag.split('}')[0]+'}' if '}' in root.tag else ''
                parent=root.find(namespace+'parent')
                if parent is None:
                    continue
                relative=parent.find(namespace+'relativePath')
                value=relative.text.strip() if relative is not None and relative.text else ('../pom.xml' if relative is None else '')
                if value:
                    candidate=(pom.parent/value).resolve()
                    if not candidate.is_relative_to(scoped.resolve()):
                        if relative is not None:
                            raise DiagnosticError(ErrorDiagnostic('SECURITY_BOUNDARY_VIOLATION', 'A local Maven parent escapes the dependency snapshot.', 'Provide a dependency inventory confined to the planned workspace.'))
                        ET.SubElement(parent,namespace+'relativePath').text=''
                        tree.write(pom,encoding='utf-8',xml_declaration=True)
                        self.notes.append('Implicit root Maven parent filesystem lookup was disabled at the snapshot boundary.')
            config=scoped/'runtime-osv.toml'
            config.write_text('',encoding='utf-8')
            args=[binary,'scan','source','--format=json','--all-packages','--all-vulns',
                '--verbosity=warn',
                '--recursive','--no-ignore','--no-call-analysis=all', '--data-source=deps.dev',
                '--experimental-no-default-plugins','--experimental-plugins=lockfile',
                '--config',str(config)]
            if offline:
                args += ['--offline','--no-resolve']
            args.append(str(scoped))
            emit('FALLBACK_RUNNING',scanner=self.name,capability=tuple(self.capabilities))
            with external_tool_loader():
                try:
                    process=run_process(args,cwd=str(scoped),env=environment,timeout=self.timeout,max_output=4_000_000)
                except (TimeoutError, OutputLimitError):
                    scanner_process_observed()
                    raise
                scanner_process_observed()
            if process.return_code not in (0,1):
                _process_failure(process)
            data=json.loads(process.stdout)
            if not isinstance(data,dict) or not isinstance(data.get('results'),list):
                raise ValueError('OSV output has no dependency inventory')
            observed=set()
            for result in data['results']:
                relative=manifest_target(result.get('source',{}).get('path',''), scoped, aliases)
                if relative not in scope:
                    raise ValueError('OSV reported a dependency outside its planned manifest scope')
                result['source']['path']=relative
                if relative in supported and result.get('packages'):
                    observed.add(relative)
                else:
                    self.notes.append('Additional manifest inventory does not attest a complete resolved dependency graph.')
                for entry in result.get('packages',[]):
                    package=entry.get('package',{})
                    if not all(package.get(key) for key in ('name','version','ecosystem')):
                        self.notes.append('One or more extracted packages have an unconfirmed name, version or ecosystem.')
            # Maven test dependencies are unsupported by the pinned upstream
            # resolver. Parent/property/graph completeness is not attested by
            # JSON inventory. Never promote POM-only success to FULL.
            if any(Path(f).name not in LOCKFILES for f in supported):
                self.notes.append('Manifest extraction/resolution does not attest a complete transitive dependency graph; Maven test dependencies are not covered.')
            if observed != set(supported):
                self.notes.append('One or more planned dependency inputs produced no inventory confirmation.')
            if any(report['unresolved_entries'] for report in python_reports.values()):
                self.notes.append('Some Python declarations are dynamic, unpinned or unsupported; no installed version was inferred.')
            if python_reports:
                self.notes.append('Python declared exact versions include optional/build declarations and unevaluated environment markers; applicability and installed versions are unconfirmed.')
            if any(Path(f).name not in MANIFESTS and Path(f).name not in {'package.json','go.sum'} for f in scope):
                self.notes.append('Some planned dependency formats are not supported by this fallback scope.')
            if process.stderr.strip():
                # Native warnings may indicate incomplete resolution. Preserve
                # useful findings but conservatively withhold FULL coverage.
                from .diagnostics import sanitize
                self.notes.append('Native extraction/resolution diagnostics: '+sanitize(process.stderr,500))
            if offline:
                # Presence of a local archive proves availability, not that
                # the advisory dataset is current. Complete lockfile inventory
                # cannot promote an unverified database to FULL coverage.
                self.notes.append('Offline vulnerability database freshness is unconfirmed; extracted package inventory does not attest current vulnerability coverage.')
            if not self.notes:
                self.coverage='FULL'
            packages=[entry.get('package',{}) for result in data['results'] for entry in result.get('packages',[])]
            self.inventory = {'package_occurrences':len(packages),
                'unique_packages':len({(p.get('ecosystem',''),p.get('name',''),p.get('version','')) for p in packages}),
                'confirmed_package_occurrences':sum(all(p.get(k) for k in ('ecosystem','name','version')) for p in packages),
                'confirmed_manifests':len(observed), 'planned_manifests':len(supported),
                'unconfirmed_manifests':sorted(set(supported) - observed),
                'python_declarations':python_reports,
                'per_manifest':{result['source']['path']:len(result.get('packages',[])) for result in data['results']},
                'complete_dependency_graph_attested':False if self.coverage=='PARTIAL' else True,
                'native_duration_ms':process.duration_ms}
            if offline:
                self.inventory['vulnerability_db_freshness'] = 'UNKNOWN'
            return self.normalize(data,normalizer)

    def normalize(self, data, normalizer):
        found=[]
        for result in data.get('results',[]):
            manifest=result.get('source',{}).get('path','')
            for entry in result.get('packages',[]):
                package=entry.get('package',{})
                for vuln in entry.get('vulnerabilities',[]):
                    finding=normalizer.dependency(scanner=self.name,
                        package=package.get('name',''), version=package.get('version',''),
                        ecosystem=package.get('ecosystem',''), manifest=manifest,
                        vulnerability_id=vuln.get('id',''), aliases=vuln.get('aliases',[]),
                        severity=vuln.get('database_specific',{}).get('severity','UNKNOWN'),
                        title=vuln.get('summary') or vuln.get('id','Dependency vulnerability'),
                        description=vuln.get('details',''), source='OSV')
                    from .diagnostics import sanitize
                    finding.technical_details['severity_vectors']=[{'type':sanitize(item.get('type',''),30),
                        'score':sanitize(item.get('score',''),300)} for item in vuln.get('severity',[]) if isinstance(item,dict)]
                    ranges=[];fixed=[]
                    for affected in vuln.get('affected',[]):
                        identity=affected.get('package',{})
                        if identity.get('name')!=package.get('name') or identity.get('ecosystem')!=package.get('ecosystem'):
                            continue
                        for row in affected.get('ranges',[])[:20]:
                            events=[{key:sanitize(value,100) for key,value in event.items() if key in {'introduced','fixed','last_affected','limit'}} for event in row.get('events',[])[:40]]
                            ranges.append({'type':sanitize(row.get('type',''),30),'events':events})
                            fixed.extend(event['fixed'] for event in events if event.get('fixed'))
                    finding.technical_details.update(affected_ranges=ranges[:20],fixed_versions=sorted(set(fixed))[:40])
                    found.append(finding)
        return found
