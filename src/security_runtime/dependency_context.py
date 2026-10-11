"""Bounded offline declaration/usage evidence; not Maven or exploit reachability."""
from dataclasses import dataclass, field
from pathlib import PurePosixPath
import ast
import posixpath
import re
from xml.parsers import expat

MAX_POMS = 100
MAX_POM_BYTES = 2_000_000
MAX_SOURCE_BYTES = 1_000_000
VERSION = re.compile(r'[A-Za-z0-9_.+\x24{}:\-]{1,120}\Z')
PACKAGE = re.compile(r'[A-Za-z0-9_.\-]{1,100}:[A-Za-z0-9_.\-]{1,100}\Z')


@dataclass
class Node:
    tag: str
    line: int
    text: str = ''
    children: list = field(default_factory=list)

    def child(self, tag):
        return next((c for c in self.children if c.tag == tag), None)

    def value(self, tag):
        node = self.child(tag)
        return node.text.strip() if node else ''


def parse_pom(text):
    """Track XML node start lines; reject DTDs and expansion/depth abuse."""
    parser = expat.ParserCreate(namespace_separator='}')
    stack = []; root = None; count = 0
    def start(tag, attrs):
        nonlocal root, count
        count += 1
        if len(stack) >= 64 or count > 10000:
            raise ValueError('POM_PARSE_BUDGET')
        node = Node(tag.rsplit('}', 1)[-1], parser.CurrentLineNumber)
        if stack: stack[-1].children.append(node)
        else: root = node
        stack.append(node)
    def reject(*args):
        raise ValueError('POM_DTD_NOT_ALLOWED')
    parser.StartElementHandler = start
    parser.EndElementHandler = lambda tag: stack.pop()
    parser.CharacterDataHandler = lambda data: setattr(stack[-1], 'text', stack[-1].text + data) if stack else None
    parser.StartDoctypeDeclHandler = reject
    parser.ExternalEntityRefHandler = reject
    parser.Parse(text, True)
    if root is None or root.tag != 'project': raise ValueError('POM_ROOT_INVALID')
    return root


def _dependencies(root, managed=False):
    if managed: root = root.child('dependencyManagement')
    node = root.child('dependencies') if root else None
    return [c for c in node.children if c.tag == 'dependency'] if node else []


class DependencyContext:
    def __init__(self, builder):
        self.builder = builder
        self.poms = {}; self.errors = []; self.cache = {}; self.usage_files = {}
        size = 0
        names = sorted(n for n in builder.allowed if PurePosixPath(n).name == 'pom.xml')
        if len(names) > MAX_POMS: self.errors.append('POM_COUNT_LIMIT')
        for name in names[:MAX_POMS]:
            try:
                lines = builder.read(name, min(262144, MAX_POM_BYTES-size))
                size += builder._file_sizes[name]
                self.poms[name] = parse_pom('\n'.join(lines))
            except (ValueError, OSError, expat.ExpatError):
                self.errors.append('POM_UNAVAILABLE_OR_UNSUPPORTED')
            if size >= MAX_POM_BYTES:
                self.errors.append('POM_BYTE_LIMIT'); break

    def lineage(self, name):
        chain = []; seen = set()
        while name in self.poms and name not in seen and len(chain) < 20:
            seen.add(name); root = self.poms[name]; chain.append((name, root))
            parent = root.child('parent')
            if not parent: break
            relative = parent.child('relativePath')
            value = relative.text.strip() if relative else '../pom.xml'
            if not value: break
            candidate = posixpath.normpath(posixpath.join(posixpath.dirname(name), value))
            other = self.poms.get(candidate)
            if other is None or any(parent.value(key) != other.value(key)
                                    for key in ('groupId', 'artifactId', 'version')):
                break
            name = candidate
        return chain

    def declaration(self, manifest, package, version):
        out = {'status':'UNKNOWN', 'directness':'UNKNOWN', 'edit_location':None,
               'declared_version':None, 'locally_resolved_version':None,
               'scanner_version':version, 'complete_dependency_graph':False}
        if not isinstance(package, str) or not PACKAGE.fullmatch(package): return out
        lineage = self.lineage(manifest)
        props = {}
        for file, root in reversed(lineage):
            node = root.child('properties')
            for prop in node.children if node else []:
                if VERSION.fullmatch(prop.text.strip()):
                    props[prop.tag] = (prop.text.strip(), file, prop.line, prop.tag)
        group, artifact = package.split(':')
        matches = []
        for file, root in lineage:
            matches = [(file, dep) for dep in _dependencies(root) if
                       dep.value('groupId') == group and dep.value('artifactId') == artifact]
            if matches: break
        if len(matches) != 1: return out
        file, dep = matches[0]
        node = dep.child('version'); owner_kind = 'DEPENDENCY_VERSION'
        if node is None:
            for managed_file, root in lineage:
                managed = [d for d in _dependencies(root, True) if
                    d.value('groupId') == group and d.value('artifactId') == artifact and
                    d.value('scope') != 'import']
                if len(managed) > 1: return out
                if managed:
                    node = managed[0].child('version'); file = managed_file
                    owner_kind = 'LOCAL_DEPENDENCY_MANAGEMENT'; break
        if node is None: return out
        value = node.text.strip()
        if not VERSION.fullmatch(value): return out
        out['declared_version'] = value
        owner = {'file':file, 'line':node.line, 'kind':owner_kind}
        seen = set()
        for _ in range(10):
            match = re.fullmatch(r'\$\{([^{}]+)\}', value)
            if not match: break
            key = match[1]
            if key in seen or key not in props: return out
            seen.add(key); value, file, line, prop = props[key]
            owner = {'file':file, 'line':line, 'kind':'LOCAL_PROPERTY', 'property':prop}
        if '\x24{' in value: return out
        out.update(locally_resolved_version=value, declaration={'file':matches[0][0], 'line':dep.line})
        if any(root.child('profiles') is not None for _, root in lineage):
            out['status'] = 'PROFILE_CONTEXT_REQUIRED'; return out
        if value != version:
            out['status'] = 'VERSION_DISCREPANCY'; return out
        out.update(status='LOCAL_DECLARATION_SUPPORTED', directness='DIRECT',
                   edit_location=owner)
        return out

    def usage(self, ecosystem, package):
        ecosystem = str(ecosystem).lower()
        key = (ecosystem, package)
        if key in self.cache: return self.cache[key]
        self.usage_files[key] = set()
        prefixes = {'com.alibaba:fastjson':'com.alibaba.fastjson',
            'org.springframework.security:spring-security-crypto':'org.springframework.security.crypto',
            'org.springframework:spring-webmvc':'org.springframework.web.servlet',
            'io.netty:netty-handler':'io.netty.handler',
            'org.apache.logging.log4j:log4j-api':'org.apache.logging.log4j'}
        python = {'requests':'requests','httpx':'httpx','pyjwt':'jwt','pyyaml':'yaml','django':'django','flask':'flask'}
        prefix = prefixes.get(package) if ecosystem == 'maven' else python.get(str(package).lower()) if ecosystem == 'pypi' else None
        out = {'status':'UNSUPPORTED_PACKAGE_MAPPING' if not prefix else 'NOT_OBSERVED_IN_BOUNDED_SCOPE',
               'references':[], 'searched_files':0, 'searched_bytes':0,
               'truncated':False, 'exploitability':'NOT_ESTABLISHED',
               'dataflow':'NOT_ESTABLISHED', 'evidence_origin':'BOUNDED_CURRENT_WORKSPACE'}
        if not prefix: self.cache[key] = out; return out
        extension = '.java' if ecosystem == 'maven' else '.py'
        files = sorted(n for n in self.builder.allowed if n.endswith(extension))
        out['truncated'] = len(files) > 200
        for name in files[:200]:
            if out['searched_bytes'] >= MAX_SOURCE_BYTES:
                out['truncated'] = True; break
            try:
                lines = self.builder.read(name, min(262144, MAX_SOURCE_BYTES-out['searched_bytes']))
            except (ValueError, OSError):
                out['truncated'] = True; continue
            out['searched_files'] += 1; out['searched_bytes'] += self.builder._file_sizes[name]
            self.usage_files[key].add(name)
            text = '\n'.join(lines)
            if extension == '.py':
                try: tree = ast.parse(text)
                except (SyntaxError, RecursionError): out['truncated'] = True; continue
                imports = {}
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            imports[alias.asname or alias.name.split('.')[0]] = alias.name if alias.asname else alias.name.split('.')[0]
                    if isinstance(node, ast.ImportFrom) and node.module and not node.level:
                        for alias in node.names: imports[alias.asname or alias.name] = node.module+'.'+alias.name
                shadowed = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)}
                shadowed.update(node.arg for node in ast.walk(tree) if isinstance(node, ast.arg))
                for node in ast.walk(tree):
                    if not isinstance(node, ast.Call): continue
                    target = node.func; parts = []
                    while isinstance(target, ast.Attribute): parts.insert(0,target.attr); target = target.value
                    if not isinstance(target, ast.Name) or target.id in shadowed: continue
                    symbol = '.'.join([imports.get(target.id,''), *parts])
                    if symbol.startswith(prefix+'.'):
                        out['references'].append({'file':name,'line':node.lineno,'symbol':symbol[:200],'basis':'AST_IMPORTED_CALL_CANDIDATE'})
            else:
                scrubbed = re.sub(r'/\*[\s\S]*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"', lambda m:'\n'*m[0].count('\n'), text)
                imports = re.findall(r'\bimport\s+('+re.escape(prefix)+r'\.[\w.]+)\s*;', scrubbed)
                for symbol in imports:
                    short = symbol.rsplit('.',1)[-1]
                    for index, line in enumerate(scrubbed.splitlines(),1):
                        if re.search(r'\b'+re.escape(short)+r'\s*\.\s*\w+\s*\(',line) and not line.strip().startswith('import '):
                            out['references'].append({'file':name,'line':index,'symbol':symbol,'basis':'LEXICAL_IMPORTED_API_REFERENCE'})
            if len(out['references']) >= 12:
                out['truncated'] = True; break
        out['references'] = out['references'][:12]
        if out['references']: out['status'] = 'PACKAGE_API_REFERENCES_FOUND'
        self.cache[key] = out
        return out

    def describe(self, finding):
        md = finding.get('technical_details', {})
        return {'declaration':self.declaration(md.get('manifest') or finding['file_path'],
                    md.get('package'), md.get('package_version')),
                'usage':self.usage(md.get('ecosystem'), md.get('package')),
                'limitations':list(dict.fromkeys(self.errors + [
                    'Local properties/parents only; external BOMs, profiles, plugins and transitive graph are not resolved.',
                    'Current declarations/API references are not advisory-specific attack paths or original scanner proof.']))}

    def revision_files(self, finding):
        md = finding.get('technical_details', {})
        return set(self.poms) | self.usage_files.get((str(md.get('ecosystem')).lower(), md.get('package')), set())


def remediation_options(findings, evidence=()):
    """Advisories retain their own fixed options; never invent a joint upgrade."""
    rows = []
    for finding in findings[:100]:
        md = finding.get('technical_details', {})
        raw = md.get('fixed_versions')
        raw = raw[:40] if isinstance(raw, (list, tuple)) else []
        fixed = [v for v in raw if isinstance(v,str) and VERSION.fullmatch(v)][:20]
        rows.append({'finding_id':finding['id'], 'advisory':md.get('canonical_vulnerability_id') or md.get('vulnerability_id'),
            'fixed_options':fixed, 'status':'ADVISORY_OPTIONS_REQUIRE_COMPATIBILITY_REVIEW' if fixed else 'FIXED_VERSION_NOT_PROVIDED'})
    owners = [p['enrichment']['dependency_context']['declaration'] for p in evidence
              if p.get('enrichment',{}).get('dependency_context')]
    return {'advisories':rows, 'declarations':owners[:20],
        'joint_upgrade_verified':False, 'automatic_edit':False,
        'next_steps':['按 edit_location 修改实际版本拥有者，不能仅改扫描器标记的清单第 1 行。',
                      '逐项核对 fixed_options、受影响 API 和兼容性；缺失修复版本时查对应官方公告，不猜版本。',
                      '原依赖扫描器复查 + 已授权的相关功能测试；不完整依赖图不能证明整体修复。']}
