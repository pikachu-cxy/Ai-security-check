"""Bounded, evidence-backed Spring source facts for a development audit."""
import hashlib
import re
import subprocess
from collections import Counter

from .git import GitError, GitService
from .local_evidence import WorkspaceReader
from .review_delivery import json_bytes

MAX_PATHS = 8
MAPPINGS = {'RequestMapping', 'GetMapping', 'PostMapping', 'PutMapping',
            'PatchMapping', 'DeleteMapping'}
GUARDS = {'PreAuthorize', 'PostAuthorize', 'Secured', 'RolesAllowed'}
BEANS = {'Controller', 'RestController', 'Service', 'Component', 'Repository'}
ANNOTATION_PACKAGES = {
    **{name: ('org.springframework.stereotype',) for name in BEANS - {'RestController'}},
    **{name: ('org.springframework.web.bind.annotation',) for name in MAPPINGS | {'RestController'}},
    **{name: ('org.springframework.security.access.prepost',) for name in {'PreAuthorize', 'PostAuthorize'}},
    'Secured': ('org.springframework.security.access.annotation',),
    'RolesAllowed': ('javax.annotation.security', 'jakarta.annotation.security'),
}
WRITE = re.compile(r'^(save|update|delete|insert|persist|remove|flush|setStatus|setState)(?:[A-Z_].*)?$')
CHECK = re.compile(r'^(check|require|verify|assert|authorize|ensure|has|is)(?:[A-Z_].*)$')
STATE = re.compile(r'owner|tenant|principal|permission|status|state|amount|version', re.I)


def _changed_lines(git, path):
    diff = git._run('diff', '--no-ext-diff', '--no-textconv', '--unified=0',
                    'HEAD', '--', ':(literal)' + path)
    lines = set()
    for start, count in re.findall(r'^@@ .* \+(\d+)(?:,(\d+))? @@', diff, re.M):
        start = max(1, int(start))
        lines.update(range(start, start + max(1, int(count or 1))))
    return lines


def _parse(path, source, sha, changed, related):
    import javalang
    from javalang import tree

    unit = javalang.parse.parse(source)
    imports = [imp for imp in unit.imports if not imp.static]
    tokens = list(javalang.tokenizer.tokenize(source))
    closing = {}
    stack = []
    positions = {}
    for i, token in enumerate(tokens):
        positions[token.position] = i
        if token.value == '{':
            stack.append(i)
        elif token.value == '}':
            closing[stack.pop()] = token.position.line
    package = unit.package.name + '.' if unit.package else ''
    nodes, edges, gaps = [], [], []

    def annotation_name(annotation):
        simple = annotation.name.rsplit('.', 1)[-1]
        packages = ANNOTATION_PACKAGES.get(simple, ())
        qualified = {prefix + '.' + simple for prefix in packages}
        if '.' in annotation.name:
            return simple if annotation.name in qualified else ''
        for imp in imports:
            if imp.path in (packages if imp.wildcard else qualified):
                return simple
        return ''

    def fact(kind, name, start, end=None):
        identifier = 'asset-' + hashlib.sha256(
            repr((path, kind, name, start, end)).encode()).hexdigest()[:24]
        item = dict(id=identifier, kind=kind, name=name, file_path=path,
                    line_start=start, line_end=end or start, sha256=sha, source='SPRING_JAVA_AST')
        nodes.append(item)
        return item

    for cls in unit.types:
        annotations = {annotation_name(a) for a in cls.annotations}
        if not annotations & BEANS:
            continue
        methods = []
        for method in cls.methods:
            if method.body is None:
                continue
            start = min([method.position.line, *(a.position.line for a in method.annotations)])
            # Skip balanced parameter/annotation expressions before the body.
            depth = 0
            for i in range(positions[method.position], len(tokens)):
                token = tokens[i]
                if depth == 0 and token.value == '{':
                    break
                depth += (token.value == '(') - (token.value == ')')
            end = closing[i]
            methods.append((method, start, end))
        signatures = Counter((m.name, len(m.parameters)) for m, _, _ in methods)
        focus = {m for m, start, end in methods if related or not changed
                 or any(start <= line <= end for line in changed)}
        if not focus:
            continue
        # Include direct local callers and callees of the changed methods only.
        calls = {m: [call for _, call in m.filter(tree.MethodInvocation)
                     if call.position and not call.qualifier and not call.selectors]
                 for m, _, _ in methods}
        targets = {(m.name, len(m.parameters)): m for m, _, _ in methods
                   if signatures[m.name, len(m.parameters)] == 1 and
                   not any(p.varargs for p in m.parameters)}
        selected = focus | {targets.get((c.member, len(c.arguments))) for m in focus for c in calls[m]}
        selected |= {m for m, items in calls.items()
                     if any(targets.get((c.member, len(c.arguments))) in focus for c in items)}
        method_nodes = {}
        for method, start, end in methods:
            if method not in selected:
                continue
            entry = bool({annotation_name(a) for a in method.annotations} & MAPPINGS)
            name = f'{package}{cls.name}.{method.name}'
            item = fact('ENTRY' if entry else 'METHOD', name, start, end)
            item['focus'] = method in focus and not related
            method_nodes[method] = item
        for method, item in method_nodes.items():
            local_calls = {id(call) for call in calls[method]}
            for annotation in method.annotations:
                if annotation_name(annotation) in GUARDS:
                    point = fact('DECLARED_GUARD', annotation.name, annotation.position.line)
                    edges.append(dict(from_id=item['id'], to_id=point['id'], kind='DECLARES', proof=point))
            for _, node in method:
                if not node.position:
                    continue
                if isinstance(node, tree.IfStatement):
                    names = {m.member for _, m in node.condition.filter(tree.MemberReference)
                             if STATE.search(m.member)}
                    names.update(v for _, m in node.condition.filter(tree.MethodInvocation)
                                 for v in (m.qualifier, m.member) if v and STATE.search(v))
                    if names:
                        point = fact('CHECK_CANDIDATE', 'if ' + ', '.join(sorted(names))[:200], node.position.line)
                        edges.append(dict(from_id=item['id'], to_id=point['id'], kind='CONTAINS', proof=point))
                elif isinstance(node, tree.MethodInvocation):
                    kind = ('WRITE_CANDIDATE' if WRITE.fullmatch(node.member) else
                            'CHECK_CANDIDATE' if CHECK.fullmatch(node.member) else 'CALL')
                    point = fact(kind, '.'.join(filter(None, (node.qualifier, node.member))), node.position.line)
                    edges.append(dict(from_id=item['id'], to_id=point['id'], kind='CONTAINS', proof=point))
                    callee = targets.get((node.member, len(node.arguments))) if id(node) in local_calls else None
                    if callee in method_nodes:
                        edges.append(dict(from_id=point['id'], to_id=method_nodes[callee]['id'],
                                          kind='LOCAL_DECLARATION_CANDIDATE', proof=point))
                    else:
                        point['binding'] = 'UNKNOWN'
                elif isinstance(node, tree.MemberReference) and STATE.search(node.member):
                    point = fact('STATE_REFERENCE', node.member, node.position.line)
                    edges.append(dict(from_id=item['id'], to_id=point['id'], kind='CONTAINS', proof=point))
    if any(n.get('binding') == 'UNKNOWN' for n in nodes):
        gaps.append(dict(file_path=path, reason='CALL_BINDING_UNKNOWN'))
    if nodes:
        gaps.append(dict(file_path=path, reason='AOP_AND_CONFIGURATION_UNVERIFIED'))
    return nodes, edges, gaps


def plan(root, paths, related=()):
    """Use only explicitly observed or owner-authorized paths."""
    observed = list(dict.fromkeys(paths))
    names = list(dict.fromkeys([*observed, *related]))
    windows, nodes, edges, gaps = [], [], [], []
    if not any(name.endswith('.java') for name in names[:MAX_PATHS]):
        return ([dict(file_path=name, start_line=1, end_line=80) for name in observed[:MAX_PATHS]],
                [], [], [dict(file_path=name, reason='LANGUAGE_NOT_SUPPORTED') for name in observed[:MAX_PATHS]])
    try:
        git = GitService(root)
        if git.top_level() != root:
            git = None
    except (GitError, OSError, subprocess.SubprocessError):
        git = None
    import javalang
    for name in names[:MAX_PATHS]:
        reason = 'LANGUAGE_NOT_SUPPORTED'
        if name.endswith('.java'):
            try:
                raw, source = WorkspaceReader(root).read(name, maximum=250_000)
                changed = _changed_lines(git, name) if git and name in observed else set()
                facts, links, limits = _parse(name, source, hashlib.sha256(raw).hexdigest(),
                                              changed, name not in observed)
                if facts:
                    if name in observed:
                        limits.append(dict(file_path=name, reason=('CHECK_PATH_DIFF_NOT_SESSION_ATTRIBUTED'
                                      if changed else 'CHANGED_METHOD_RANGE_UNKNOWN')))
                    nodes.extend(facts)
                    edges.extend(links)
                    gaps.extend(limits)
                    points = sorted(facts, key=lambda n: (
                        n['kind'] not in {'ENTRY', 'WRITE_CANDIDATE', 'CHECK_CANDIDATE', 'DECLARED_GUARD'},
                        not n.get('focus'), n['line_start']))
                    seen = []
                    for point in points:
                        start = point['line_start']
                        if any(first <= start <= end for first, end in seen):
                            continue
                        first, end = max(1, start - 4), start + 23
                        seen.append((first, end))
                        windows.append(dict(file_path=name, start_line=first, end_line=end))
                        if len(seen) == 3:
                            break
                    continue
                reason = 'SPRING_METHOD_NOT_LOCATED'
            except (ValueError, OSError, GitError, subprocess.SubprocessError, KeyError, IndexError,
                    RecursionError, javalang.parser.JavaSyntaxError, javalang.tokenizer.LexerError):
                reason = 'JAVA_EXTRACTION_FAILED'
        gaps.append(dict(file_path=name, reason=reason))
        if name in observed:
            windows.append(dict(file_path=name, start_line=1, end_line=80))
    gaps.extend(dict(file_path=name, reason='INITIAL_PATH_BUDGET') for name in names[MAX_PATHS:MAX_PATHS+50])
    return windows[:MAX_PATHS], nodes, edges, gaps


def project(nodes, edges, gaps, evidence):
    """Return only facts whose locations are covered by same-version receipts."""
    backed = {}
    for item in nodes:
        for receipt in evidence:
            first, last = item['line_start'], item['line_end']
            if (receipt['file_path'] == item['file_path'] and receipt['sha256'] == item['sha256']
                    and receipt['line_start'] <= first <= receipt['line_end']
                    and (last <= receipt['line_end'] or item['kind'] in {'ENTRY', 'METHOD'})):
                backed[item['id']] = dict(item, line_end=min(last, receipt['line_end']),
                                          evidence_ref=receipt['evidence_ref'])
                break
        if len(backed) == 64:
            break
    relations = []
    for edge in edges:
        first, last, proof = edge['from_id'], edge['to_id'], edge['proof']['id']
        if first in backed and last in backed and proof in backed:
            location = backed[proof]
            relations.append(dict(from_id=first, to_id=last, kind=edge['kind'], **{
                key: location[key] for key in ('file_path', 'line_start', 'line_end', 'sha256',
                                                'source', 'evidence_ref')}))
    if any(item['id'] not in backed for item in nodes):
        gaps = [*gaps, dict(reason='INITIAL_EVIDENCE_WINDOW_LIMIT')]
    return dict(nodes=list(backed.values()), edges=relations[:96], gaps=gaps)


def bound(graph, maximum):
    if json_bytes(graph) <= maximum:
        return graph
    graph['gaps'].append(dict(reason='ASSET_GRAPH_RESPONSE_LIMIT'))
    size = json_bytes(graph)
    while graph['edges'] and size > maximum:
        size -= json_bytes(graph['edges'].pop()) + 1
    while graph['nodes'] and size > maximum:
        size -= json_bytes(graph['nodes'].pop()) + 1
    return graph
