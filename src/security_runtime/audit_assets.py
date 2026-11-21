"""Bounded, evidence-backed source-region assets for a development audit.

The graph is language agnostic: every text file yields ``FILE`` grouping nodes and
``SOURCE_REGION`` windows. Only regions covered by a same-version evidence receipt
enter the graph. Git HEAD differences are used to locate changed lines and never
prove that a line was edited by this session.
"""
import hashlib
import re
import subprocess

from .git import GitError, GitService
from .local_evidence import WorkspaceReader
from .review_delivery import json_bytes

MAX_PATHS = 8
WINDOW_LINES = 80
MERGE_GAP = 8
FIRST_PACKAGE_ITEMS = 4
GIT_HEAD_DIFF = 'GIT_HEAD_DIFF'
CHANGED_LINES_UNKNOWN = 'CHANGED_LINES_UNKNOWN'


def _identifier(kind, path, start, end):
    return 'asset-' + hashlib.sha256(
        repr((path, kind, start, end)).encode()).hexdigest()[:24]


def _changed_lines(git, path):
    """Candidate lines from the working-tree diff against HEAD, if available."""
    if git is None:
        return set()
    try:
        diff = git._run('diff', '--no-ext-diff', '--no-textconv', '--unified=0',
                        'HEAD', '--', ':(literal)' + path)
    except (GitError, OSError, subprocess.SubprocessError):
        return set()
    lines = set()
    for start, count in re.findall(r'^@@ .* \+(\d+)(?:,(\d+))? @@', diff, re.M):
        start = max(1, int(start))
        lines.update(range(start, start + max(1, int(count or 1))))
    return lines


def _windows(lines, total):
    """Bounded windows covering changed lines, one cluster at a time."""
    clusters = []
    for line in sorted(lines):
        if clusters and line - clusters[-1][1] <= MERGE_GAP:
            clusters[-1][1] = line
        else:
            clusters.append([line, line])
    windows = []
    for first, last in clusters:
        cursor = first
        while cursor <= last:
            start = max(1, cursor - 4)
            end = min(total, start + WINDOW_LINES - 1)
            if end < cursor:
                end = min(total, cursor)
                start = max(1, end - WINDOW_LINES + 1)
            # A neighbouring change already covered by the previous window must
            # not consume another read window.
            if windows and start >= windows[-1][0] and end <= windows[-1][1]:
                break
            windows.append((start, end))
            cursor = end + 1
    return windows


def plan(root, paths, related=()):
    """Use only explicitly observed or owner-authorized paths."""
    observed = list(dict.fromkeys(paths))
    names = list(dict.fromkeys([*observed, *related]))
    try:
        git = GitService(root)
        if git.top_level() != root:
            git = None
    except (GitError, OSError, subprocess.SubprocessError):
        git = None
    reader = WorkspaceReader(root)
    gaps, candidates = [], []
    for name in names[:MAX_PATHS]:
        try:
            raw, source = reader.read(name, maximum=250_000)
        except (ValueError, OSError):
            gaps.append(dict(file_path=name, reason='SOURCE_UNREADABLE'))
            continue
        total = len(source.splitlines())
        if not total:
            gaps.append(dict(file_path=name, reason='EMPTY_FILE'))
            continue
        changed = {line for line in _changed_lines(git, name) if line <= total}
        if changed:
            windows = _windows(changed, total)
            locator = GIT_HEAD_DIFF
            gaps.append(dict(file_path=name, reason='CHECK_PATH_DIFF_NOT_SESSION_ATTRIBUTED'))
        else:
            windows = []
            locator = CHANGED_LINES_UNKNOWN
            gaps.append(dict(file_path=name, reason=CHANGED_LINES_UNKNOWN))
        candidates.append(dict(file_path=name, sha256=hashlib.sha256(raw).hexdigest(),
                               locator=locator, windows=windows, line_count=total))
    # Spread the window budget over distinct files first, then deepen one file.
    chosen, depth = [], 0
    while len(chosen) < MAX_PATHS:
        progressed = False
        for candidate in candidates:
            if depth < len(candidate['windows']):
                chosen.append((candidate, candidate['windows'][depth]))
                progressed = True
                if len(chosen) == MAX_PATHS:
                    break
        if not progressed:
            break
        depth += 1
    nodes, edges, windows = [], [], []
    for candidate in candidates:
        picked = [window for owner, window in chosen if owner is candidate]
        if not picked and candidate['windows']:
            gaps.append(dict(file_path=candidate['file_path'], reason='INITIAL_PATH_BUDGET'))
            continue
        file_id = _identifier('FILE', candidate['file_path'], 1, 1)
        file = dict(id=file_id, kind='FILE', name=candidate['file_path'],
                          file_path=candidate['file_path'], line_start=1, line_end=1,
                          sha256=candidate['sha256'], source='WORKSPACE_SOURCE')
        if candidate['locator'] == CHANGED_LINES_UNKNOWN:
            file.update(locator=CHANGED_LINES_UNKNOWN, line_count=candidate['line_count'])
        nodes.append(file)
        for start, end in picked:
            region = dict(id=_identifier('SOURCE_REGION', candidate['file_path'], start, end),
                          kind='SOURCE_REGION',
                          name=f"{candidate['file_path']}:{start}-{end}",
                          file_path=candidate['file_path'], line_start=start, line_end=end,
                          sha256=candidate['sha256'], locator=candidate['locator'],
                          source='WORKSPACE_SOURCE')
            nodes.append(region)
            edges.append(dict(from_id=file_id, to_id=region['id'], kind='CONTAINS', proof=region))
            windows.append(dict(file_path=candidate['file_path'], start_line=start, end_line=end))
    gaps.extend(dict(file_path=name, reason='INITIAL_PATH_BUDGET') for name in names[MAX_PATHS:MAX_PATHS + 50])
    return windows, nodes, edges, gaps


def project(nodes, edges, gaps, evidence):
    """Keep receipt-backed regions and file-only targets for Worker reads."""
    receipts = {}
    for receipt in evidence:
        receipts.setdefault((receipt['file_path'], receipt['sha256']), []).append(receipt)
    backed = {}
    for item in nodes:
        if item['kind'] != 'SOURCE_REGION':
            continue
        for receipt in receipts.get((item['file_path'], item['sha256']), ()):
            if receipt['line_start'] <= item['line_start'] and item['line_end'] <= receipt['line_end']:
                backed[item['id']] = dict(item, evidence_ref=receipt['evidence_ref'])
                break
        if len(backed) == 64:
            break
    files = {item['file_path']: item for item in nodes
             if item['kind'] == 'FILE' and item.get('locator') == CHANGED_LINES_UNKNOWN}
    for item in backed.values():
        files.setdefault(item['file_path'], dict(
            id=_identifier('FILE', item['file_path'], 1, 1), kind='FILE', name=item['file_path'],
            file_path=item['file_path'], line_start=1, line_end=1, sha256=item['sha256'],
            source=item['source'], evidence_ref=item['evidence_ref']))
    relations = []
    file_ids = {node['id'] for node in files.values()}
    for edge in edges:
        first, last = edge['from_id'], edge['to_id']
        if first in file_ids and last in backed:
            proof = backed[last]
            relations.append(dict(from_id=first, to_id=last, kind=edge['kind'], **{
                key: proof[key] for key in ('file_path', 'line_start', 'line_end', 'sha256',
                                            'source', 'evidence_ref')}))
    if any(item['kind'] == 'SOURCE_REGION' and item['id'] not in backed for item in nodes):
        gaps = [*gaps, dict(reason='INITIAL_EVIDENCE_WINDOW_LIMIT')]
    return dict(nodes=[*files.values(), *backed.values()], edges=relations[:96], gaps=gaps)


def first_package(evidence, remaining):
    """Reuse already-read evidence as the Planner's first readable source package."""
    items = []
    for item in evidence[:FIRST_PACKAGE_ITEMS]:
        entry = {key: item[key] for key in ('file_path', 'line_start', 'line_end',
                                            'sha256', 'evidence_ref', 'content')}
        size = json_bytes(entry) + 1
        if items and size > remaining:
            break
        items.append(entry)
        remaining -= size
    return items


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
