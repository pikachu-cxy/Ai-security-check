import subprocess

from security_runtime import audit_assets
from test_development_risks import sample  # noqa: F401  (fixture)


def python_source(note=''):
    """A 102 line module whose only change is a comment on the last line."""
    lines = ['OWNER = None', 'STATUS = None']
    lines += [f'STEP_{index} = {index}' for index in range(2, 99)]
    lines += ['def refund(owner):', '    check_owner(owner)',
              '    save_refund(owner)' + (f'  # {note}' if note else '')]
    return '\n'.join(lines) + '\n'


def plain_java():
    """Ordinary Java with no Spring annotation or framework import."""
    lines = ['class RefundService {']
    lines += [f'    int step{index}() {{ return {index}; }}' for index in range(1, 90)]
    lines += ['    void refund(String owner) {', '        save(owner);', '    }', '}']
    return '\n'.join(lines) + '\n'


def git_repo(root):
    subprocess.run(['git', 'init', '-q', str(root)], check=True)
    for key, value in (('user.email', 'dev@example.test'), ('user.name', 'Dev')):
        subprocess.run(['git', '-C', str(root), 'config', key, value], check=True)


def commit_file(root, name, text):
    (root / name).write_text(text, encoding='utf-8')
    subprocess.run(['git', '-C', str(root), 'add', '--', name], check=True)
    subprocess.run(['git', '-C', str(root), 'commit', '-qm', 'base'], check=True)


def test_changed_lines_locate_the_first_package_region(sample):
    root = sample[0]
    git_repo(root)
    commit_file(root, 'refund.py', python_source())
    (root / 'refund.py').write_text(python_source('clarify'), encoding='utf-8')
    windows, nodes, edges, gaps = audit_assets.plan(root, ['refund.py'])
    assert windows == [dict(file_path='refund.py', start_line=98, end_line=102)]
    regions = [node for node in nodes if node['kind'] == 'SOURCE_REGION']
    assert len(regions) == 1 and regions[0]['locator'] == audit_assets.GIT_HEAD_DIFF
    assert regions[0]['line_start'] <= 102 <= regions[0]['line_end']
    files = [node for node in nodes if node['kind'] == 'FILE']
    assert len(files) == 1 and files[0]['file_path'] == 'refund.py'
    assert edges == [dict(from_id=files[0]['id'], to_id=regions[0]['id'],
                          kind='CONTAINS', proof=regions[0])]
    assert {gap['reason'] for gap in gaps} == {'CHECK_PATH_DIFF_NOT_SESSION_ATTRIBUTED'}


def test_evidence_projection_requires_the_same_version(sample):
    root = sample[0]
    git_repo(root)
    commit_file(root, 'refund.py', python_source())
    (root / 'refund.py').write_text(python_source('clarify'), encoding='utf-8')
    windows, nodes, edges, gaps = audit_assets.plan(root, ['refund.py'])
    region = next(node for node in nodes if node['kind'] == 'SOURCE_REGION')
    receipt = dict(file_path='refund.py', line_start=windows[0]['start_line'],
                   line_end=windows[0]['end_line'], sha256=region['sha256'],
                   evidence_ref='dre1-proof')
    graph = audit_assets.project(nodes, edges, gaps, [receipt])
    assert {node['kind'] for node in graph['nodes']} == {'FILE', 'SOURCE_REGION'}
    assert all(node['evidence_ref'] == 'dre1-proof' for node in graph['nodes'])
    assert [edge['kind'] for edge in graph['edges']] == ['CONTAINS']
    assert not audit_assets.project(nodes, edges, gaps, [dict(receipt, sha256='0' * 64)])['nodes']
    assert not audit_assets.project(nodes, edges, gaps, [])['nodes']


def test_no_git_uses_file_head_and_marks_unknown_changes(sample):
    root = sample[0]
    (root / 'module.ts').write_text(python_source(), encoding='utf-8')
    windows, nodes, edges, gaps = audit_assets.plan(root, ['module.ts'])
    assert windows == [dict(file_path='module.ts', start_line=1, end_line=80)]
    region = next(node for node in nodes if node['kind'] == 'SOURCE_REGION')
    assert region['locator'] == audit_assets.FILE_HEAD_FALLBACK
    assert {gap['reason'] for gap in gaps} == {'CHANGED_LINES_UNKNOWN'}


def test_plain_java_needs_no_spring_annotations(sample):
    root = sample[0]
    (root / 'RefundService.java').write_text(plain_java(), encoding='utf-8')
    windows, nodes, edges, gaps = audit_assets.plan(root, ['RefundService.java'])
    assert [node['kind'] for node in nodes] == ['FILE', 'SOURCE_REGION']
    assert not any(gap['reason'] in {'LANGUAGE_NOT_SUPPORTED', 'JAVA_EXTRACTION_FAILED',
                                     'SPRING_METHOD_NOT_LOCATED'} for gap in gaps)


def test_empty_and_unreadable_files_only_record_gaps(sample):
    root = sample[0]
    (root / 'empty.py').write_text('', encoding='utf-8')
    windows, nodes, edges, gaps = audit_assets.plan(root, ['empty.py', 'missing.py'])
    assert windows == [] and not nodes and not edges
    assert {gap['reason'] for gap in gaps} == {'EMPTY_FILE', 'SOURCE_UNREADABLE'}


def test_window_budget_prefers_distinct_files(sample):
    root = sample[0]
    git_repo(root)
    base = '\n'.join(f'LINE_{index} = {index}' for index in range(1, 901)) + '\n'
    commit_file(root, 'wide.py', base)
    commit_file(root, 'narrow.py', base)
    wide = base.splitlines()
    for line in (10, 120, 230, 340, 450, 560, 670, 780):
        wide[line - 1] = wide[line - 1] + '  # changed'
    (root / 'wide.py').write_text('\n'.join(wide) + '\n', encoding='utf-8')
    narrow = base.splitlines()
    narrow[899] = narrow[899] + '  # changed'
    (root / 'narrow.py').write_text('\n'.join(narrow) + '\n', encoding='utf-8')
    windows, nodes, edges, gaps = audit_assets.plan(root, ['wide.py', 'narrow.py'])
    assert len(windows) == audit_assets.MAX_PATHS
    per_file = {name: sum(window['file_path'] == name for window in windows)
                for name in ('wide.py', 'narrow.py')}
    assert per_file == {'wide.py': 7, 'narrow.py': 1}
    assert not any(gap.get('file_path') == 'narrow.py' and gap['reason'] == 'INITIAL_PATH_BUDGET'
                   for gap in gaps)


def test_neighbouring_changes_share_one_window(sample):
    root = sample[0]
    git_repo(root)
    base = python_source()
    commit_file(root, 'refund.py', base)
    lines = base.splitlines()
    for index in (95, 100, 102):
        lines[index - 1] = lines[index - 1] + '  # changed'
    (root / 'refund.py').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    windows, nodes, edges, gaps = audit_assets.plan(root, ['refund.py'])
    assert len(windows) == 1
    assert windows[0]['start_line'] <= 95 and windows[0]['end_line'] >= 102


def test_first_package_reuses_evidence_inside_the_budget():
    evidence = [dict(file_path='a.py', line_start=1, line_end=2, sha256='a' * 64,
                     evidence_ref='dre1-a', content='one\ntwo\n'),
                dict(file_path='b.py', line_start=3, line_end=4, sha256='b' * 64,
                     evidence_ref='dre1-b', content='three\nfour\n')]
    package = audit_assets.first_package(evidence, 100_000)
    assert [item['evidence_ref'] for item in package] == ['dre1-a', 'dre1-b']
    assert package[0]['content'] == 'one\ntwo\n'
    assert [item['evidence_ref'] for item in audit_assets.first_package(evidence, 1)] == ['dre1-a']
