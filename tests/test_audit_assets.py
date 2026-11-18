from security_runtime import audit_assets
from security_runtime.audit_stream_service import manage, process
from test_development_risks import sample


def spring_source(guard):
    return ('import org.springframework.web.bind.annotation.*;\n'
            '@RestController\nclass RefundController {\n' + '\n' * 100
            + '@PostMapping("/refund")\nvoid refund(String owner) {\n'
            + ('  verifyOwner(owner);\n' if guard else '')
            + '  service.saveRefund(owner);\n}\n'
            + 'void verifyOwner(String owner) { if (!owner.equals(principal)) throw new Denied(); }\n}\n')


def test_spring_facts_have_same_version_receipts_and_skip_file_header(sample):
    root, service, ref, risks = sample
    for path, protected in [('Protected.java', True), ('Unprotected.java', False)]:
        (root / path).write_text(spring_source(protected), encoding='utf-8')
    (root / 'Unapproved.java').write_text(spring_source(True), encoding='utf-8')
    service.record(root, ref, ['Protected.java', 'Unprotected.java'])
    token = manage(risks, 'prepare')['audit_token']
    manage(risks, 'started', agent_ref='asset-worker', audit_token=token)
    result = process(risks, 'claim', agent_ref='asset-worker', audit_token=token)
    graph = result['context']['asset_graph']
    nodes = graph['nodes']
    receipts = {e['evidence_ref']: e for e in result['context']['evidence']}
    assert {(n['file_path'], n['kind']) for n in nodes} >= {
        ('Protected.java', 'CHECK_CANDIDATE'), ('Unprotected.java', 'WRITE_CANDIDATE')}
    unprotected_entry = next(n['id'] for n in nodes
                             if n['file_path'] == 'Unprotected.java' and n['kind'] == 'ENTRY')
    checks = {n['id'] for n in nodes if n['kind'] == 'CHECK_CANDIDATE'}
    assert not any(e['from_id'] == unprotected_entry and e['to_id'] in checks for e in graph['edges'])
    assert not any(n['file_path'] == 'Unapproved.java' for n in nodes)
    assert any(e['kind'] == 'LOCAL_DECLARATION_CANDIDATE' for e in graph['edges'])
    for item in nodes + graph['edges']:
        receipt = receipts[item['evidence_ref']]
        assert receipt['file_path'] == item['file_path']
        assert receipt['sha256'] == item['sha256']
        assert receipt['line_start'] <= item['line_start'] <= item['line_end'] <= receipt['line_end']
        assert receipt['line_start'] > 80
    assert any(g['reason'] == 'CALL_BINDING_UNKNOWN' for g in graph['gaps'])
    assert any(g['reason'] == 'LANGUAGE_NOT_SUPPORTED' for g in graph['gaps'])


def test_unparseable_java_has_fallback(sample):
    root = sample[0]
    (root / 'Broken.java').write_text('class Broken {', encoding='utf-8')
    windows, facts, edges, gaps = audit_assets.plan(root, ['Broken.java'])
    assert windows == [dict(file_path='Broken.java', start_line=1, end_line=80)]
    assert not facts and not edges
    assert gaps == [dict(file_path='Broken.java', reason='JAVA_EXTRACTION_FAILED')]
