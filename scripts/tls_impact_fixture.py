"""Simulated host impact reasoning for disposable, known TLS fixtures only."""
from pathlib import Path


async def fixture_payload(call, name, arguments):
    response = await call(name, arguments)
    return response[0] if isinstance(response, tuple) else response


async def assess_tls_fixture(call, waiting, root, sources):
    for name, expected in sources.items():
        assert name.endswith('.java') and 'HostnameVerifier' in expected and '-> true' in expected
        assert (root / name).read_text(encoding='utf-8') == expected
    required = waiting.get('repair_impact', waiting)
    action = required['next_action']
    assert action['tool'] == 'prepare_repair_impact'
    arguments = action['arguments']
    assert arguments['source']['kind'] == 'SCANNER_TASK_GROUP'
    assert all(change['file_path'] in sources for change in arguments['proposal']['changes'])
    prepared = await fixture_payload(call, action['tool'], arguments)
    ref = prepared['assessment_ref']
    windows, page = [], prepared
    for _ in range(20):
        windows.extend(page['required_windows'])
        offset = page['page']['next_offset']
        if offset is None:
            break
        page = await fixture_payload(call, 'get_repair_impact', dict(
            assessment_ref=ref, workspace_path=str(root), offset=offset))
    else:
        raise AssertionError('Synthetic impact plan exceeded bounded pagination')
    evidence = []
    merged = {}
    for window in sorted(windows, key=lambda item: (item['file_path'], item['start_line'])):
        name, start, end = window['file_path'], window['start_line'], window['end_line']
        ranges = merged.setdefault(name, [])
        if ranges and start <= ranges[-1][1] + 1:
            ranges[-1][1] = max(ranges[-1][1], end)
        else:
            ranges.append([start, end])
    for name, ranges in merged.items():
        assert name in sources
        for start, end in ranges:
            while start <= end:
                result = await fixture_payload(call, 'read_repair_impact_context', dict(
                    assessment_ref=ref, workspace_path=str(root), file_path=name,
                    start_line=start, end_line=min(end, start + 79)))
                assert result['numbered_lines'] and result['start_line'] == start
                evidence.append(result['evidence_ref'])
                start = result['end_line'] + 1
    evidence = list(dict.fromkeys(evidence))
    assert evidence and len(evidence) <= 12
    saved = await fixture_payload(call, 'submit_repair_impact', dict(
        assessment_ref=ref, workspace_path=str(root), coverage='REVIEWED',
        impacts=[dict(kind='EXPECTED_SECURITY_RESTRICTION',
            summary='Known synthetic TLS fixture only: restore platform hostname validation; '
                    'valid hostnames remain permitted and unconditional trust is removed. '
                    'This is simulated host reasoning, not human or production compatibility proof.',
            evidence_refs=evidence)], unknowns=[]))
    assert saved['gate'] == 'READY_FOR_EXISTING_AUTH' and not saved['repair_authorized'], saved
    assert all((root / name).read_text(encoding='utf-8') == expected for name, expected in sources.items())
    return ref


async def confirm_tls_fixture(call, arguments, source, expected):
    assert arguments['approve'] is True
    assert source.read_text(encoding='utf-8') == expected
    waiting = await fixture_payload(call, 'confirm_remediation', arguments)
    assert waiting['status'] == 'IMPACT_REQUIRED', waiting
    required = waiting.get('repair_impact', waiting)
    root = Path(required['next_action']['arguments']['workspace_path'])
    name = source.relative_to(root).as_posix()
    ref = await assess_tls_fixture(call, waiting, root, {name: expected})
    return await fixture_payload(call, 'confirm_remediation', dict(arguments, impact_ref=ref))
