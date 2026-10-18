"""Exercise the real v3 navigation, source delivery and batch APIs in tests."""


def evidence_id(packet):
    """Use an actually issued ID, including a duplicate delivery receipt."""
    if 'evidence_id' in packet:
        return packet['evidence_id']
    assert packet['status'] == 'ALREADY_DELIVERED'
    refs = packet['evidence_refs']
    assert refs and all(isinstance(item, str) for item in refs)
    return refs[0]


def read_plan(service, root, ref, packet):
    """Collect every navigation fragment without reading or completing units."""
    page = service.review_plan(root, ref, packet['review_session'], cursor=0, limit=5)
    units, sources = {}, {}
    while True:
        sources.update((source['source_ref'], source) for source in page['sources'])
        for item in page['units']:
            unit = units.setdefault(item['unit_id'], dict(item, required_windows=[]))
            unit['required_windows'].extend(dict(sources[window['source_ref']], **window)
                                            for window in item['required_windows'])
        if page['next_cursor'] is None:
            return list(units.values()), sources
        page = service.review_plan(root, ref, packet['review_session'],
                                   cursor=page['next_cursor'], limit=5)


def read_window(service, root, ref, session, window):
    source_version = ('BEFORE_TASK' if window['location_version'] in
                      {'BEFORE_TASK', 'BEFORE_DELETION'} else 'CURRENT')
    low, high, delivered = window['start_line'], window['end_line'], []
    assert high is not None
    while low <= high:
        requested_high = min(high, low + 79)
        pending = [[low, requested_high]]
        while pending:
            first, last = pending.pop(0)
            packet = service.read(root, ref, session, window['path'], first, last,
                                  source_version=source_version)
            delivered.append(packet)
            evidence_id(packet)
            if 'next_range' in packet:
                pending.append(packet['next_range'])
            pending.extend(packet.get('unread_ranges', []))
        low = requested_high + 1
    return delivered


def review_all(service, root, ref, packet):
    """Explicitly deliver all required versions, then submit their real units."""
    units, _ = read_plan(service, root, ref, packet)
    delivered = []
    for unit in units:
        for window in unit['required_windows']:
            delivered.extend(read_window(service, root, ref, packet['review_session'], window))
        result = service.submit_batch(root, ref, packet['review_session'],
                                      [unit['unit_id']], 'REVIEWED', [])
        assert result['status'] == 'BATCH_RECORDED' and result['scanner_run'] is False
    return delivered, units
