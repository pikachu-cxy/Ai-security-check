"""Read-only request projections; host totals never get added to BYOK usage."""


def latest_attempts(records):
    selected = {}
    for record in records:
        model = record['model_request']
        identity = model['attempt_id']
        previous = selected.get(identity)
        if previous is None or (record.get('finished_at') or 0) > (previous.get('finished_at') or 0):
            selected[identity] = record
    return sorted(selected.values(), key=lambda item: item.get('started_at') or 0)


def request_data(records, *, links=(), limit=1000):
    records = latest_attempts(records)
    related = {item['attempt_id']:item for item in links}
    seen, rows, reported = set(), [], []
    incomplete = missing = 0
    # Replayed collector records collapse by local attempt identity. A repeated
    # provider response ID across distinct attempts is ambiguous for aggregation.
    response_ids = {}
    for record in records:
        value = record['model_request'].get('response_fingerprint')
        if value:
            response_ids[value] = response_ids.get(value, 0) + 1
    for record in records:
        value = record['model_request']
        manifest = value['manifest']
        duplicate = response_ids.get(value.get('response_fingerprint'), 0) > 1
        usable = value['usage_status'] == 'REPORTED' and value['state'] != 'STARTED' and not duplicate
        if usable:
            reported.append(value['usage'])
        else:
            missing += 1
        incomplete += value['state'] == 'STARTED'
        components = []
        for component in manifest['components']:
            identity = (component['role'],component['category'],component['fingerprint'])
            components.append(dict(role=component['role'], category=component['category'],
                bytes=component['bytes'], parts=component['parts'],
                reuse='PREVIOUSLY_OBSERVED' if identity in seen else 'FIRST_OBSERVED'))
            seen.add(identity)
        if len(rows) < limit:
            relation = related.get(value['attempt_id'], {})
            rows.append(dict(request_id=value['request_id'], attempt_id=value['attempt_id'],
                parent_call_id=record.get('call_id'), links=relation.get('links', []),
                state=value['state'], usage=value['usage'], usage_status=value['usage_status'],
                aggregate_status='INCLUDED' if usable else 'DUPLICATE_RESPONSE_ID' if duplicate else 'UNKNOWN',
                started_at=record.get('started_at'), finished_at=record.get('finished_at'),
                elapsed_ms=record.get('elapsed_ms'),
                input=dict(status=manifest['status'], request_bytes=manifest['request_bytes'],
                    content_bytes=manifest['content_bytes'], message_count=manifest['message_count'],
                    components=components, component_tokens=None)))
    totals = None
    if reported:
        totals = {name:sum(item[name] for item in reported) if all(item[name] is not None for item in reported) else None
                  for name in ('input_tokens','output_tokens','total_tokens','cached_input_tokens','reasoning_output_tokens')}
    return dict(status='UNAVAILABLE' if not records else 'PARTIAL' if missing else 'AVAILABLE',
        requests=rows, observed_attempts=len(records), pending_attempts=incomplete,
        reported_attempts=len(reported), unknown_or_ambiguous_attempts=missing, reported_usage=totals,
        details_omitted=max(0,len(records)-len(rows)),
        usage_scope='RETAINED_BYOK_ATTEMPTS; PROVIDER_REPORTED; NOT_HOST_TOTAL_OR_BILLING_ATTESTATION',
        input_scope='EXACT_CLIENT_MESSAGES; SERVER_WRAPPERS_AND_COMPONENT_TOKENS_UNKNOWN',
        reuse_scope='SAME_PRODUCER_RETAINED_CONTENT; NOT_PROVIDER_CACHE_HITS',
        native_host_request_usage='UNAVAILABLE', native_host_final_input='UNAVAILABLE')
