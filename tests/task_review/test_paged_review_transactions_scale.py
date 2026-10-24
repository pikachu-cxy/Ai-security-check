"""Actual >4 MB new-head metadata integration, not MCP or host acceptance."""
import copy
import hashlib
import json
import time

from security_runtime.snapshot_contract import development_capabilities
from security_runtime.task_review.paged_task_store import (
    PagedReviewTaskStore, SOURCE_RETENTION_DOMAIN, source_binding,
)
from security_runtime.tasks.security_state import MAX_RECORD_BYTES
from security_runtime.tasks.snapshot_pages import _store
from test_paged_review_transactions import (
    OWNER, _assert_legacy_unchanged, _create, _head, _metadata, _mutate, _sample,
)
from test_review_metadata_compatibility import _encoded, _unit


def test_more_than_four_megabytes_keep_one_small_head_and_all_original_source_refs(tmp_path):
    sample = _sample(tmp_path)
    started = time.perf_counter()
    _create(sample)
    original = copy.deepcopy(_head(sample))
    for field in ("baseline", "end"):
        pointer = original[field]["paged_entries"]
        binding = source_binding(sample.binding, field, pointer["source"])
        sealed_source = _store(sample.state).resume(pointer["ref"], binding)
        assert sealed_source["state"] == "SEALED"
        assert sealed_source["binding"]["retention_domain"] == SOURCE_RETENTION_DOMAIN
    assert SOURCE_RETENTION_DOMAIN != "TASK_PAGES_GC_V1"
    plan = _mutate(sample, dict(kind="create", name="plan"), "scale-create-plan")
    ref = plan["metadata"]["ref"]
    sizes, encoded_bytes, expected_digest = [], 0, hashlib.sha256()
    count, batch = 1001, 12
    previous = _head(sample)
    for offset in range(0, count, batch):
        items = [_unit(index) for index in range(offset, min(offset + batch, count))]
        for item in items:
            raw = _encoded(item)
            encoded_bytes += len(raw)
            expected_digest.update(raw + b"\n")
        receipt = _mutate(sample, dict(kind="append", ref=ref, items=items),
                          f"scale-append-{offset}", head=previous)
        current = _head(sample)
        assert current["generation"] == previous["generation"] + 1 == receipt["head_generation"]
        assert current["metadata_generation"] == previous["metadata_generation"] + 1
        assert current["metadata_generation"] == current["generation"]
        for field in ("baseline", "end", "source_catalog"):
            assert current[field] == original[field]
        sizes.append(len(_encoded(current)))
        assert sizes[-1] <= 32_768
        assert receipt["metadata"]["item_count"] == offset + len(items)
        previous = current
    sealed = _mutate(sample, dict(kind="seal", ref=ref, expected_items=count),
                      "scale-seal", head=previous)
    assert sealed["metadata"]["state"] == "SEALED"
    assert encoded_bytes == 4_699_695 and encoded_bytes > MAX_RECORD_BYTES
    assert max(sizes) - min(sizes) < 32  # Only small counter-digit growth.

    # Every method closes its SQLite transaction.  Drop the previous client and
    # authenticate the original head again through a newly constructed client.
    sample.store = None
    reopened = PagedReviewTaskStore(sample.state)
    head = reopened.get(sample.binding.task_ref, dict(OWNER))
    assert head["generation"] == sealed["head_generation"]
    assert head["metadata_generation"] == head["generation"]
    assert len(_encoded(head)) <= 32_768
    for field in ("baseline", "end", "source_catalog"):
        assert head[field] == original[field]
    metadata = _metadata(sample)
    ledger = metadata.ledger(sample.binding)
    read_digest, seen, cursor, pages = hashlib.sha256(), 0, 0, 0
    with metadata.reader(ref, sample.binding) as reader:
        while True:
            page = reader.page(after_page=cursor)
            pages += 1
            for item in page["items"]:
                assert item == _unit(seen)
                read_digest.update(_encoded(item) + b"\n")
                seen += 1
            if page["next_cursor"] is None:
                break
            assert page["next_cursor"] > cursor
            cursor = page["next_cursor"]
    assert seen == count and pages == sealed["metadata"]["page_count"]
    assert read_digest.hexdigest() == expected_digest.hexdigest()
    assert metadata.ledger(sample.binding) == ledger
    assert reopened.get(sample.binding.task_ref, dict(OWNER)) == head
    _assert_legacy_unchanged(sample)
    assert development_capabilities()["paged_review_storage"] is False
    print(json.dumps(dict(scope="internal-new-head-metadata-integration", items=seen,
                          pages=pages, encoded_bytes=encoded_bytes,
                          initial_head_bytes=len(_encoded(original)),
                          maximum_head_bytes=max(sizes), final_head_bytes=len(_encoded(head)),
                          final_generation=head["generation"],
                          elapsed_seconds=round(time.perf_counter() - started, 3),
                          source_refs_unchanged=True, source_retention_domain=SOURCE_RETENTION_DOMAIN,
                          production_review_enabled=False),
                     sort_keys=True))
