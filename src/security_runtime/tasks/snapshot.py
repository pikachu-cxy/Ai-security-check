"""Finite, synchronous task snapshots, independent of review delivery budgets.

The inventory defines the work.  Elapsed time never discards source evidence:
file, byte and private-store quotas bound collection instead.  The caller must
finish the initial collection before allowing edits; this module never fills an
old baseline from later workspace contents.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path

from ..local_evidence import EvidenceUnavailable
from ..local_evidence import MAX_FILE_BYTES
from ..local_evidence import WorkspaceReader
from ..local_evidence import safe_source
from . import preimages as task_preimages
from ..source_redaction import VERSION, SUPPORTED_VERSIONS


MAX_READ_BYTES = 20_000_000
MAX_INLINE_TEXT_BYTES = 512_000
MAX_INVENTORY_PATHS = 20_000
MAX_INVENTORY_NAME_BYTES = 256_000
MAX_INVENTORY_DIRECTORIES = 2000
MAX_INVENTORY_DEPTH = 12
MAX_LIMITATIONS = 100


@dataclass(frozen=True)
class SnapshotPolicy:
    """A caller may lower supported capacities, never bypass the private store."""

    max_files: int | None = task_preimages.MAX_TASK_FILES
    max_read_bytes: int = MAX_READ_BYTES
    max_inline_text_bytes: int = MAX_INLINE_TEXT_BYTES
    max_inventory_paths: int = MAX_INVENTORY_PATHS
    max_inventory_name_bytes: int = MAX_INVENTORY_NAME_BYTES
    max_inventory_directories: int = MAX_INVENTORY_DIRECTORIES
    max_inventory_depth: int = MAX_INVENTORY_DEPTH

    def __post_init__(self):
        ceilings = dict(max_files=task_preimages.MAX_TASK_FILES,
            max_read_bytes=min(MAX_READ_BYTES, task_preimages.MAX_TASK_BYTES),
            max_inline_text_bytes=min(MAX_INLINE_TEXT_BYTES, task_preimages.MAX_TASK_BYTES),
            max_inventory_paths=MAX_INVENTORY_PATHS,
            max_inventory_name_bytes=MAX_INVENTORY_NAME_BYTES,
            max_inventory_directories=MAX_INVENTORY_DIRECTORIES,
            max_inventory_depth=MAX_INVENTORY_DEPTH)
        for key, maximum in ceilings.items():
            value = getattr(self, key)
            if key == 'max_files' and value is None:
                continue  # New batched tasks use byte/storage admission, not a prefix.
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError('Invalid task snapshot capacity: '+key)

    def limits(self):
        return dict(asdict(self), max_file_bytes=MAX_FILE_BYTES,
            max_private_file_body_bytes=task_preimages.MAX_FILE_BODY_BYTES,
            max_private_task_bytes=task_preimages.MAX_TASK_BYTES,
            max_private_workspace_bytes=task_preimages.MAX_WORKSPACE_BYTES,
            max_private_database_bytes=task_preimages.MAX_DATABASE_BYTES)


def _environment(name):
    return Path(name).name == '.env' or Path(name).name.startswith('.env.')


def collect_snapshot(root, *, inventory, dirty=(), inventory_complete=True,
                     inventory_limits=(), known_paths=None, priority_paths=(),
                     include_text=True, preimage_writer=None, policy=None,
                     reader_factory=WorkspaceReader, sanitizer=safe_source, raw_sink=None,
                     redaction_version=VERSION):
    """Collect one bounded before-edit or current-version snapshot.

    ``inventory`` comes from the caller's guarded project boundary discovery.
    Read failures consume their reserved allowance conservatively: failure after
    opening a binary/invalid source cannot grant another unlimited read.  Raw
    bytes and exception text never become part of the returned record.
    """
    policy = policy or SnapshotPolicy()
    if type(redaction_version) is not int or redaction_version not in SUPPORTED_VERSIONS:
        raise ValueError('Unsupported source redaction policy')
    if preimage_writer is not None and getattr(preimage_writer, 'redaction_version', redaction_version) != redaction_version:
        raise ValueError('Snapshot and preimage representation differ')
    root = Path(root)
    reader = reader_factory(root)
    names = list(dict.fromkeys(inventory))
    inventory_count = len(names)
    known = set(known_paths) if known_paths is not None else None
    added = [name for name in names if known is not None and name not in known]
    priority = list(dict.fromkeys([*priority_paths, *added, *sorted(dirty)]))
    available = set(names)
    ordered = list(dict.fromkeys([*(name for name in priority if name in available), *names]))
    limitations = list(inventory_limits)
    read_limitations = list(inventory_limits)
    complete = inventory_complete

    def limit(reason, *, read=False, **details):
        item = dict(reason=reason, **details)
        limitations.append(item)
        if read:
            read_limitations.append(item)

    selected, name_bytes = [], 0
    for name in ordered:
        cost = len(name.encode('utf-8'))
        if len(selected) >= policy.max_inventory_paths:
            complete = False
            limit('SNAPSHOT_INVENTORY_FILE_BUDGET', read=True,
                  limit=policy.max_inventory_paths, pending_count=len(ordered)-len(selected))
            break
        if name_bytes+cost > policy.max_inventory_name_bytes:
            complete = False
            limit('SNAPSHOT_INVENTORY_NAME_BYTE_BUDGET', read=True,
                  limit=policy.max_inventory_name_bytes, used=name_bytes,
                  pending_count=len(ordered)-len(selected))
            break
        selected.append(name)
        name_bytes += cost

    hashes, texts, truncations, preimages, unavailable, line_counts = {}, {}, {}, {}, {}, {}
    attempts, accepted_bytes, reserved_failed_bytes, text_bytes, private_bytes = 0, 0, 0, 0, 0
    byte_limited = False
    scheduled = selected if policy.max_files is None else selected[:policy.max_files]
    for index, name in enumerate(scheduled):
        if index and index % 256 == 0 and callable(getattr(preimage_writer, 'checkpoint', None)):
            preimage_writer.checkpoint()
        used_bytes = accepted_bytes+reserved_failed_bytes
        remaining = policy.max_read_bytes-used_bytes
        if remaining <= 0:
            byte_limited = True
            limit('SNAPSHOT_READ_BYTE_BUDGET', read=True, limit=policy.max_read_bytes,
                  used=used_bytes, pending_count=len(selected)-index)
            break
        maximum = min(MAX_FILE_BYTES, remaining)
        attempts += 1
        try:
            raw, text = reader.read(name, maximum=maximum)
        except (OSError, EvidenceUnavailable, UnicodeError) as exc:
            # The guarded reader may have rejected data after actually reading
            # it. Charge its full reservation rather than resetting that work.
            reserved_failed_bytes += maximum
            if getattr(exc, 'reason', None) == 'FILE_TOO_LARGE' and maximum < MAX_FILE_BYTES:
                byte_limited = True
                limit('SNAPSHOT_READ_BYTE_BUDGET', read=True, path=name,
                      limit=policy.max_read_bytes, used=accepted_bytes+reserved_failed_bytes,
                      pending_count=len(selected)-index)
                break
            limit(getattr(exc, 'reason', 'SOURCE_UNAVAILABLE'), read=True, path=name)
            continue
        hashes[name] = hashlib.sha256(raw).hexdigest()
        line_counts[name] = len(text.splitlines())
        accepted_bytes += len(raw)
        if not include_text or _environment(name):
            continue
        if raw_sink is not None:
            raw_sink.put(name, raw)
        if preimage_writer is not None:
            try:
                if callable(getattr(preimage_writer, 'put_source', None)):
                    prepared = preimage_writer.put_source(name, raw)
                    reference, truncated = prepared['reference'], prepared['truncated_lines']
                else:
                    truncated = []
                    lines = sanitizer(text, source_path=name, truncation_lines=truncated,
                                      max_line_chars=None, redaction_version=redaction_version)
                    reference = preimage_writer.put(name, raw, lines)
                preimages[name] = reference
                private_bytes += reference['body_bytes']
                if truncated:
                    truncations[name] = dict(line_count=len(truncated), lines=truncated)
            except task_preimages.TaskPreimageUnavailable as exc:
                unavailable[name] = exc.reason_code
                limit(exc.reason_code, path=name)
            continue
        truncated = []
        lines = sanitizer(text, source_path=name, truncation_lines=truncated,
                          max_line_chars=None, redaction_version=redaction_version)
        if truncated:
            truncations[name] = dict(line_count=len(truncated), lines=truncated)
        cost = len(json.dumps(lines, ensure_ascii=True).encode('utf-8'))
        if text_bytes+cost <= policy.max_inline_text_bytes:
            texts[name] = lines
            text_bytes += cost
        else:
            unavailable[name] = 'SNAPSHOT_INLINE_TEXT_BYTE_BUDGET'
            limit('SNAPSHOT_INLINE_TEXT_BYTE_BUDGET', path=name,
                  limit=policy.max_inline_text_bytes, used=text_bytes, required=cost)
    if policy.max_files is not None and len(selected) > policy.max_files and not byte_limited:
        limit('SNAPSHOT_READ_FILE_BUDGET', read=True, limit=policy.max_files,
              used=attempts, pending_count=len(selected)-attempts)

    expected_bodies = sum(not _environment(name) for name in names) if include_text else 0
    body_count = len(texts)+len(preimages)
    reason_counts = dict(Counter(item.get('reason', 'UNKNOWN') for item in limitations))
    stats = dict(inventory_file_count=inventory_count,
        inventory_count_complete=bool(inventory_complete),
        inventory_total_file_count=inventory_count if inventory_complete else None,
        selected_inventory_file_count=len(selected),
        attempted_file_count=attempts, hashed_file_count=len(hashes),
        pending_hash_file_count=(inventory_count-len(hashes) if inventory_complete else None),
        known_pending_hash_file_count=inventory_count-len(hashes),
        hash_complete=bool(complete and len(hashes) == inventory_count),
        body_requested=bool(include_text),
        expected_body_file_count=(expected_bodies if inventory_complete or not include_text else None),
        saved_body_file_count=body_count,
        pending_body_file_count=(expected_bodies-body_count if inventory_complete or not include_text else None),
        known_pending_body_file_count=expected_bodies-body_count,
        body_complete=(bool(complete and body_count == expected_bodies) if include_text else None),
        accepted_source_bytes=accepted_bytes, failed_read_reserved_bytes=reserved_failed_bytes,
        read_budget_used_bytes=accepted_bytes+reserved_failed_bytes,
        inline_body_bytes=text_bytes, private_body_bytes=private_bytes,
        limitation_count=len(limitations), limitation_omitted_count=max(0,len(limitations)-MAX_LIMITATIONS),
        limitation_reason_counts=reason_counts, limits=policy.limits())
    return dict(hashes=hashes, texts=texts, text_truncations=truncations, redaction_version=redaction_version,
        line_counts=line_counts, preimages=preimages, text_unavailable=unavailable,
        limitations=limitations[:MAX_LIMITATIONS], read_limitations=read_limitations[:MAX_LIMITATIONS],
        inventory=sorted(selected), inventory_complete=complete,
        read_priority=scheduled, capture_stats=stats)
