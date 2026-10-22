"""Disposable Vue script projections; preserve original evidence coordinates."""
from pathlib import Path
import os
import hashlib

from .local_evidence import WorkspaceReader
from .vue_scripts import extract_vue_scripts


def _key(path):
    return os.path.normcase(os.path.normpath(str(path)))


class VueProjection:
    def __init__(self, root, files, directory, plan, budget=None, path_filters=False):
        self.aliases = {}
        self.blocks = {}
        self.details = {}
        self.scope = []
        self.fingerprints = {}
        self.plan = plan
        budget = budget if budget is not None else {'files': 0, 'bytes': 0}
        reader = WorkspaceReader(root)
        directory.mkdir(parents=True, exist_ok=True)
        for index, name in enumerate(files):
            if Path(name).suffix.lower() != '.vue':
                self.scope.append(name)
                continue
            detail = dict(script_blocks=0, scanned_script_blocks=0, script_languages=[], scanned_languages=[],
                          issues=[], template_status='NOT_COVERED')
            self.details[name] = detail
            if path_filters:
                detail['issues'] = ['VUE_RULE_PATH_FILTER_UNSUPPORTED']
                continue
            if budget['files'] >= 64 or budget['bytes'] >= 4 * 1024 * 1024:
                detail['issues'] = ['VUE_SCAN_BUDGET_EXCEEDED']
                continue
            budget['files'] += 1
            try:
                remaining = 4 * 1024 * 1024 - budget['bytes']
                raw, _ = reader.read(name, maximum=min(512 * 1024, remaining))
                if budget['bytes'] + len(raw) > 4 * 1024 * 1024:
                    detail['issues'] = ['VUE_SCAN_BUDGET_EXCEEDED']
                    continue
                budget['bytes'] += len(raw)
                self.fingerprints[name] = hashlib.sha256(raw).hexdigest()
                extracted = extract_vue_scripts(raw)
            except (OSError, ValueError) as exc:
                reason = getattr(exc, 'reason', 'VUE_SOURCE_UNAVAILABLE')
                if reason == 'FILE_TOO_LARGE' and remaining < 512 * 1024:
                    reason = 'VUE_SCAN_BUDGET_EXCEEDED'
                detail['issues'] = [reason]
                continue
            detail.update(script_blocks=len(extracted.scripts), issues=list(extracted.issues),
                          script_languages=sorted({s.language for s in extracted.scripts}))
            for ordinal, script in enumerate(extracted.scripts):
                target = directory / f'{index}-{ordinal}{script.suffix}'
                target.write_bytes(script.shadow_bytes)
                path = str(target.resolve())
                self.scope.append(path)
                self.aliases[_key(path)] = name
                self.blocks[_key(path)] = script

    def map_paths(self, value, depth=0):
        if depth > 32:
            return None
        if isinstance(value, dict):
            return {k: self.aliases.get(_key(v), v) if k == 'path' and isinstance(v, str)
                    else self.map_paths(v, depth+1) for k,v in value.items()}
        if isinstance(value, list):
            return [self.map_paths(v, depth+1) for v in value]
        return value

    def finish(self, payloads):
        merged = dict(results=[], errors=[], paths={'scanned': [], 'skipped': []}, time={'rules': []})
        scanned, failed = set(), set()
        for data in payloads:
            scanned.update(_key(p) for p in data.get('paths', {}).get('scanned', []))
            failed.update(_key(e.get('path', '')) for e in data.get('errors', []))
            failed.update(_key(e.get('path', '')) for e in data.get('paths', {}).get('skipped', []))
            for item in data.get('results', []):
                block = self.blocks.get(_key(item.get('path', '')))
                if block is not None:
                    start, end = item.get('start', {}).get('offset'), item.get('end', {}).get('offset')
                    # Never attribute a match in masked template/style text to JS.
                    if (type(start) is not int or type(end) is not int
                            or not block.content_start <= start <= end <= block.content_end):
                        continue
                merged['results'].append(self.map_paths(item))
            merged['errors'].extend(self.map_paths(data.get('errors', [])))
            merged['paths']['scanned'].extend(self.aliases.get(_key(p), p) for p in data.get('paths', {}).get('scanned', []))
            merged['paths']['skipped'].extend(self.map_paths(data.get('paths', {}).get('skipped', [])))
            merged['time']['rules'].extend(data.get('time', {}).get('rules', []))
            merged.setdefault('skipped_rules', []).extend(data.get('skipped_rules', []))
        for alias, name in self.aliases.items():
            if alias in scanned and alias not in failed:
                self.details[name]['scanned_script_blocks'] += 1
                self.details[name]['scanned_languages'].append(self.blocks[alias].language)
        for name, detail in self.details.items():
            if not detail['script_blocks']:
                self.plan.skipped_files[name] = 'VUE_NO_SUPPORTED_SCRIPT'
            detail['status'] = 'PARTIAL' if detail['scanned_script_blocks'] else 'NOT_COVERED'
            detail['scanned_languages'] = sorted(set(detail['scanned_languages']))
        self.plan.embedded_coverage.update(self.details)
        merged['paths']['scanned'] = sorted(set(merged['paths']['scanned']))
        merged['time']['rules'] = sorted(set(merged['time']['rules']))
        return merged
