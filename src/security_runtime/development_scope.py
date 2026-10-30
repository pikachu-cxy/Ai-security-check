"""Cheap observation filtering and bounded closeout-only output declarations."""
from pathlib import PurePosixPath


def excluded_artifact(name):
    # Deliberately narrow: tests/ and arbitrary .log/.db files may be source.
    parts = PurePosixPath(str(name).replace('\\', '/')).parts
    return any(part == '.test-tmp' or part.startswith(('.test-tmp-', '.test-tmp-run'))
               for part in parts)


def output_roots(root, values):
    """Validate exact task-owned output roots, never glob or global exclusions."""
    from .hook_state import no_links
    from .scan_request import relative_path
    if not isinstance(values, (list, tuple)) or len(values) > 32:
        raise ValueError('DEVELOPMENT_OUTPUT_ROOTS_INVALID')
    result = set()
    for value in values:
        name = relative_path(value)
        if name == '.' or any(char in name for char in '*?[]') or '.git' in PurePosixPath(name).parts:
            raise ValueError('DEVELOPMENT_OUTPUT_ROOTS_INVALID')
        target = root / name
        no_links(target)
        if not target.resolve().is_relative_to(root):
            raise ValueError('DEVELOPMENT_OUTPUT_ROOTS_INVALID')
        result.add(name)
    if sum(len(name.encode()) for name in result) > 4096:
        raise ValueError('DEVELOPMENT_OUTPUT_ROOTS_INVALID')
    return sorted(result)


def select_outputs(root, row):
    """Closeout-only classification of observed paths; never inventory the repo.

    A declaration is not proof that a file is generated. Explicit edits and
    tracked files always win. On any verification failure keep every input.
    Hooks keep the original bounded path journal, not a permanent ignore list.
    """
    import os
    from .git import GitService
    observed = [name for name in row['observed_paths'] if not excluded_artifact(name)]
    declared = row.get('generated_output_roots', [])
    facts = dict(declared_roots=declared, excluded_paths=[], protected_paths=[], gaps=[])
    if not declared:
        return observed, facts
    try:
        roots = output_roots(root, declared)
        def beneath(name, parent):
            name = os.path.normcase(name).replace('\\', '/')
            parent = os.path.normcase(parent).replace('\\', '/')
            return name == parent or name.startswith(parent + '/')
        candidates = [name for name in observed if any(beneath(name, parent) for parent in roots)]
        protected = {os.path.normcase(name) for name in row.get('explicit_paths', [])}
        # Only queried candidates, bounded chunks and output. No Git on the
        # file-watch hot path and no recursive project/baseline inventory.
        if candidates:
            git = GitService(root)
            for start in range(0, len(candidates), 8):
                data = git._run_bytes('ls-files', '--cached', '-z', '--',
                    *(':(literal)' + name for name in candidates[start:start+8]), maximum=64_000)
                protected.update(os.path.normcase(name.decode('utf-8'))
                                 for name in data.split(b'\0') if name)
        excluded = {name for name in candidates if os.path.normcase(name) not in protected}
        facts.update(excluded_paths=sorted(excluded),
                     protected_paths=sorted(name for name in candidates if os.path.normcase(name) in protected))
        return [name for name in observed if name not in excluded], facts
    except (OSError, ValueError, RuntimeError, __import__('subprocess').TimeoutExpired):
        facts['gaps'] = ['GENERATED_OUTPUT_SCOPE_UNVERIFIABLE']
        return observed, facts
