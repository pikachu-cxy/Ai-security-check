"""Cheap observation filtering and bounded closeout-only output declarations."""
from pathlib import PurePosixPath
from .scope_policy import INSTALLATION_DIRS, is_compiled_artifact


def excluded_artifact(name):
    # Exact installation roots and task artifacts only; tests/ and arbitrary
    # .log/.db files may be source, and manifests outside installs stay eligible.
    parts = PurePosixPath(str(name).replace('\\', '/')).parts
    return any(part in INSTALLATION_DIRS or part == '.test-tmp' or part.startswith(('.test-tmp-', '.test-tmp-run'))
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


def watch_only_paths(row):
    """Positive provenance only; legacy/unclassified paths stay mandatory."""
    return set(row.get('watch_paths', ())) - set(row.get('explicit_paths', ()))


def separate_directories(root, names, *, compiled_paths=None, watch_only=(), missing_watch_paths=None):
    """Classify only recorded paths at closeout; never enumerate children.

    Preserve explicit/unknown missing inputs, inaccessible, linked and special
    paths for validation. Only confirmed absent watch-only paths may be skipped.
    Reuse the existing lstat; do not add filesystem probes or inventory.
    """
    import stat
    from .hook_state import native_io_path, no_links
    files, directories = [], []
    for name in names:
        path = root / name
        try:
            no_links(path)
            try:
                mode = native_io_path(path).lstat().st_mode
            except FileNotFoundError:
                if missing_watch_paths is not None and name in watch_only:
                    missing_watch_paths.append(name)
                    continue
                raise
            directory = stat.S_ISDIR(mode)
            if compiled_paths is not None and stat.S_ISREG(mode) and is_compiled_artifact(native_io_path(path)):
                compiled_paths.append(name)
                continue
        except (OSError, ValueError):
            directory = False
        (directories if directory else files).append(name)
    return files, directories


def filter_gitignored(root, names):
    """Query only observed paths; Git keeps tracked files and handles negation.

    Failure retains the complete input. This is a closeout filter, not a
    temporary-file classifier or a repository inventory.
    """
    import subprocess
    from .git import GitService
    from .scan_preferences import section
    if not names:
        return names, [], None
    try:
        git = GitService(root)
        ignored = set()
        for start in range(0, len(names), 32):
            chunk = names[start:start+32]
            result = subprocess.run([
                'git', '-c', f'safe.directory={git.safe_directory.as_posix()}',
                '-c', 'core.fsmonitor=false', '-C', str(root),
                'check-ignore', '-v', '-z', '--stdin'],
                input=b''.join(name.encode('utf-8')+b'\0' for name in chunk),
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                timeout=section('scan', 'git')['timeout_seconds'] or 10, check=False)
            if result.returncode not in (0, 1):
                raise ValueError('GIT_IGNORE_QUERY_FAILED')
            fields = result.stdout.split(b'\0')
            if fields[-1:] == [b'']:
                fields.pop()
            if len(fields) % 4:
                raise ValueError('GIT_IGNORE_OUTPUT_INVALID')
            matches = {fields[i+3].decode('utf-8') for i in range(0, len(fields), 4)
                       if not fields[i+2].startswith(b'!')}
            if not matches.issubset(set(chunk)):
                raise ValueError('GIT_IGNORE_OUTPUT_INVALID')
            ignored.update(matches)
        return [name for name in names if name not in ignored], sorted(ignored), None
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        return names, [], 'GIT_IGNORE_FILTER_UNAVAILABLE'
