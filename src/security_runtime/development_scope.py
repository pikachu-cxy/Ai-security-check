"""Path-only exclusions for observed development events; never consult Git."""
from pathlib import PurePosixPath


def excluded_artifact(name):
    # Deliberately narrow: tests/ and arbitrary .log/.db files may be source.
    parts = PurePosixPath(str(name).replace('\\', '/')).parts
    return any(part == '.test-tmp' or part.startswith(('.test-tmp-', '.test-tmp-run'))
               for part in parts)
