from __future__ import annotations

import subprocess
import re
import tempfile
from pathlib import Path
from .dependency_inputs import is_dependency_input


class GitError(RuntimeError):
    pass


class GitService:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.safe_directory = next((parent for parent in (self.root, *self.root.parents) if (parent / ".git").exists()), self.root)
        self._run("rev-parse", "--show-toplevel")

    def _run(self, *args: str) -> str:
        return self._run_bytes(*args).decode('utf-8', errors='replace').strip()

    def _run_bytes(self, *args: str, maximum=4_000_000) -> bytes:
        with tempfile.TemporaryFile() as out:
            p = subprocess.run(["git", "-c", f"safe.directory={self.safe_directory.as_posix()}", "-c", "core.quotepath=false", '-c', 'core.fsmonitor=false', "-C", str(self.root), *args], stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.PIPE, timeout=10, check=False)
            if out.tell() > maximum:
                raise GitError("Git output limit exceeded")
            out.seek(0)
            output = out.read()
        if p.returncode:
            raise GitError('GIT_COMMAND_FAILED')
        return output

    def _paths(self, *args):
        try:
            return [name.decode('utf-8') for name in self._run_bytes(*args).split(b'\0') if name]
        except UnicodeError:
            raise GitError('GIT_FILENAME_ENCODING_UNSUPPORTED') from None

    def branch(self) -> str:
        return self._run("branch", "--show-current")

    def top_level(self) -> Path:
        return Path(self._run("rev-parse", "--show-toplevel")).resolve()

    def changed_files(self, mode: str, staged: bool = False) -> list[str]:
        if mode == "release":
            return [f for f in self._paths("ls-files", "--cached", "--others", "--exclude-standard", '-z') if not f.startswith(".security-runtime/")]
        if mode == "feature":
            base = self._base()
            committed = self._paths("diff", "--name-only", '-z', '--no-renames', "--diff-filter=ACMRD", f"{base}...HEAD")
        else:
            committed = []
        diff_args = ["diff", "--name-only", '-z', '--no-renames', "--diff-filter=ACMRD"]
        if staged:
            diff_args.append("--cached")
        changed = self._paths(*diff_args)
        deleted_from_index = set(self._paths('diff', '--cached', '--name-only', '-z', '--no-renames', '--diff-filter=D')) if staged else set()
        if not staged:
            changed += self._paths("diff", "--cached", "--name-only", '-z', '--no-renames', "--diff-filter=ACMRD")
            changed += self._paths("ls-files", "--others", "--exclude-standard", '-z')
        return sorted({f for f in committed + changed if not f.startswith(".security-runtime/")
                       and (is_dependency_input(f) or
                            (f not in deleted_from_index and (staged or (self.root / f).is_file())))})

    def changed_lines(self, files: list[str], mode: str, staged: bool = False) -> dict[str, set[int]]:
        result: dict[str, set[int]] = {}
        untracked = set(self._paths("ls-files", "--others", "--exclude-standard", '-z')) if not staged else set()
        base = self._base() if mode == "feature" else ""
        for name in files:
            lines: set[int] = set()
            if name in untracked:
                with (self.root / name).open("rb") as source:
                    lines.update(range(1, sum(1 for _ in source) + 1))
            diffs = []
            if mode == "feature":
                diffs.append(self._run("diff", '--no-ext-diff', '--no-textconv', "--unified=0", f"{base}...HEAD", "--", name))
            if not staged:
                diffs.append(self._run("diff", '--no-ext-diff', '--no-textconv', "--unified=0", "--", name))
            diffs.append(self._run("diff", '--no-ext-diff', '--no-textconv', "--cached", "--unified=0", "--", name))
            for diff in diffs:
                for start, count in re.findall(r"^@@ .* \+(\d+)(?:,(\d+))? @@", diff, re.MULTILINE):
                    lines.update(range(int(start), int(start) + int(count or 1)))
            result[name] = lines
        return result

    def _base(self) -> str:
        if self.branch() in {"main", "master"}:
            return "HEAD"
        for candidate in ("origin/main", "origin/master", "main", "master"):
            try:
                self._run("rev-parse", "--verify", candidate)
                if candidate != self.branch():
                    return candidate
            except GitError:
                continue
        raise GitError("No base branch found; feature scan requires main/master or origin/main/master")
