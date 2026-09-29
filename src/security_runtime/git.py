from __future__ import annotations

import subprocess
import re
import tempfile
from pathlib import Path


class GitError(RuntimeError):
    pass


class GitService:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.safe_directory = next((parent for parent in (self.root, *self.root.parents) if (parent / ".git").exists()), self.root)
        self._run("rev-parse", "--show-toplevel")

    def _run(self, *args: str) -> str:
        with tempfile.TemporaryFile() as out:
            p = subprocess.run(["git", "-c", f"safe.directory={self.safe_directory.as_posix()}", "-c", "core.quotepath=false", "-C", str(self.root), *args], stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.PIPE, timeout=10, check=False)
            if out.tell() > 4_000_000:
                raise GitError("Git output limit exceeded")
            out.seek(0)
            output = out.read().decode("utf-8", errors="replace")
        if p.returncode:
            raise GitError(p.stderr.decode("utf-8", errors="replace").strip()[:300])
        return output.strip()

    def branch(self) -> str:
        return self._run("branch", "--show-current")

    def top_level(self) -> Path:
        return Path(self._run("rev-parse", "--show-toplevel")).resolve()

    def changed_files(self, mode: str, staged: bool = False) -> list[str]:
        if mode == "release":
            return [f for f in self._run("ls-files", "--cached", "--others", "--exclude-standard").splitlines() if not f.replace("\\", "/").startswith(".security-runtime/")]
        if mode == "feature":
            base = self._base()
            committed = self._run("diff", "--name-only", "--diff-filter=ACMR", f"{base}...HEAD").splitlines()
        else:
            committed = []
        diff_args = ["diff", "--name-only", "--diff-filter=ACMR"]
        if staged:
            diff_args.append("--cached")
        changed = self._run(*diff_args).splitlines()
        if not staged:
            changed += self._run("diff", "--cached", "--name-only", "--diff-filter=ACMR").splitlines()
            changed += self._run("ls-files", "--others", "--exclude-standard").splitlines()
        return sorted({f.replace("\\", "/") for f in committed + changed if not f.replace("\\", "/").startswith(".security-runtime/") and (self.root / f).is_file()})

    def changed_lines(self, files: list[str], mode: str, staged: bool = False) -> dict[str, set[int]]:
        result: dict[str, set[int]] = {}
        untracked = set(self._run("ls-files", "--others", "--exclude-standard").splitlines()) if not staged else set()
        base = self._base() if mode == "feature" else ""
        for name in files:
            lines: set[int] = set()
            if name in untracked:
                with (self.root / name).open("rb") as source:
                    lines.update(range(1, sum(1 for _ in source) + 1))
            diffs = []
            if mode == "feature":
                diffs.append(self._run("diff", "--unified=0", f"{base}...HEAD", "--", name))
            if not staged:
                diffs.append(self._run("diff", "--unified=0", "--", name))
            diffs.append(self._run("diff", "--cached", "--unified=0", "--", name))
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
