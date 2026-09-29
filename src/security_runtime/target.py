import os
from pathlib import Path

from .models import TargetProfile


EXTENSIONS = {".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript", ".java": "Java", ".go": "Go", ".php": "PHP"}
DEPENDENCIES = {"requirements.txt": "pip", "pyproject.toml": "pip", "package.json": "npm", "package-lock.json": "npm", "yarn.lock": "yarn", "pnpm-lock.yaml": "pnpm", "pom.xml": "maven", "build.gradle": "gradle", "go.mod": "go"}
IGNORED = {".git", ".venv", "venv", ".tools", ".security-runtime", "node_modules", ".idea", ".vscode", "dist", "build", "target", "__pycache__"}
MAX_FILES = 10_000
MAX_DIRECTORIES = 2_000


class TargetDetector:
    def detect(self, root: Path, files: list[str] | None = None) -> TargetProfile:
        if files is None:
            files = []
            directory_count = 0
            for directory, subdirs, names in os.walk(root):
                directory_count += 1
                if directory_count > MAX_DIRECTORIES:
                    raise ValueError(f"Project exceeds directory limit ({MAX_DIRECTORIES}); choose a smaller --path")
                subdirs[:] = [name for name in subdirs if name not in IGNORED]
                if directory_count + len(subdirs) > MAX_DIRECTORIES:
                    raise ValueError(f"Project exceeds directory limit ({MAX_DIRECTORIES}); choose a smaller --path")
                if len(files) + len(names) > MAX_FILES:
                    raise ValueError(f"Project exceeds file limit ({MAX_FILES}); choose a smaller --path")
                files.extend((Path(directory) / name).relative_to(root).as_posix() for name in names)
        languages, ecosystems, frameworks = set(), set(), set()
        for name in files:
            path = Path(name)
            if path.suffix.lower() in EXTENSIONS:
                languages.add(EXTENSIONS[path.suffix.lower()])
            if path.name in DEPENDENCIES:
                ecosystems.add(DEPENDENCIES[path.name])
            if path.name in {"main.py", "app.py"}:
                try:
                    if "fastapi" in (root / name).read_text(encoding="utf-8", errors="ignore").lower():
                        frameworks.add("FastAPI")
                except OSError:
                    pass
        return TargetProfile(str(root), languages=sorted(languages), frameworks=sorted(frameworks), ecosystems=sorted(ecosystems), files=sorted(files))
