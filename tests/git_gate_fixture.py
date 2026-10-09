"""Deterministic provider for real Git-commit control-flow tests, not detection quality."""
import sys
from pathlib import Path

from security_runtime.git import GitError
from security_runtime.hooks import gate_exit
from security_runtime.models import ScannerRun, RunStatus
from security_runtime.runtime import SecurityRuntime
from security_runtime.storage import SQLiteStore


class Provider:
    name = scanner_id = 'fixed-local-provider'
    capabilities = ('CODE_SAST', 'SECRET_SCAN')
    filter_changed_lines = True
    def supports(self, profile, context):
        return True
    def scan(self, context, normalizer):
        found = []
        for name in context.files:
            for line, raw in enumerate((Path(context.root) / name).read_text().splitlines(), 1):
                if raw == 'RISK':
                    found.append(normalizer.make(scanner=self.name, category='command-injection', title='Fixture',
                        description='Fixture marker', severity='HIGH', confidence='HIGH', file_path=name,
                        line=line, evidence='RISK'))
                if raw == 'INCOMPLETE':
                    return [], ScannerRun(self.name, 'fixture', RunStatus.UNAVAILABLE, 0)
        return found, ScannerRun(self.name, 'fixture', RunStatus.SUCCESS, 0)


class Registry:
    adapters = [Provider()]


if __name__ == '__main__':
    try:
        result = SecurityRuntime(Registry(), SQLiteStore()).scan(Path.cwd(), staged=True)
        raise SystemExit(gate_exit(result, 'strict'))
    except (GitError, ValueError, OSError):
        raise SystemExit(2)
