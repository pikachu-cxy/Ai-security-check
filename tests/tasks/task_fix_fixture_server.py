"""Stdio test server with a deliberately local deterministic fixture provider."""
from security_runtime.mcp_server import create_server
from security_runtime.models import ScannerRun
from security_runtime.runtime import SecurityRuntime
from security_runtime.scanners import ScannerRegistry


class FailedLocalProvider:
    name = scanner_id = 'semgrep'
    verification_offline = verification_scope_complete = True

    def supports(self, profile, context):
        return True

    def scan(self, context, normalizer):
        return [], ScannerRun(self.name, 'fixture', 'FAILED', 1, error_code='FIXTURE_FAILURE')


create_server(SecurityRuntime(ScannerRegistry([FailedLocalProvider()]))).run(transport='stdio')
