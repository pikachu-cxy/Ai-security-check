"""Explicit mocked scanners; real stdio MCP server for host-agent acceptance."""
from pathlib import Path
import os
from security_runtime.models import ScannerRun
from security_runtime.runtime import SecurityRuntime
from security_runtime.storage import SQLiteStore
from security_runtime.scanners import ScannerRegistry
from security_runtime.capabilities import Capability
from security_runtime.mcp_server import create_server


class Scanner:
    name=scanner_id='semgrep'
    capabilities=frozenset({Capability.CODE_SAST,Capability.SECRET_SCAN})
    def supports(self,*args): return True
    def scan(self,context,n):
        return [n.make(scanner='semgrep',category='trust-all-tls',title='TLS candidate',description='test',severity='HIGH',confidence='HIGH',file_path='App.java',line=3,rule_id='test-tls'),
            n.make(scanner='gitleaks',category='secret',title='Secret candidate',description='test',severity='HIGH',confidence='HIGH',file_path='config.properties',line=1,evidence='[REDACTED_SECRET]')],ScannerRun(self.name,'mock','SUCCESS',1,2)


if __name__=='__main__':
    create_server(SecurityRuntime(ScannerRegistry([Scanner()]),SQLiteStore())).run(transport='stdio')
