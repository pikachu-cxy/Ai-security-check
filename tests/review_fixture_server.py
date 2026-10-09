"""Synthetic scanner for protocol/output-volume tests, not scanner acceptance."""
from security_runtime.capabilities import Capability
from security_runtime.local_evidence import snapshot_fingerprint
from security_runtime.models import ScannerRun
from security_runtime.runtime import SecurityRuntime
from security_runtime.scanners import ScannerRegistry
from security_runtime.storage import SQLiteStore
from security_runtime.mcp_server import create_server


class Scanner:
    name=scanner_id='semgrep'
    capabilities=frozenset({Capability.CODE_SAST})
    def supports(self,*args): return True
    def scan(self,context,n):
        findings=[]
        for line in range(3,117):
            finding=n.make(scanner='semgrep',category='tls-validation',title='Synthetic TLS candidate',
                description='Protocol fixture, not real detection',severity='HIGH',confidence='HIGH',
                file_path='App.java',line=line,rule_id='ai-security.java.trust-all-hostname')
            finding.technical_details['evidence_locator']=snapshot_fingerprint(context.root,'App.java')
            findings.append(finding)
        return findings,ScannerRun(self.name,'mock','SUCCESS',1,len(findings))


if __name__=='__main__':
    create_server(SecurityRuntime(ScannerRegistry([Scanner()]),SQLiteStore()),hook_advisory_only=True).run(transport='stdio')
