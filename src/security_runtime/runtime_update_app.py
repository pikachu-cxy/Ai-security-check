"""Read-only MCP App resource. A host must project update metadata alone."""
from pathlib import Path

URI = 'ui://ai-security-runtime/runtime-update'
MIME = 'text/html;profile=mcp-app'


def register_update_resource(server):
    @server.resource(URI, name='Runtime update', mime_type=MIME)
    def runtime_update_card():
        return (Path(__file__).parent / 'assets' / 'runtime_update_card.html').read_text(encoding='utf-8')
