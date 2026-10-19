"""Platform defaults for installer children, without changing the host environment."""
from __future__ import annotations

import os
from pathlib import Path
import ssl
import sys
import tempfile
import urllib.request

MACOS = sys.platform == 'darwin'
SYSTEM_CA = Path('/etc/ssl/cert.pem')


def temporary_parent():
    from .hook_state import no_links
    parent = Path(tempfile.gettempdir())
    # Accept only Apple's conventional top-level aliases. An arbitrary linked
    # TMPDIR or a link below /private/var must still fail strict validation.
    for alias, target in [('/var', '/private/var'), ('/tmp', '/private/tmp')]:
        base = Path(alias)
        if (MACOS and parent.is_relative_to(base) and base.is_symlink()
                and os.readlink(base) in {target, target.lstrip('/')}):
            parent = Path(target) / parent.relative_to(base)
            break
    no_links(parent)
    return parent.resolve(strict=True)


def network_environment(environment=None):
    child = dict(os.environ if environment is None else environment)
    if not MACOS:
        return child
    if environment is None:
        # Python discovers macOS System Configuration proxies; external Go and
        # pip helpers need the same settings explicitly in their child env.
        proxies = urllib.request.getproxies()
        for scheme, name in [('http', 'HTTP_PROXY'), ('https', 'HTTPS_PROXY'), ('no', 'NO_PROXY')]:
            if proxies.get(scheme) and not child.get(name) and not child.get(name.lower()):
                child[name] = proxies[scheme]
    # Explicit certificate configuration remains authoritative, including a
    # broken path: never silently bypass an administrator's trust policy.
    ca = child.get('SSL_CERT_FILE')
    if not ca and not child.get('SSL_CERT_DIR') and SYSTEM_CA.is_file():
        ca = str(SYSTEM_CA)
        child['SSL_CERT_FILE'] = ca
    if ca:
        child.setdefault('REQUESTS_CA_BUNDLE', ca)
        child.setdefault('PIP_CERT', ca)
    return child


def download_context():
    environment = network_environment()
    return ssl.create_default_context(cafile=environment.get('SSL_CERT_FILE'))
