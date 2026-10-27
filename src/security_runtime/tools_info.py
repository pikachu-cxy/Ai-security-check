"""Scanner installation guidance, kept separate from doctor and scanner execution."""

INSTALL_DOCS = {
    "opengrep": "https://github.com/opengrep/opengrep",
    "semgrep": "https://semgrep.dev/docs/getting-started/quickstart",
    "gitleaks": "https://github.com/gitleaks/gitleaks#installing",
    "trivy": "https://trivy.dev/latest/getting-started/installation/",
}


def installation_help(name: str) -> str:
    return INSTALL_DOCS.get(name, "")
