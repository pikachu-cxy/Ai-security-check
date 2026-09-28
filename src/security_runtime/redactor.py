import re


class SecretRedactor:
    _patterns = [
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
        re.compile(r"(?i)(?:sk-[A-Za-z0-9_-]{12,}|ghp_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16})"),
        re.compile(r"(?i)(?:password|token|api[_-]?key|secret)\s*[:=]\s*['\"]?[^\s,'\"]{8,}"),
        re.compile(r"(?i)(?:postgres(?:ql)?|mysql|mongodb)://[^\s'\"]+"),
    ]

    def redact(self, text: str) -> str:
        for pattern in self._patterns:
            text = pattern.sub("[REDACTED_SECRET]", text)
        return text
