import re


class SecretRedactor:
    # Evidence has already replaced literals before this generic pass. Preserve
    # only a complete marker value; a marker followed by extra credential text
    # must still be treated as a secret. Do not protect markers globally.
    _credential_pattern = re.compile(
        r"(?i)(?:password|token|api[_-]?key|secret)\s*[:=]\s*"
        r"(?:(?P<safe>\[REDACTED_(?:LITERAL|SECRET|COMMENT)\])(?=$|[\s,;)}\]])"
        r"|['\"]?[^\s,'\"]{8,})")
    _patterns = [
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
        re.compile(r"(?i)(?:sk-[A-Za-z0-9_-]{12,}|ghp_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16})"),
        re.compile(r"(?i)(?:postgres(?:ql)?|mysql|mongodb)://[^\s'\"]+"),
    ]

    def redact(self, text: str) -> str:
        for pattern in self._patterns:
            text = pattern.sub("[REDACTED_SECRET]", text)
        return self._credential_pattern.sub(
            lambda match: match.group(0) if match.group('safe') else '[REDACTED_SECRET]', text)
