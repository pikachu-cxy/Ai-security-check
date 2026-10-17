"""Small shared linear scanner for untrusted quoted source literals."""


def quoted_literals(line, *, strict=False):
    """Single pass over bounded untrusted text, including malformed strings."""
    index = 0
    while index < len(line):
        if line[index] not in {'\'', '"'}:
            index += 1
            continue
        start, quote = index, line[index]
        index += 1
        while index < len(line):
            if line[index] == '\\':
                index += 2
            elif line[index] == quote:
                index += 1
                yield line[start:index]
                break
            else:
                index += 1
        else:
            if strict:
                raise ValueError('Quoted literal is incomplete')
            return
