"""Conservative, non-executing classification of simple shell command lists.

This is an optimization hint, not a shell interpreter. Unsupported syntax must
reach filesystem reconciliation instead of claiming the command was read-only.
"""
from __future__ import annotations


READ_ONLY = 'READ_ONLY'
UNKNOWN = 'UNKNOWN'
MUTATION = 'POSSIBLE_WORKSPACE_MUTATION'

_READ_COMMANDS = {
    'cat', 'type', 'get-content', 'gc', 'ls', 'dir', 'get-childitem', 'gci',
    'get-location', 'pwd', 'rg', 'grep', 'findstr', 'select-object',
    'sort-object', 'measure-object', 'format-table', 'format-list',
}
_WRITE_COMMANDS = {
    'set-content', 'add-content', 'out-file', 'tee', 'tee-object',
    'rm', 'del', 'erase', 'remove-item', 'mv', 'move', 'move-item',
    'rename', 'rename-item', 'copy', 'cp', 'copy-item', 'new-item', 'mkdir',
}


def _commands(command):
    """Read literal arguments and simple separators shared by Bash/PowerShell.

    No interpolation, invocation operators, script blocks, substitutions,
    escapes or here-documents are evaluated. Quoted query text is only data.
    """
    commands, words, word = [], [], []
    quote, active = None, False
    index = 0
    while index < len(command):
        char = command[index]
        if quote is not None:
            if char == quote:
                quote = None
            elif quote == '"' and (char in '$`' or
                    char == '\\' and index + 1 < len(command) and command[index + 1] in '\\"$`'):
                return None, UNKNOWN
            else:
                word.append(char)
            index += 1
            continue
        # Unquoted globs could expand a filename into an executable option
        # such as ripgrep's --pre. No filesystem expansion is attempted here.
        if char in '$`{}()@*?[]':
            return None, UNKNOWN
        if char in '<>':
            return None, MUTATION
        if char in '\'"':
            if word and word[-1] == '\\':
                return None, UNKNOWN
            quote, active = char, True
        elif char in ';|&\r\n':
            if char == '&' and command[index:index + 2] != '&&':
                return None, UNKNOWN
            if active:
                words.append(''.join(word))
                word, active = [], False
            if words:
                commands.append(words)
                words = []
            elif char not in '\r\n':
                return None, UNKNOWN
            if command[index:index + 2] in {'&&', '||'}:
                index += 1
        elif char.isspace():
            if char not in ' \t':
                return None, UNKNOWN
            if active:
                words.append(''.join(word))
                word, active = [], False
        else:
            word.append(char)
            active = True
        index += 1
    if quote is not None:
        return None, UNKNOWN
    if active:
        words.append(''.join(word))
    if words:
        commands.append(words)
    return commands, None


def _git_readonly(args):
    # Global configuration overrides can install executable helpers. Only
    # literal directory selection and disabling a pager/optional locks qualify.
    while args and args[0] in {'-C', '--no-pager', '--no-optional-locks'}:
        if args[0] == '-C':
            if len(args) < 3:
                return False
            args = args[2:]
        else:
            args = args[1:]
    if not args:
        return False
    subcommand, args = args[0], args[1:]
    if subcommand == 'branch':
        flags = {'--list', '--show-current', '--all', '-a', '--remotes', '-r',
                 '--verbose', '-v', '-vv'}
        return all(arg in flags or '--list' in args and not arg.startswith('-')
                   for arg in args)
    if subcommand not in {'status', 'diff', 'log', 'show'}:
        return False
    # Git accepts abbreviated long options. Fail closed for prefixes too.
    unsafe = {'--output', '--ext-diff', '--textconv'}
    args = args[:args.index('--')] if '--' in args else args
    return not any(arg.startswith('--') and any(
        option.startswith(arg.split('=', 1)[0]) or arg.split('=', 1)[0] == option
        for option in unsafe) for arg in args)


def classify_command(command):
    commands, reason = _commands(command)
    if reason is not None:
        return reason
    if not commands:
        return UNKNOWN
    classifications = []
    for words in commands:
        name, args = words[0].casefold(), words[1:]
        # Backslash-escaped option names differ across shells (e.g. --p\\re).
        # Keep ordinary Windows path arguments, but never trust such options.
        escaped_option = any('\\' in arg and arg.lstrip('\\').startswith('-') for arg in words)
        if escaped_option:
            classifications.append(UNKNOWN)
        elif name in _WRITE_COMMANDS:
            classifications.append(MUTATION)
        elif name == 'git':
            classifications.append(READ_ONLY if _git_readonly(args) else UNKNOWN)
        elif name in _READ_COMMANDS:
            # ripgrep can execute a preprocessor or a hostname helper.
            helpers = {'--pre', '--hostname-bin'}
            executable_option = name == 'rg' and any(arg.split('=', 1)[0] in helpers for arg in args)
            classifications.append(UNKNOWN if executable_option else READ_ONLY)
        else:
            classifications.append(UNKNOWN)
    if MUTATION in classifications:
        return MUTATION
    return READ_ONLY if all(value == READ_ONLY for value in classifications) else UNKNOWN
