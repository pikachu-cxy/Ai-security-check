"""Conservative, non-executing classification of simple shell command lists.

This is an optimization hint, not a shell interpreter. Unsupported syntax must
reach filesystem reconciliation instead of claiming the command was read-only.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import shlex


READ_ONLY = 'READ_ONLY'
UNKNOWN = 'UNKNOWN'
MUTATION = 'POSSIBLE_WORKSPACE_MUTATION'
OUTSIDE_WORKSPACE = 'OUTSIDE_WORKSPACE_MUTATION'

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


def _trusted_powershell(value):
    """Only unwrap the owned native shell, never an arbitrary lookalike EXE."""
    if os.name != 'nt':
        return False
    try:
        from .hook_state import no_links
        candidate = Path(value)
        if not candidate.is_absolute():
            return False
        no_links(candidate)
        resolved = candidate.resolve(strict=True)
        bundled = (Path.home()/'.cache/codex-runtimes/codex-primary-runtime'
                   /'dependencies/native/powershell/pwsh.exe')
        system = (Path(os.environ.get('SystemRoot', r'C:\Windows'))
                  /'System32/WindowsPowerShell/v1.0/powershell.exe')
        if any(resolved == allowed.resolve() for allowed in (bundled, system)):
            return True
        # Desktop Store installs use a versioned package under WindowsApps.
        # Require the publisher, package shape and exact bundled shell path;
        # a similarly named executable elsewhere must remain unknown.
        package_root = Path(os.environ.get('ProgramFiles', r'C:\Program Files'))/'WindowsApps'
        parts = resolved.relative_to(package_root.resolve()).parts
        return (len(parts) == 5 and re.fullmatch(
            r'OpenAI\.CodexPrimaryRuntime\.v\d+(?:-\d+)*_\d+(?:\.\d+){3}_'
            r'(?:x64|arm64)__3k8sg7r9htsxt', parts[0], re.I) is not None
            and tuple(p.casefold() for p in parts[1:]) ==
                ('dependencies', 'native', 'powershell', 'pwsh.exe'))
    except (OSError, ValueError, RuntimeError):
        return False


def _unwrap_powershell(command):
    try:
        words = shlex.split(command, posix=True)
    except ValueError:
        return command
    if not words or not _trusted_powershell(words[0]):
        return command
    options = words[1:]
    while options and options[0].casefold() in {'-noprofile', '-noninteractive', '-nologo'}:
        options = options[1:]
    if len(options) != 2 or options[0].casefold() != '-command':
        return command
    return options[1]


def _readonly_powershell_fragments(command):
    # Recognize only local numeric bookkeeping and an identity pipeline. Do
    # not treat general PowerShell script blocks or assignments as read-only.
    quoted, quote = set(), None
    for index, char in enumerate(command):
        if quote is not None:
            quoted.add(index)
            if char == quote:
                quote = None
        elif char in '\'"':
            quote = char
            quoted.add(index)
    patterns = (
        (re.compile(r'(^|[;\r\n])([ \t]*)\$[A-Za-z_]\w*[ \t]*=[ \t]*[+-]?\d+(?:\.\d+)?(?=[ \t]*(?:[;\r\n]|$))'),
         lambda match: match[1]+match[2]+'Get-Location'),
        (re.compile(r'(?<=\|)[ \t]*ForEach-Object[ \t]+\{[ \t]*\$_[ \t]*\}(?=[ \t]*(?:[;|\r\n]|$))', re.I),
         lambda match: ' Select-Object'),
    )
    replacements = []
    for pattern, replacement in patterns:
        for match in pattern.finditer(command):
            if not any(index in quoted for index in range(match.start(), match.end())):
                replacements.append((match.start(), match.end(), replacement(match)))
    for start, end, replacement in sorted(replacements, reverse=True):
        command = command[:start]+replacement+command[end:]
    return command


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


def _statements(command):
    """Split literal statements without interpreting quoted separators."""
    start, quote = 0, None
    for index, char in enumerate(command):
        if quote:
            if char == quote:
                quote = None
        elif char in '\'"':
            quote = char
        elif char in ';\r\n':
            yield command[start:index].strip()
            start = index + 1
    yield command[start:].strip()


def _readonly_content_fragments(command):
    # Only recognize values established in this command. No shell evaluation,
    # methods, interpolation, computed indices or arbitrary variable reads.
    if '$' not in command:
        return command
    paths, contents, output = {}, set(), []
    for statement in _statements(command):
        literal = re.fullmatch(r'''\$([A-Za-z_]\w*)\s*=\s*(['"])([^'"$`\r\n]+)\2''', statement)
        if literal and not any(c in literal[3] for c in '{}()<>;|&'):
            name = literal[1].casefold()
            paths[name] = literal[2] + literal[3] + literal[2]
            contents.discard(name)
            output.append('Get-Location')
            continue
        assignment = re.fullmatch(r'\$([A-Za-z_]\w*)\s*=\s*(Get-Content\s+.+)', statement, re.I)
        expression = assignment[2] if assignment else statement
        variable = re.fullmatch(r'Get-Content\s+\$([A-Za-z_]\w*)', expression, re.I)
        if variable and variable[1].casefold() in paths:
            expression = 'Get-Content ' + paths[variable[1].casefold()]
        words, reason = _commands(expression)
        # Avoid output/pipeline variable options: Get-Content accepts only a
        # literal path and bounded read options in this assignment grammar.
        if assignment and reason is None and len(words) == 1 and _content_read(words[0]):
            name = assignment[1].casefold()
            contents.add(name)
            paths.pop(name, None)
            output.append(expression)
            continue
        selection = re.fullmatch(r'\$([A-Za-z_]\w*)(?:\[\s*-?\d+\s*(?:\.\.\s*-?\d+\s*)?\])?', statement)
        if selection and selection[1].casefold() in contents:
            output.append('Get-Location')
        else:
            output.append(statement if assignment else expression)
    return '; '.join(output)


def _content_read(words):
    if not words or words[0].casefold() != 'get-content':
        return False
    args, paths = iter(words[1:]), 0
    for arg in args:
        if arg.casefold() in {'-path', '-literalpath'}:
            arg = next(args, '')
        elif arg.casefold() in {'-totalcount', '-tail'}:
            if not next(args, '').isdigit():
                return False
            continue
        elif arg.casefold() == '-raw':
            continue
        if not arg or arg.startswith('-') or any(c in arg for c in '$`{}()<>;|&'):
            return False
        paths += 1
    return paths == 1


def _outside_removal(words, root):
    """Prove a narrow literal cleanup cannot touch this workspace tree."""
    if root is None or words[0].casefold() not in {'remove-item', 'rm'}:
        return False
    flags = ({'-recurse', '-force', '-literalpath', '-path'}
             if words[0].casefold() == 'remove-item' else {'-r', '-f', '-rf', '-fr', '--'})
    targets = [arg for arg in words[1:] if arg.casefold() not in flags]
    if not targets or len(targets) > 32:
        return False
    try:
        from .hook_state import no_links
        root = Path(root)
        no_links(root)
        root = root.resolve(strict=True)
        for value in targets:
            if value.startswith(('-', '//', '\\\\')) or any(c in value for c in '*?[]$`{},;|&<>'):
                return False
            path = Path(value)
            if not path.is_absolute() or '..' in path.parts:
                return False
            no_links(path)
            # Windows short names and spelling aliases must not turn a
            # workspace/ancestor deletion into an apparently external path.
            path = path.resolve(strict=False)
            if path.is_relative_to(root) or root.is_relative_to(path):
                return False
        return True
    except (OSError, ValueError, RuntimeError):
        return False


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
    if subcommand == 'rev-parse':
        flags = {'--show-toplevel', '--git-dir', '--git-common-dir', '--is-inside-work-tree',
                 '--is-bare-repository', '--show-prefix', '--verify', '--quiet', '-q',
                 '--path-format=absolute', '--path-format=relative'}
        return bool(args) and all(arg in flags or arg == 'HEAD' for arg in args)
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


def classify_command(command, *, workspace=None):
    command = _readonly_powershell_fragments(_unwrap_powershell(command))
    command = _readonly_content_fragments(command)
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
        elif '|' not in command and '&' not in command and _outside_removal(words, workspace):
            classifications.append(OUTSIDE_WORKSPACE)
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
    if OUTSIDE_WORKSPACE in classifications and all(value in {READ_ONLY, OUTSIDE_WORKSPACE} for value in classifications):
        return OUTSIDE_WORKSPACE
    return READ_ONLY if all(value == READ_ONLY for value in classifications) else UNKNOWN
