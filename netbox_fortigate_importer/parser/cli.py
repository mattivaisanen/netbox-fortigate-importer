"""
FortiOS CLI configuration parser.

Turns the text of a FortiGate backup or `show full-configuration` output into
a tree of `Section` objects. Pure Python, no Django, so it can be tested and
reused on its own.

The FortiOS CLI is line based:

    config <path words...>      open a table (or a settings block)
    edit <name>                 open an entry of the table
    set <key> <value...>        set a value (several tokens for lists)
    unset <key>                 clear a value
    append <key> <value...>     add to a list value
    next                        close the entry
    end                         close the table

Tables nest (`config` inside `edit`, or inside another `config`). Values are
bare words or quoted strings, and quoted strings may span several lines
(certificates, replacement messages). Scripts also use `delete`, `rename`,
`move`, `clone`, `purge`, `select` and `unselect`; those are applied to the
tree so that a CLI script and a backup give the same result.

Secrets are removed while parsing (see secrets.py): they never reach the
tree, so nothing downstream can store them by accident.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .secrets import is_secret

__all__ = ['Section', 'ParseResult', 'ParseError', 'parse', 'tokenize_line']


class ParseError(ValueError):
    """The input is not a FortiOS configuration at all."""


@dataclass
class Section:
    """
    A `config` block or an `edit` entry.

    - `values`: `set` keys to their list of tokens (quotes removed).
    - `tables`: nested `config` blocks, by their path (`"system interface"`).
    - `entries`: `edit` entries of this table, in file order, by name.
    """
    name: str = ''
    values: dict[str, list[str]] = field(default_factory=dict)
    tables: dict[str, 'Section'] = field(default_factory=dict)
    entries: dict[str, 'Section'] = field(default_factory=dict)

    # Helpers used by the extractors. They never raise on missing data.

    def get(self, key, default=None):
        """The single value of `key` (first token), or `default`."""
        tokens = self.values.get(key)
        if not tokens:
            return default
        return tokens[0]

    def get_list(self, key):
        """All tokens of `key`, or an empty list."""
        return list(self.values.get(key) or [])

    def get_int(self, key, default=None):
        value = self.get(key)
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def is_enabled(self, key, default=False):
        value = self.get(key)
        if value is None:
            return default
        return value == 'enable'

    def table(self, path):
        """The nested table at `path`, or an empty Section."""
        return self.tables.get(path) or Section(name=path)

    def has_table(self, path):
        return path in self.tables

    def __iter__(self):
        """Iterate over (name, entry) pairs of this table."""
        return iter(self.entries.items())


@dataclass
class ParseResult:
    root: Section
    header: dict[str, str]
    warnings: list[str]
    #: How many values were dropped as secrets (counts only, never values).
    secrets_removed: int = 0
    #: Command lines seen (for the summary).
    lines: int = 0


MAX_WARNINGS = 200
_COMMAND_LINE = re.compile(r'[ \t]*(set|unset|append|next|end|edit|config)\b')
_PROMPT_RE = re.compile(r'^[\w.\-()]+ *[#$] *(show|get|config|end|execute)\b')
_MORE_RE = re.compile(r'--More--\s*(\r)?')


def tokenize_line(text, pos=0):
    """
    Read one command from `text` starting at `pos`. Returns (tokens, new_pos).

    Works like a shell: a token ends at unquoted whitespace, and quoted and
    bare parts next to each other join into one token ("new"_name is
    new_name). A backslash takes the next character literally, inside or
    outside quotes; outside quotes, a backslash before a newline continues
    the line. Quoted parts may contain newlines (certificates, messages).

    A quote left open on a line whose next line is a CLI command (`set`,
    `next`, `end`, ...) is a typo, not a multi-line value: it is closed at the
    end of its line, so one stray quote can't swallow the rest of the file.
    Returns (tokens, new_pos, repaired) where `repaired` says that happened.
    """
    tokens = []
    length = len(text)
    repaired = False
    current = None  # list of chars of the token being read, or None
    while pos < length:
        char = text[pos]
        if char == '\n':
            pos += 1
            break
        if char in ' \t\r':
            if current is not None:
                tokens.append(''.join(current))
                current = None
            pos += 1
            continue
        if current is None:
            current = []
        if char == '\\' and pos + 1 < length:
            nxt = text[pos + 1]
            if nxt == '\n':
                pos += 2  # line continuation
                continue
            current.append(nxt)
            pos += 2
            continue
        if char in '"\'':
            quote = char
            pos += 1
            multiline = False
            while pos < length:
                char = text[pos]
                if char == '\\' and pos + 1 < length:
                    current.append(text[pos + 1])
                    pos += 2
                    continue
                if char == quote:
                    pos += 1
                    break
                if char == '\n' and not multiline and _COMMAND_LINE.match(text, pos + 1):
                    repaired = True
                    break  # stray quote: close it here; the newline ends the command
                if char == '\n':
                    multiline = True
                current.append(char)
                pos += 1
            continue
        current.append(char)
        pos += 1
    if current is not None:
        tokens.append(''.join(current))
    return tokens, pos, repaired


def _clean(text):
    if text.startswith('﻿'):
        text = text[1:]
    text = text.replace('\r\n', '\n')
    text = _MORE_RE.sub('', text)
    return text


def parse(text):
    """
    Parse FortiOS configuration text into a ParseResult. Raises ParseError if
    the text has no FortiOS commands at all (not a FortiGate config).
    """
    if not isinstance(text, str):
        raise TypeError('parse() takes text; decode the file first')
    text = _clean(text)
    root = Section(name='')
    header = {}
    warnings = []
    secrets_removed = 0
    commands = 0

    # Stack of (section, kind, path) where kind is 'table' or 'entry'.
    stack = [(root, 'root', '')]
    pos = 0
    line_no = 0  # line number of the command being read (1-based)
    next_line = 1
    length = len(text)
    while pos < length:
        line_no = next_line
        start = pos
        # Fast path for header comments: '#key=value' at the start of a line.
        # Leading whitespace is fine.
        stripped_start = pos
        while stripped_start < length and text[stripped_start] in ' \t':
            stripped_start += 1
        if stripped_start < length and text[stripped_start] == '#':
            end = text.find('\n', stripped_start)
            end = length if end == -1 else end
            comment = text[stripped_start + 1:end].strip()
            if '=' in comment and len(stack) == 1:
                key, _, value = comment.partition('=')
                header.setdefault(key.strip(), value.strip())
            pos = end + 1
            next_line += 1
            continue

        tokens, pos, repaired = tokenize_line(text, pos)
        next_line += text.count('\n', start, pos)
        if repaired:
            warnings.append(f'line {line_no}: unbalanced quote, closed at the end of the line')
        if not tokens:
            continue
        raw_line = text[start:pos].strip()
        if _PROMPT_RE.match(raw_line) and tokens[0] not in ('config', 'end', 'edit', 'set', 'next'):
            continue  # a CLI prompt captured with the output ("FGT # show")

        command = tokens[0].lower()
        args = tokens[1:]
        current, kind, path = stack[-1]
        commands += 1

        if command == 'config':
            if not args:
                warnings.append(f'line {line_no}: "config" without a name')
                continue
            name = ' '.join(args)
            table = current.tables.get(name)
            if table is None:
                table = Section(name=name)
                current.tables[name] = table
            stack.append((table, 'table', name))
        elif command == 'edit':
            if kind != 'table':
                warnings.append(f'line {line_no}: "edit" outside a table')
                continue
            if not args:
                warnings.append(f'line {line_no}: "edit" without a name')
                continue
            name = args[0]
            entry = current.entries.get(name)
            if entry is None:
                entry = Section(name=name)
                current.entries[name] = entry
            stack.append((entry, 'entry', name))
        elif command == 'next':
            if kind == 'entry':
                stack.pop()
            else:
                warnings.append(f'line {line_no}: "next" outside an entry')
        elif command == 'end':
            # "end" closes the table; an entry still open is closed with it
            # (FortiOS accepts a missing "next" before "end").
            if kind == 'entry':
                stack.pop()
                current, kind, path = stack[-1]
            if kind == 'table':
                stack.pop()
            else:
                warnings.append(f'line {line_no}: "end" without a matching "config"')
        elif command in ('set', 'append', 'unset', 'select', 'unselect'):
            if not args:
                warnings.append(f'line {line_no}: "{command}" without a key')
                continue
            key = args[0]
            values = args[1:]
            if command == 'unset':
                current.values.pop(key, None)
                continue
            table_path = path if kind == 'table' else (stack[-2][2] if len(stack) > 1 else '')
            if is_secret(key, values, table_path):
                secrets_removed += 1
                current.values.pop(key, None)
                continue
            if command == 'set':
                current.values[key] = values
            elif command in ('append', 'select'):
                existing = current.values.setdefault(key, [])
                existing.extend(v for v in values if v not in existing)
            else:  # unselect
                existing = current.values.get(key, [])
                current.values[key] = [v for v in existing if v not in values]
        elif command in ('delete', 'purge', 'rename', 'move', 'clone'):
            _table_command(current, kind, command, args, warnings, line_no)
        elif command in ('show', 'get', 'execute', 'diagnose', 'diag'):
            continue  # captured CLI commands around the output
        else:
            warnings.append(f'line {line_no}: unknown command "{tokens[0]}"')

    if len(stack) > 1:
        open_path = ' > '.join(p for _, k, p in stack[1:])
        warnings.append(f'file ends inside "{open_path}": it may be truncated')

    if commands == 0 or (not root.tables and not header):
        raise ParseError('This does not look like a FortiGate configuration (no "config" blocks found).')

    if len(warnings) > MAX_WARNINGS:
        extra = len(warnings) - MAX_WARNINGS
        warnings = warnings[:MAX_WARNINGS] + [f'... and {extra} more warnings']

    return ParseResult(
        root=root, header=header, warnings=warnings,
        secrets_removed=secrets_removed, lines=next_line - 1,
    )


def _table_command(table, kind, command, args, warnings, line_no):
    if kind != 'table':
        warnings.append(f'line {line_no}: "{command}" outside a table')
        return
    entries = table.entries
    if command == 'purge':
        entries.clear()
    elif command == 'delete':
        for name in args:
            entries.pop(name, None)
    elif command == 'rename' and len(args) >= 3 and args[1] == 'to':
        old, new = args[0], args[2]
        if old in entries and new not in entries:
            table.entries = {
                (new if name == old else name): entry for name, entry in entries.items()
            }
            table.entries[new].name = new
    elif command == 'clone' and len(args) >= 3 and args[1] == 'to':
        import copy

        source = entries.get(args[0])
        if source is not None and args[2] not in entries:
            clone = copy.deepcopy(source)
            clone.name = args[2]
            entries[args[2]] = clone
    elif command == 'move' and len(args) >= 3 and args[1] in ('before', 'after'):
        name, where, other = args[0], args[1], args[2]
        if name in entries and other in entries and name != other:
            moved = entries[name]
            order = [n for n in entries if n != name]
            index = order.index(other) + (1 if where == 'after' else 0)
            order.insert(index, name)
            table.entries = {n: (moved if n == name else entries[n]) for n in order}
    else:
        warnings.append(f'line {line_no}: could not apply "{command} {" ".join(args)}"')
