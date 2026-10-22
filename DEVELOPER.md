# Developer guide

How the importer works and why, for anyone changing it.

## Pipeline

1. **Bytes to text** (`parser/files.py`): plain, gzip or encrypted
   (`#FGBK|` header, AES-256-GCM, key = SHA-256 of the password, gzip
   inside). In memory only.
2. **Text to tree** (`parser/cli.py`): a shell-like tokenizer (quoted and
   bare parts join, backslash escapes, multi-line quoted values) and a
   stack machine for `config` / `edit` / `set` / `next` / `end`, plus the
   script commands `rename`, `move`, `clone`, `delete`, `purge`, `append`,
   `select`, `unselect`. A stray quote is closed at the end of its line when
   the next line is a CLI command, so one typo can't swallow the file.
3. **Secrets out** (`parser/secrets.py`): checked for every `set` while
   parsing; flagged values never enter the tree. Only a count is kept.
4. **Layout** (`parser/layout.py`): header facts (model, firmware, VDOM
   mode, serial from the default `alias`) and the global / per-VDOM split.
5. **Extract** (`extract/`): the importer's own JSON document, the only
   thing saved (`ImportRun.data`).

## Optional plugins

`integrations/__init__.py` decides what is installed. Code that imports
another plugin lives in modules that are only imported when it is.
