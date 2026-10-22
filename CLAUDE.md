# Working on this repo

NetBox plugin that imports FortiGate configurations: upload, plan, review,
dry run, apply, roll back. Follows the conventions of
mattivaisanen/netbox-change-approval and mattivaisanen/netbox-local-dateformat.

## Rules

- **Never store the configuration file.** Uploads are read in memory only
  (no temp file), parsed, stripped of secrets, and only the importer's
  extracted data (`ImportRun.data`) is saved. Never log, cache, attach to a
  job or write the file or its text anywhere. Secrets are dropped by the
  parser (`parser/secrets.py`) and must never reach the database.
- **No hard dependencies on other plugins.** netbox-security,
  netbox-routing and netbox-change-approval are optional: detect them with
  `integrations.has_*()` and import their code only inside functions or
  modules loaded when they are installed. The plugin must work flawlessly
  without any of them, and CI tests both ways.
- **Bookkeeping models are not NetBoxModel** (see models.py and
  DEVELOPER.md): approval plugins gate every NetBoxModel, and recording an
  import must not need approval.
- **Built-in NetBox first:** changelog (one request ID per apply), jobs,
  tags, VDCs, virtual chassis, VPN models, FHRP groups, config context,
  permissions. Writes go through `full_clean()` + `save()` like a form.
- **Robust imports:** applies are all-or-nothing by default, plans are
  re-checked for drift before applying, rollback refuses to overwrite
  later edits. Every change of behaviour gets a test.
- **Matti's NetBox:** Matti restarts it themselves. After pushing, pull
  into ~/projects/netbox-fortigate-importer on their machine and tell them
  it's ready to restart. Keep test runs minimal (token cost).
- **NetBox support:** only claim what CI tests. `min_version` is the oldest
  release in the CI matrix; keep README "Requirements" in sync.
- **Python:** `requires-python >= 3.10`; CI runs 3.12.
- **Packaging:** setuptools via `pyproject.toml`, no runtime dependencies.
  Keep `version` in `pyproject.toml` and `FortiGateImporterConfig.version`
  the same. Non-`.py` files must be listed in package-data.
- **Tests:** Django tests in `netbox_fortigate_importer/tests/`, run with
  `python manage.py test netbox_fortigate_importer` from a NetBox checkout.
  Never skip or weaken a test to get CI green. Tests that need an optional
  plugin use `skipUnless(installed)`.
- **Docs:** update in the same commit as the change: README.md,
  DEVELOPER.md, docs/configuration.md (every setting), CHANGELOG.md
  (`## Unreleased` on top, `New:` / `Fixed:` lists written for NetBox users).
- **Commits:** subject says what changes for the user, in plain words. Body
  explains the problem, then the fix, in plain language.
