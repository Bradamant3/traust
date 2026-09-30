# Contributing

## Setup

```bash
git clone https://github.com/traust-security/traust.git && cd traust
make sync      # install dependencies (uv)
make hooks     # enable the repository's git hooks for this clone
make install   # create TRAUST_CONFIG_HOME from the shipped templates
```

`make doctor` verifies the configuration and scanner toolchain; `make setup`
installs the toolchain for a profile. See [docs/setup.md](docs/setup.md) for
the full reference.

## Commit messages

Use conventional-commit style: `type(scope): subject`

Types: `feat`, `fix`, `perf`, `refactor`, `docs`, `test`, `chore`, `ci`, `build`, `style`, `revert`

```
feat(threat-model): add pr mode
fix(triage): handle empty scanner output
build!: drop Python 3.11 support        ← breaking change
```

## Hooks

| Hook | Runs | Blocks |
|------|------|--------|
| `pre-commit` | `python3 -m traust.cli check skill-alignment` and `check skill-security` | a cross-skill contract or security-posture regression |
| `pre-push` | `python3 -m traust.cli check docs-consistency` and `check content-licenses` | docs drifted from the tree, or re-imported restrictively licensed content |

Both fail closed: a missing checker blocks too. Bypass once, in an emergency,
with `--no-verify`.

## Adding or changing a skill

Run the three checks the hooks enforce before opening a pull request, plus the
docs check if you touched Markdown, scripts or schemas:

```bash
python3 -m traust.cli check skill-alignment
python3 -m traust.cli check skill-security
python3 -m traust.cli check content-licenses
python3 -m traust.cli check docs-consistency
```

## Releasing

If your pull request has `feat:`, `fix:`, `perf:` or `!` (breaking) commits:

```bash
make bump patch|minor|major     # VERSION, pyproject.toml and version.args together
python3 release.py check
git add VERSION pyproject.toml version.args
git commit -m "chore: release X.Y.Z"
```

`VERSION`, `pyproject.toml` and `version.args` must agree; the docs-consistency
check fails when they drift. Tags follow `vX.Y.Z`.

## Running tests

```bash
make test              # unit tests, parallel via pytest-xdist
uv run pytest -q       # full suite (integration tests need the scanner toolchain)
```

pytest is the only runner; `unittest discover` silently skips part of the suite.

### Ledger auth in tests

traust-ledger (>=0.7) verifies a signed identity token on every write: `sign`,
`create`, `patch_metadata`, `stamp_event_identities`. The suite sets up a real
**local** identity for itself, so no OIDC provider and no manual step is
needed. `tests/conftest.py`, at import time:

| Step | Setting |
|------|---------|
| Isolates ledger config | `HOME=<tmp>/ledger-home`, so the ledger reads `<tmp>/ledger-home/.config/traust-ledger/` and never your `~/.config/traust-ledger` |
| Clears inherited credentials | unsets `LAAS_TOKEN`, `LEDGER_TOKEN`, `LEDGER_TOKEN_PATH`, `LEDGER_LOCAL_MACHINE` |
| Sets the test identity | `LEDGER_LOCAL_IDENTITY=test@traust.local` (human) |
| Proves it works | calls `resolve_auth()` and aborts the run with a usage error unless the source is `auto-mint` |

Every `LedgerClient()` / `LedgerService()` built without a token then
auto-mints an ES256 JWT (`iss=local`) and verifies it against the generated
`local-jwks.json`. Tests exercise the real verification path; nothing is
stubbed.

When writing tests:

- Do not pass `token="..."` strings. The ledger refuses any token that is not a
  local-issuer JWT when no OIDC provider is configured ("token is not a
  local-issuer JWT and no OIDC provider is configured").
- For a **machine** actor, mint one explicitly:
  ```python
  from traust_ledger.auth.local import ensure_local_keypair, mint_local_token
  from traust_ledger.cli.identity.config import config_dir

  tok = mint_local_token("triage/1.0", ensure_local_keypair(config_dir()), machine=True)
  LedgerClient(token=tok, data_dir=td)
  ```
- Subprocess tests that set their own `HOME` must also set
  `LEDGER_LOCAL_IDENTITY` (see `tests/test_countersign_identity.py`).
- Countersign refuses local-issuer tokens unless
  `HARNESS_COUNTERSIGN_ALLOW_LOCAL=1`; that refusal is intended.
- The ledger validates the complete layer against its schema before it signs.
  To test a harness rule against an invalid layer, sign a valid one and then
  mutate the result (see `test_severity_override_requires_rationale`).

To reproduce the same setup outside pytest, for example when running a CLI
by hand against a scratch ledger:

```bash
export HOME=$(mktemp -d)                 # keep your real ledger config out of it
unset LAAS_TOKEN LEDGER_TOKEN LEDGER_TOKEN_PATH
export LEDGER_LOCAL_IDENTITY=you@example.com
# or, to store a credential instead of auto-minting:
uv run ledger auth local --identity you@example.com
```

## Architecture

See [README.md](README.md) for the skill catalogue and pipeline stages, and
[AGENTS.md](AGENTS.md) for the conventions every skill follows.
