# Contributing

Thanks for helping. This is a Python project; issues and pull requests are welcome.

## Set up and check your change

Needs Python 3.11+. Caches and virtual environments stay in git-ignored folders inside the repo.

```bash
make setup   # install dependencies
make lint    # ruff, ruff format, mypy --strict
make test    # full test suite (the live test runs in CI)
make audit   # known-vulnerability check (as in CI)
make demo    # audit the three fixture hosts
```

A pull request is ready when `make lint` and `make test` pass and CI is green.

## Adding or changing a rule

- Rules live in `src/linux_hardening_auditor/rules/*.yaml`; run `lha rules validate` after editing.
- Use an existing check kind where possible. A new kind needs code in `checks.py`, tests for pass,
  fail, not-applicable and malformed specs, and an ADR if it reads a new kind of source.
- Update the fixture hosts in `tests/fixtures/hosts/` and the expected verdict sets in
  `tests/test_audit.py` so the new control is exercised end to end. Fixture files must stay
  inert: no real password hashes, keys or tokens.

## Guidelines

- Keep each change focused; explain the problem it solves in the pull request.
- Add or update a test for every behaviour change, and update `docs/results/` when numbers change.
- Significant design changes need an ADR in `docs/adr/` (copy `0001` for the format).
- Keep function comments to one short phrase; let names and tests explain the rest.
- Report security problems privately, as described in [SECURITY.md](SECURITY.md).

By contributing you agree that your work is released under the [MIT License](LICENSE).
