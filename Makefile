.PHONY: setup lint test demo bench audit ci

PY ?= python

setup:
	$(PY) -m pip install --upgrade pip && $(PY) -m pip install -e ".[dev]"

# ruff, ruff format and mypy --strict.
lint:
	$(PY) -m ruff check . && $(PY) -m ruff format --check . && $(PY) -m mypy

# Unit, parser, host and end-to-end tests on the shipped fixture trees (the live test is CI-only).
test:
	$(PY) -m pytest -q -rs

# Audit the three fixture hosts (exit 1 means failed controls, which weak and rocky have).
demo:
	-lha audit --fixture tests/fixtures/hosts/hardened
	-lha audit --fixture tests/fixtures/hosts/weak
	-lha audit --fixture tests/fixtures/hosts/rocky

bench:
	@echo "M3: before/after scores on Vagrant lab VMs and agreement with Lynis"

# Known vulnerabilities in the installed Python dependencies.
audit:
	$(PY) -m pip_audit --skip-editable --cache-dir .tmp/pip-audit

ci: setup lint test
