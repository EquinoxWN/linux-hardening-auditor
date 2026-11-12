"""Loading and validating YAML rules: one control per rule, with check, severity, rationale and fix."""

from __future__ import annotations

import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from .checks import Check, SpecError, parse_check

SEVERITIES = ("low", "medium", "high", "critical")
RULE_KEYS = {"id", "title", "severity", "rationale", "fix", "check"}
MAX_RULE_FILE_BYTES = 256 * 1024
MAX_TEXT = 2000
_ID = re.compile(r"^[A-Z]{2,6}-\d{3}$")


class RuleError(ValueError):
    """A rule file or rule is invalid."""


@dataclass(frozen=True)
class Rule:
    """One control."""

    id: str
    title: str
    severity: str
    rationale: str
    fix: str
    check: Check
    source: str


def _text(raw: dict[str, Any], key: str, where: str) -> str:
    """A required, bounded, non-empty text field."""
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise RuleError(f"{where}: {key} must be a non-empty string")
    if len(value) > MAX_TEXT:
        raise RuleError(f"{where}: {key} is longer than {MAX_TEXT} characters")
    return " ".join(value.split())


def parse_rule(raw: Any, source: str) -> Rule:
    """Validate one rule mapping."""
    if not isinstance(raw, dict):
        raise RuleError(f"{source}: each rule must be a mapping")
    rid = raw.get("id")
    where = f"{source}: rule {rid!r}"
    if not isinstance(rid, str) or not _ID.fullmatch(rid):
        raise RuleError(f"{where}: id must look like ABC-001")
    keys = set(raw)
    if keys != RULE_KEYS:
        missing, unknown = sorted(RULE_KEYS - keys), sorted(keys - RULE_KEYS)
        raise RuleError(f"{where}: missing {missing or 'nothing'}, unknown {unknown or 'nothing'}")
    severity = raw["severity"]
    if severity not in SEVERITIES:
        raise RuleError(f"{where}: severity must be one of {', '.join(SEVERITIES)}")
    try:
        check = parse_check(raw["check"])
    except SpecError as exc:
        raise RuleError(f"{where}: check: {exc}") from exc
    return Rule(
        rid,
        _text(raw, "title", where),
        severity,
        _text(raw, "rationale", where),
        _text(raw, "fix", where),
        check,
        source,
    )


def parse_rule_file(text: str, source: str) -> list[Rule]:
    """Parse a YAML document of the form `rules: [...]` with the safe loader."""
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise RuleError(f"{source}: not valid YAML: {exc}") from exc
    if not isinstance(doc, dict) or set(doc) != {"rules"} or not isinstance(doc["rules"], list):
        raise RuleError(f"{source}: the document must be a mapping with one key, rules: [...]")
    if not doc["rules"]:
        raise RuleError(f"{source}: rules is empty")
    return [parse_rule(item, source) for item in doc["rules"]]


def _check_unique(rules: list[Rule]) -> list[Rule]:
    """Reject duplicate ids and return the rules sorted by id."""
    seen: dict[str, str] = {}
    for rule in rules:
        if rule.id in seen:
            raise RuleError(f"duplicate rule id {rule.id} in {seen[rule.id]} and {rule.source}")
        seen[rule.id] = rule.source
    return sorted(rules, key=lambda r: r.id)


def load_rules(directory: Path | None = None) -> list[Rule]:
    """Load every *.yaml in a directory, or the bundled rules when none is given."""
    if directory is None:
        base = resources.files("linux_hardening_auditor") / "rules"
        items = sorted(
            (e for e in base.iterdir() if e.name.endswith(".yaml")), key=lambda e: e.name
        )
        texts = [(e.name, e.read_text(encoding="utf-8")) for e in items]
    else:
        if not directory.is_dir():
            raise RuleError(f"rules directory not found: {directory}")
        texts = []
        for path in sorted(directory.glob("*.yaml")):
            if path.stat().st_size > MAX_RULE_FILE_BYTES:
                raise RuleError(f"{path.name}: larger than {MAX_RULE_FILE_BYTES} bytes")
            texts.append((path.name, path.read_text(encoding="utf-8")))
    if not texts:
        raise RuleError(f"no *.yaml rule files in {directory or 'the bundled rules'}")
    rules: list[Rule] = []
    for name, text in texts:
        rules.extend(parse_rule_file(text, name))
    return _check_unique(rules)
