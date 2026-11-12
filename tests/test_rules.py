"""YAML rules are loaded strictly and the bundled set is complete."""

from __future__ import annotations

from pathlib import Path

import pytest

from linux_hardening_auditor.checks import SshdOption
from linux_hardening_auditor.rules import RuleError, load_rules, parse_rule_file

GOOD = """
rules:
  - id: TST-001
    title: Root cannot log in
    severity: high
    rationale: Because.
    fix: Set it.
    check: {kind: sshd_option, option: PermitRootLogin, expect: {equals: "no"}}
"""


def test_bundled_rules_load_and_cover_every_area() -> None:
    rules = load_rules()
    assert len(rules) == 29
    prefixes = {r.id.split("-")[0] for r in rules}
    assert prefixes == {"SSH", "SUDO", "PAM", "KERN", "PERM", "SVC"}
    assert [r.id for r in rules] == sorted(r.id for r in rules)
    for r in rules:
        assert r.title
        assert r.rationale
        assert r.fix
        assert r.severity in {"low", "medium", "high", "critical"}


def test_a_valid_rule_parses() -> None:
    (rule,) = parse_rule_file(GOOD, "t.yaml")
    assert rule.id == "TST-001"
    assert isinstance(rule.check, SshdOption)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("", "mapping with one key"),
        ("rules: []", "empty"),
        ("rules: {}", "mapping with one key"),
        ("other: 1\nrules: []", "mapping with one key"),
        ("rules: [1]", "must be a mapping"),
        (GOOD.replace("TST-001", "tst-1"), "id must look like"),
        (GOOD.replace("severity: high", "severity: urgent"), "severity"),
        (GOOD.replace("    fix: Set it.\n", ""), "missing \\['fix'\\]"),
        (GOOD.replace("fix: Set it.", "fix: Set it.\n    owner: me"), "unknown \\['owner'\\]"),
        (GOOD.replace("fix: Set it.", "fix: ''"), "fix must be a non-empty"),
        (GOOD.replace("sshd_option", "shell"), "unknown check kind"),
        ("rules: [!!python/object/apply:os.system [id]]", "not valid YAML"),
        ("rules: [", "not valid YAML"),
    ],
)
def test_invalid_rule_files_are_rejected_with_a_reason(text: str, message: str) -> None:
    with pytest.raises(RuleError, match=message):
        parse_rule_file(text, "t.yaml")


def test_overlong_text_is_rejected() -> None:
    with pytest.raises(RuleError, match="longer than"):
        parse_rule_file(GOOD.replace("Because.", "x" * 2001), "t.yaml")


def test_duplicate_ids_across_files_are_rejected(tmp_path: Path) -> None:
    (tmp_path / "a.yaml").write_text(GOOD, encoding="utf-8")
    (tmp_path / "b.yaml").write_text(GOOD, encoding="utf-8")
    with pytest.raises(RuleError, match="duplicate rule id TST-001"):
        load_rules(tmp_path)


def test_rule_directory_errors(tmp_path: Path) -> None:
    with pytest.raises(RuleError, match="not found"):
        load_rules(tmp_path / "missing")
    with pytest.raises(RuleError, match=r"no \*\.yaml"):
        load_rules(tmp_path)
    (tmp_path / "big.yaml").write_text("#" * (256 * 1024 + 1), encoding="utf-8")
    with pytest.raises(RuleError, match="larger than"):
        load_rules(tmp_path)
