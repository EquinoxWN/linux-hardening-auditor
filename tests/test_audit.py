"""End to end on the shipped fixture trees, the JSON report and the CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from helpers import FIXTURES, FakeHost

from linux_hardening_auditor.audit import evaluate, format_text, run_audit, write_json
from linux_hardening_auditor.checks import Status
from linux_hardening_auditor.cli import main
from linux_hardening_auditor.hosts import TreeHost
from linux_hardening_auditor.rules import load_rules

RULES = load_rules()

WEAK_FAILS = {
    "SSH-001", "SSH-002", "SSH-003", "SSH-004", "SSH-005",
    "SUDO-001", "SUDO-002", "SUDO-003",
    "PAM-001", "PAM-002", "PAM-003",
    "KERN-001", "KERN-002", "KERN-003", "KERN-005", "KERN-006",
    "PERM-001", "PERM-003", "PERM-006",
    "SVC-001", "SVC-003",
}  # fmt: skip
ROCKY_FAILS = {"SSH-004", "PAM-001", "KERN-001", "PERM-006"}


def _by_status(name: str) -> dict[Status, set[str]]:
    report = run_audit(TreeHost.fixture(FIXTURES / name), RULES)
    out: dict[Status, set[str]] = {s: set() for s in Status}
    for f in report.findings:
        out[f.outcome.status].add(f.rule.id)
    return out


def test_hardened_fixture_passes_every_rule() -> None:
    got = _by_status("hardened")
    assert got[Status.PASS] == {r.id for r in RULES}


def test_weak_fixture_fails_exactly_the_planted_weaknesses() -> None:
    got = _by_status("weak")
    assert got[Status.FAIL] == WEAK_FAILS
    assert got[Status.NOT_APPLICABLE] == {"PERM-005"}
    assert got[Status.ERROR] == set()


def test_rocky_fixture_layout_and_traps() -> None:
    got = _by_status("rocky")
    assert got[Status.FAIL] == ROCKY_FAILS
    assert got[Status.ERROR] == set()


def test_weak_fixture_evidence_names_the_drop_in_that_wins() -> None:
    report = run_audit(TreeHost.fixture(FIXTURES / "weak"), RULES)
    ssh1 = next(f for f in report.findings if f.rule.id == "SSH-001")
    assert "50-cloud-init.conf:1" in ssh1.outcome.evidence


def test_collection_errors_become_error_findings_not_crashes() -> None:
    host = FakeHost(broken=frozenset({"/etc/ssh/sshd_config"}))
    finding = evaluate(next(r for r in RULES if r.id == "SSH-001"), host)
    assert finding.outcome.status is Status.ERROR
    assert "permission denied" in finding.outcome.evidence


def test_report_counts_exit_codes_and_text() -> None:
    clean = run_audit(TreeHost.fixture(FIXTURES / "hardened"), RULES)
    assert clean.exit_code() == 0
    assert clean.counts() == {"pass": 29, "fail": 0, "not_applicable": 0, "error": 0}
    weak = run_audit(TreeHost.fixture(FIXTURES / "weak"), RULES)
    assert weak.exit_code() == 1
    text = format_text(weak)
    assert text.splitlines()[-1] == "29 rules: 7 pass, 21 fail, 1 not applicable, 0 error"
    assert text.index("FAIL") < text.index("PASS")
    broken = run_audit(FakeHost(broken=frozenset({"/etc/sudoers"})), RULES)
    assert broken.exit_code() == 3
    assert broken.started_at.endswith("+00:00")


def test_run_audit_needs_rules() -> None:
    with pytest.raises(ValueError, match="no rules"):
        run_audit(FakeHost(), [])


def test_json_report_is_written_atomically_and_rewrites_cleanly(tmp_path: Path) -> None:
    report = run_audit(TreeHost.fixture(FIXTURES / "weak"), RULES)
    out = tmp_path / "sub" / "report.json"
    write_json(report, out)
    first = out.read_text(encoding="utf-8")
    write_json(report, out)
    assert out.read_text(encoding="utf-8") == first
    assert sorted(p.name for p in out.parent.iterdir()) == ["report.json"]
    data = json.loads(first)
    assert data["summary"]["fail"] == 21
    assert {f["id"] for f in data["findings"] if f["status"] == "fail"} == WEAK_FAILS
    assert all(f["fix"] and f["rationale"] for f in data["findings"])


def test_cli_audit_exit_codes_and_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["audit", "--fixture", str(FIXTURES / "hardened")]) == 0
    out = tmp_path / "r.json"
    code = main(
        [
            "audit",
            "--fixture",
            str(FIXTURES / "weak"),
            "--only",
            "SSH-001,SVC-002",
            "--json",
            str(out),
        ]
    )
    assert code == 1
    assert [f["id"] for f in json.loads(out.read_text(encoding="utf-8"))["findings"]] == [
        "SSH-001",
        "SVC-002",
    ]
    assert "2 rules: 1 pass, 1 fail" in capsys.readouterr().out


@pytest.mark.parametrize(
    "argv",
    [
        ["audit", "--fixture", "does-not-exist"],
        ["audit", "--fixture", str(FIXTURES / "weak"), "--only", "NOPE-001"],
        ["audit", "--fixture", str(FIXTURES / "weak"), "--only", ","],
        ["audit", "--ssh=-oProxyCommand=calc"],
        ["audit", "--ssh", "host", "--port", "70000"],
        ["rules", "list", "--rules", "does-not-exist"],
    ],
)
def test_cli_bad_input_exits_2(argv: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    assert main(argv) == 2
    assert "lha: error:" in capsys.readouterr().err


def test_cli_rules_list_and_validate(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["rules", "validate"]) == 0
    assert capsys.readouterr().out.strip() == "29 rules valid"
    assert main(["rules", "list"]) == 0
    assert "SSH-001" in capsys.readouterr().out


def test_cli_needs_exactly_one_source() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["audit", "--fixture", "a", "--local"])
    assert exc.value.code == 2
