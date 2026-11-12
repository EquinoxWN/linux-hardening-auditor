"""Read-only audit of the real host; selected with `-m live`, run as root by the Linux CI job."""

from __future__ import annotations

import sys

import pytest

from linux_hardening_auditor.audit import run_audit
from linux_hardening_auditor.checks import Status
from linux_hardening_auditor.hosts import TreeHost
from linux_hardening_auditor.rules import load_rules

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(not sys.platform.startswith("linux"), reason="audits a real Linux host"),
]


def test_local_linux_host_is_read_without_collection_errors() -> None:
    report = run_audit(TreeHost.local(), load_rules())
    statuses = {f.rule.id: f.outcome.status for f in report.findings}
    assert len(statuses) == 29
    assert statuses["KERN-002"] is not Status.NOT_APPLICABLE
    errors = [
        f"{f.rule.id}: {f.outcome.evidence}"
        for f in report.findings
        if f.outcome.status is Status.ERROR
    ]
    assert errors == []
