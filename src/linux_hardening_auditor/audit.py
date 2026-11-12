"""Run rules against a host and write the findings."""

from __future__ import annotations

import json
import os
import tempfile
import time
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .checks import Outcome, Status
from .hosts import CollectError, Host
from .rules import Rule


@dataclass(frozen=True)
class Finding:
    """One rule's outcome on one host."""

    rule: Rule
    outcome: Outcome


def evaluate(rule: Rule, host: Host) -> Finding:
    """Run one rule; a collection failure becomes an ERROR finding with its message."""
    try:
        outcome = rule.check.evaluate(host)
    except CollectError as exc:
        outcome = Outcome(Status.ERROR, str(exc))
    return Finding(rule, outcome)


@dataclass(frozen=True)
class Report:
    """All findings for one host."""

    host: str
    started_at: str
    duration_ms: float
    findings: tuple[Finding, ...]

    def counts(self) -> dict[str, int]:
        """Findings per status, every status present."""
        c = Counter(f.outcome.status for f in self.findings)
        return {s.value: c.get(s, 0) for s in Status}

    def exit_code(self) -> int:
        """0 all clear, 1 a control failed, 3 something could not be read."""
        counts = self.counts()
        if counts[Status.ERROR.value]:
            return 3
        return 1 if counts[Status.FAIL.value] else 0

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready form."""
        return {
            "tool": "linux-hardening-auditor",
            "version": __version__,
            "host": self.host,
            "started_at": self.started_at,
            "duration_ms": round(self.duration_ms, 3),
            "summary": self.counts(),
            "findings": [
                {
                    "id": f.rule.id,
                    "title": f.rule.title,
                    "severity": f.rule.severity,
                    "status": f.outcome.status.value,
                    "evidence": f.outcome.evidence,
                    "rationale": f.rule.rationale,
                    "fix": f.rule.fix,
                }
                for f in self.findings
            ],
        }


def run_audit(host: Host, rules: list[Rule]) -> Report:
    """Evaluate every rule in id order; timing uses the monotonic clock, the stamp is UTC."""
    if not rules:
        raise ValueError("no rules to run")
    started = datetime.now(UTC).isoformat(timespec="seconds")
    t0 = time.perf_counter()
    findings = tuple(evaluate(r, host) for r in sorted(rules, key=lambda r: r.id))
    return Report(host.name, started, (time.perf_counter() - t0) * 1000, findings)


def write_json(report: Report, path: Path) -> None:
    """Write the report atomically: a temp file in the same folder, then rename."""
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(report.to_dict(), indent=2, sort_keys=False) + "\n"
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


_ORDER = {Status.ERROR: 0, Status.FAIL: 1, Status.NOT_APPLICABLE: 2, Status.PASS: 3}


def format_text(report: Report) -> str:
    """Plain-text table: errors and failures first, then a summary line."""
    lines = [f"host: {report.host}"]
    for f in sorted(report.findings, key=lambda f: (_ORDER[f.outcome.status], f.rule.id)):
        status = f.outcome.status.value.upper().replace("NOT_APPLICABLE", "N/A")
        lines.append(f"{status:<5} {f.rule.severity:<8} {f.rule.id:<9} {f.rule.title}")
        lines.append(f"{'':<24}{f.outcome.evidence}")
    c = report.counts()
    lines.append(
        f"{len(report.findings)} rules: {c['pass']} pass, {c['fail']} fail, "
        f"{c['not_applicable']} not applicable, {c['error']} error"
    )
    return "\n".join(lines)
