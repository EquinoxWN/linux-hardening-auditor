"""Command line: `lha audit` and `lha rules`."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from .audit import format_text, run_audit, write_json
from .hosts import CollectError, Host, SshHost, TreeHost
from .rules import Rule, RuleError, load_rules


def _parser() -> argparse.ArgumentParser:
    """Argument parser for both subcommands."""
    p = argparse.ArgumentParser(prog="lha", description="Audit Linux hardening controls.")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("audit", help="run the rules against one host")
    src = a.add_mutually_exclusive_group(required=True)
    src.add_argument("--fixture", type=Path, help="a directory standing in for / (with .lha-meta/)")
    src.add_argument("--local", action="store_true", help="the Linux host this runs on")
    src.add_argument("--ssh", metavar="[USER@]HOST", help="a remote host via the ssh client")
    a.add_argument("--port", type=int, default=22, help="ssh port (default 22)")
    a.add_argument("--timeout", type=float, default=15.0, help="seconds per ssh call (default 15)")
    a.add_argument("--retries", type=int, default=2, help="ssh retries on failure (default 2)")
    a.add_argument("--rules", type=Path, help="rule directory (default: bundled rules)")
    a.add_argument("--only", help="comma-separated rule ids to run")
    a.add_argument("--json", type=Path, help="also write the report as JSON to this file")

    r = sub.add_parser("rules", help="list or validate rules")
    r.add_argument("action", choices=["list", "validate"])
    r.add_argument("--rules", type=Path, help="rule directory (default: bundled rules)")
    return p


def _select(rules: list[Rule], only: str | None) -> list[Rule]:
    """Keep the requested ids, refusing unknown ones."""
    if only is None:
        return rules
    wanted = {i.strip() for i in only.split(",") if i.strip()}
    unknown = wanted - {r.id for r in rules}
    if not wanted or unknown:
        raise RuleError(f"unknown rule id(s) in --only: {', '.join(sorted(unknown)) or only!r}")
    return [r for r in rules if r.id in wanted]


def _host(args: argparse.Namespace) -> Host:
    """Build the host the arguments name."""
    if args.fixture is not None:
        return TreeHost.fixture(args.fixture)
    if args.local:
        return TreeHost.local()
    return SshHost(args.ssh, port=args.port, timeout=args.timeout, retries=args.retries)


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point; exit 0 clear, 1 failed controls, 2 bad input, 3 unreadable host."""
    args = _parser().parse_args(argv)
    try:
        rules = load_rules(args.rules)
        if args.command == "rules":
            if args.action == "list":
                for rule in rules:
                    print(f"{rule.id:<9} {rule.severity:<8} {rule.title}")
            print(f"{len(rules)} rules valid")
            return 0
        rules = _select(rules, args.only)
        host = _host(args)
    except (RuleError, CollectError) as exc:
        print(f"lha: error: {exc}", file=sys.stderr)
        return 2
    report = run_audit(host, rules)
    print(format_text(report))
    if args.json is not None:
        try:
            write_json(report, args.json)
        except OSError as exc:
            print(f"lha: error: cannot write {args.json}: {exc}", file=sys.stderr)
            return 2
    return report.exit_code()


if __name__ == "__main__":
    raise SystemExit(main())
