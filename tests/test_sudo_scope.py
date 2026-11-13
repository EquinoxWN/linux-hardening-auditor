"""Scoped Defaults are split like sudo does, so a hidden `!authenticate` is never missed."""

from __future__ import annotations

import pytest
from helpers import FakeHost

from linux_hardening_auditor.checks import Status, SudoersPolicy
from linux_hardening_auditor.parsers import split_scope, strip_comment, sudoers

POLICY = SudoersPolicy(("NOPASSWD",), (), ())


def _parsed(text: str) -> tuple[list[int], list[int]]:
    """Lines of parsed and fail-safe `!authenticate` hits."""
    result = sudoers(FakeHost({"/etc/sudoers": text}))
    assert result is not None
    return [s.line for s in result.scoped_no_auth], [s.line for s in result.unparsed_no_auth]


@pytest.mark.parametrize(
    ("rest", "binding", "body"),
    [
        ("alice !authenticate", "alice", "!authenticate"),
        ("alice, bob !authenticate", "alice, bob", "!authenticate"),
        (
            "alice ,bob , carol  !authenticate, use_pty",
            "alice ,bob , carol",
            "!authenticate, use_pty",
        ),
        ("/usr/bin/apt\\ update !authenticate", "/usr/bin/apt\\ update", "!authenticate"),
        ('"/usr/bin/apt update" !authenticate', '"/usr/bin/apt update"', "!authenticate"),
        ("alice", "alice", ""),
    ],
)
def test_split_scope_follows_the_binding_list_grammar(rest: str, binding: str, body: str) -> None:
    assert split_scope(rest) == (binding, body)


def test_split_scope_rejects_an_unterminated_quote() -> None:
    from linux_hardening_auditor.hosts import CollectError

    with pytest.raises(CollectError, match="unterminated"):
        split_scope('"/usr/bin/apt !authenticate')


@pytest.mark.parametrize(
    ("line", "kept"),
    [
        ("Defaults use_pty # keep it", "Defaults use_pty"),
        ('Defaults badpass_message="try # again"', 'Defaults badpass_message="try # again"'),
        ("Defaults lecture_file=/etc/a\\ #b", "Defaults lecture_file=/etc/a\\ #b"),
        ("Defaults:#1000 !authenticate", "Defaults:#1000 !authenticate"),
        ("alice ALL=(ALL) ALL #note", "alice ALL=(ALL) ALL"),
        ("alice ALL=(root, #-1) NOPASSWD: ALL", "alice ALL=(root, #-1) NOPASSWD: ALL"),
        ("alice ALL=(root, #1000) ALL", "alice ALL=(root, #1000) ALL"),
        ("alice ALL=(ALL) ALL # -1 is not a uid here", "alice ALL=(ALL) ALL"),
    ],
)
def test_strip_comment(line: str, kept: str) -> None:
    assert strip_comment(line) == kept


@pytest.mark.parametrize(
    "text",
    [
        "alice ALL=(root, #-1) NOPASSWD: ALL\n",
        "#1000 ALL=(ALL) NOPASSWD: ALL\n",
        "#-1 ALL=(ALL) NOPASSWD:ALL\n",
    ],
)
def test_uid_hash_is_not_a_comment_so_nopasswd_is_found(text: str) -> None:
    result = sudoers(FakeHost({"/etc/sudoers": text}))
    assert result is not None
    assert len(result.rules) == 1
    assert "NOPASSWD" in result.rules[0].text
    out = POLICY.evaluate(FakeHost({"/etc/sudoers": text}))
    assert out.status is Status.FAIL
    assert "NOPASSWD at /etc/sudoers:1" in out.evidence


def test_a_real_comment_line_is_still_a_comment() -> None:
    text = "# alice ALL=(ALL) NOPASSWD: ALL\n#includedir-like note\n"
    result = sudoers(FakeHost({"/etc/sudoers": text}))
    assert result is not None
    assert result.rules == []
    assert POLICY.evaluate(FakeHost({"/etc/sudoers": text})).status is Status.PASS


def test_rule_fail_safe_checks_the_text_before_comment_stripping() -> None:
    text = "alice ALL=(ALL) ALL # NOPASSWD: ALL\n"
    result = sudoers(FakeHost({"/etc/sudoers": text}))
    assert result is not None
    assert "NOPASSWD" not in result.rules[0].text
    assert "NOPASSWD" in result.rules[0].raw
    assert POLICY.evaluate(FakeHost({"/etc/sudoers": text})).status is Status.FAIL


@pytest.mark.parametrize(
    "text",
    [
        "Defaults:alice, bob !authenticate\n",
        "Defaults:alice ,bob !authenticate\n",
        "Defaults!/usr/bin/apt\\ update !authenticate\n",
        'Defaults!"/usr/bin/apt update" !authenticate\n',
        'Defaults:alice !authenticate # owner bob, "temporary\n',
    ],
)
def test_scoped_not_authenticate_is_parsed_and_fails_sudo_001(text: str) -> None:
    assert _parsed(text) == ([1], [])
    out = POLICY.evaluate(FakeHost({"/etc/sudoers": text}))
    assert out.status is Status.FAIL
    assert "Defaults !authenticate at /etc/sudoers:1" in out.evidence


def test_trailing_comment_does_not_break_global_defaults() -> None:
    result = sudoers(FakeHost({"/etc/sudoers": 'Defaults use_pty # see "the wiki\n'}))
    assert result is not None
    assert result.defaults["use_pty"].value == "on"


def test_fail_safe_flags_a_token_the_parser_did_not_read_as_an_entry() -> None:
    text = "Defaults:alice,!authenticate\n"  # no whitespace: parsed as part of the binding
    assert _parsed(text) == ([], [1])
    out = POLICY.evaluate(FakeHost({"/etc/sudoers": text}))
    assert out.status is Status.FAIL
    assert "not parsed as an entry" in out.evidence


def test_fail_safe_does_not_undo_a_global_re_enable() -> None:
    text = "Defaults !authenticate\nDefaults authenticate\n"
    assert _parsed(text) == ([], [])
    assert POLICY.evaluate(FakeHost({"/etc/sudoers": text})).status is Status.PASS
