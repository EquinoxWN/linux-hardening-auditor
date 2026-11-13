"""sshd, PAM and sudoers parsing follows the daemons' own rules."""

from __future__ import annotations

import random

import pytest
from helpers import FakeHost

from linux_hardening_auditor.hosts import CollectError
from linux_hardening_auditor.parsers import pam_lines, sshd_options, sudoers

CFG = "/etc/ssh/sshd_config"


def test_sshd_absent_config_is_none() -> None:
    assert sshd_options(FakeHost()) is None


def test_sshd_first_value_wins_and_keywords_are_case_insensitive() -> None:
    host = FakeHost({CFG: "permitrootlogin no\nPermitRootLogin yes\n"})
    opts = sshd_options(host)
    assert opts is not None
    assert opts["permitrootlogin"].value == "no"
    assert opts["permitrootlogin"].line == 1


def test_sshd_include_is_read_in_place_so_an_earlier_drop_in_wins() -> None:
    host = FakeHost(
        {
            CFG: "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin no\n",
            "/etc/ssh/sshd_config.d/50-cloud.conf": "PermitRootLogin yes\n",
        }
    )
    opts = sshd_options(host)
    assert opts is not None
    assert opts["permitrootlogin"].value == "yes"
    assert opts["permitrootlogin"].source.endswith("50-cloud.conf")


def test_sshd_include_after_the_setting_does_not_override_it() -> None:
    host = FakeHost(
        {
            CFG: "PermitRootLogin no\nInclude sshd_config.d/*.conf\n",
            "/etc/ssh/sshd_config.d/50-cloud.conf": "PermitRootLogin yes\n",
        }
    )
    opts = sshd_options(host)
    assert opts is not None
    assert opts["permitrootlogin"].value == "no"


def test_sshd_include_globs_expand_in_lexical_order() -> None:
    host = FakeHost(
        {
            CFG: "Include /etc/ssh/sshd_config.d/*.conf\n",
            "/etc/ssh/sshd_config.d/20-b.conf": "MaxAuthTries 5\n",
            "/etc/ssh/sshd_config.d/10-a.conf": "MaxAuthTries 2\n",
            "/etc/ssh/sshd_config.d/30-c.txt": "MaxAuthTries 9\n",
        }
    )
    opts = sshd_options(host)
    assert opts is not None
    assert opts["maxauthtries"].value == "2"


def test_sshd_match_block_options_are_not_global() -> None:
    host = FakeHost({CFG: "Match Group sftp\n  PasswordAuthentication yes\n"})
    assert sshd_options(host) == {}


def test_sshd_equals_syntax_quotes_and_comments() -> None:
    host = FakeHost({CFG: '# PermitRootLogin yes\n\nBanner="/etc/issue.net"\n'})
    opts = sshd_options(host)
    assert opts is not None
    assert "permitrootlogin" not in opts
    assert opts["banner"].value == "/etc/issue.net"


def test_sshd_include_loop_is_refused() -> None:
    host = FakeHost({CFG: "Include /etc/ssh/sshd_config\n"})
    with pytest.raises(CollectError, match="nested deeper"):
        sshd_options(host)


def test_sshd_wildcard_include_directories_are_refused() -> None:
    host = FakeHost({CFG: "Include /etc/*/x.conf\n"})
    with pytest.raises(CollectError, match="wildcards"):
        sshd_options(host)


@pytest.mark.parametrize("seed", range(5))
def test_sshd_first_occurrence_matches_a_naive_model(seed: int) -> None:
    rng = random.Random(seed)
    keys = ["PermitRootLogin", "MaxAuthTries", "X11Forwarding", "UsePAM"]
    lines = [(rng.choice(keys), str(rng.randint(0, 9))) for _ in range(40)]
    text = "\n".join(f"{k.upper() if rng.random() < 0.3 else k} {v}" for k, v in lines)
    opts = sshd_options(FakeHost({CFG: text}))
    assert opts is not None
    expected: dict[str, str] = {}
    for k, v in lines:
        expected.setdefault(k.lower(), v)
    assert {k: s.value for k, s in opts.items()} == expected


def test_pam_lines_parse_bracket_controls_and_optional_dash() -> None:
    text = (
        "auth [success=1 default=ignore] pam_unix.so nullok\n"
        "-session optional /lib/x86_64-linux-gnu/security/pam_systemd.so\n"
        "@include common-auth\n"
        "# auth required pam_deny.so\n"
    )
    lines = pam_lines(text, "/etc/pam.d/x")
    assert [(ln.type, ln.module, ln.args) for ln in lines] == [
        ("auth", "pam_unix.so", ("nullok",)),
        ("session", "pam_systemd.so", ()),
    ]
    assert lines[0].control == "[success=1 default=ignore]"
    assert lines[1].line == 2


@pytest.mark.parametrize("bad", ["auth required\n", "auth [success=1 pam_unix.so\n"])
def test_pam_malformed_lines_are_errors(bad: str) -> None:
    with pytest.raises(CollectError):
        pam_lines(bad, "/etc/pam.d/x")


def test_sudoers_absent_is_none() -> None:
    assert sudoers(FakeHost()) is None


def test_sudoers_includedir_skips_names_with_dots_or_tildes() -> None:
    host = FakeHost(
        {
            "/etc/sudoers": "#includedir /etc/sudoers.d\n",
            "/etc/sudoers.d/ops": "ops ALL=(ALL) ALL\n",
            "/etc/sudoers.d/old.bak": "x ALL=(ALL) NOPASSWD: ALL\n",
            "/etc/sudoers.d/ops~": "y ALL=(ALL) NOPASSWD: ALL\n",
        }
    )
    parsed = sudoers(host)
    assert parsed is not None
    assert parsed.files == ["/etc/sudoers", "/etc/sudoers.d/ops"]
    assert [r.text for r in parsed.rules] == ["ops ALL=(ALL) ALL"]


def test_sudoers_last_default_wins_and_negation_is_kept() -> None:
    host = FakeHost(
        {
            "/etc/sudoers": "Defaults use_pty\n@include /etc/sudoers.local\n",
            "/etc/sudoers.local": 'Defaults !use_pty, logfile="/var/log/sudo.log"\n',
        }
    )
    parsed = sudoers(host)
    assert parsed is not None
    assert parsed.defaults["use_pty"].value == "!"
    assert parsed.defaults["logfile"].value == "/var/log/sudo.log"


def test_sudoers_scoped_defaults_and_aliases_are_not_rules() -> None:
    host = FakeHost(
        {
            "/etc/sudoers": "Defaults:alice !use_pty\nCmnd_Alias X = /bin/ls\n"
            "alice ALL=(ALL) \\\n  NOPASSWD: X\n"
        }
    )
    parsed = sudoers(host)
    assert parsed is not None
    assert "use_pty" not in parsed.defaults
    assert len(parsed.rules) == 1
    assert "NOPASSWD" in parsed.rules[0].text
    assert parsed.rules[0].line == 3


def test_sudoers_missing_include_is_an_error() -> None:
    host = FakeHost({"/etc/sudoers": "@include /etc/sudoers.gone\n"})
    with pytest.raises(CollectError, match="not found"):
        sudoers(host)


def test_sudoers_defaults_split_respects_quotes_and_escapes() -> None:
    host = FakeHost(
        {
            "/etc/sudoers": 'Defaults env_keep="LANG, LC_ALL", use_pty\n'
            "Defaults badpass_message=wrong\\, try again, logfile=/var/log/sudo.log\n"
        }
    )
    parsed = sudoers(host)
    assert parsed is not None
    assert parsed.defaults["env_keep"].value == "LANG, LC_ALL"
    assert parsed.defaults["use_pty"].value == "on"
    assert parsed.defaults["badpass_message"].value == "wrong, try again"
    assert parsed.defaults["logfile"].value == "/var/log/sudo.log"
    assert " LC_ALL" not in parsed.defaults
    assert " try again" not in parsed.defaults


def test_sudoers_unterminated_quote_is_an_error() -> None:
    host = FakeHost({"/etc/sudoers": 'Defaults env_keep="LANG, use_pty\n'})
    with pytest.raises(CollectError, match="unterminated"):
        sudoers(host)


def test_sudoers_relative_include_resolves_against_the_including_file() -> None:
    host = FakeHost(
        {
            "/etc/sudoers": "@include sudoers.d/main\n",
            "/etc/sudoers.d/main": "@include extra\n#includedir conf\n",
            "/etc/sudoers.d/extra": "Defaults use_pty\n",
            "/etc/sudoers.d/conf/ops": "ops ALL=(ALL) ALL\n",
            "/etc/extra": "Defaults !use_pty\n",
        }
    )
    parsed = sudoers(host)
    assert parsed is not None
    assert parsed.files == [
        "/etc/sudoers",
        "/etc/sudoers.d/main",
        "/etc/sudoers.d/extra",
        "/etc/sudoers.d/conf/ops",
    ]
    assert parsed.defaults["use_pty"].value == "on"


def test_sudoers_host_name_escape_is_an_error_and_double_percent_is_literal() -> None:
    host = FakeHost({"/etc/sudoers": "@include /etc/sudoers.d/%h\n"})
    with pytest.raises(CollectError, match=r"%h \(host name\) in include path is not supported"):
        sudoers(host)
    literal = FakeHost(
        {"/etc/sudoers": "@include /etc/sudoers.d/a%%h\n", "/etc/sudoers.d/a%h": "x ALL=ALL\n"}
    )
    with pytest.raises(CollectError, match=r"invalid|safe characters"):
        sudoers(literal)  # '%' is outside the accepted path characters, reported, not mis-read
