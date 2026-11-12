"""Each check kind passes, fails and reports not-applicable on the right inputs."""

from __future__ import annotations

from typing import Any

import pytest
from helpers import FakeHost

from linux_hardening_auditor.checks import (
    Expect,
    FileMode,
    PamModule,
    ServicesNotRunning,
    SpecError,
    SshdOption,
    Status,
    SudoersPolicy,
    Sysctl,
    parse_check,
)
from linux_hardening_auditor.hosts import FileStat

CFG = "/etc/ssh/sshd_config"


@pytest.mark.parametrize(
    ("raw", "actual", "ok"),
    [
        ({"equals": "no"}, "No", True),
        ({"equals": "no"}, "yes", False),
        ({"equals": 0}, "0", True),
        ({"one_of": ["1", 2]}, "2", True),
        ({"one_of": ["1", 2]}, "0", False),
        ({"max": 4}, "4", True),
        ({"max": 4}, "5", False),
        ({"min": 4}, "3", False),
        ({"min": 4}, "4", True),
        ({"max": 4}, "four", False),
        ({"equals": "4096 87380"}, "4096\t87380", True),
    ],
)
def test_expect_holds(raw: dict[str, Any], actual: str, ok: bool) -> None:
    assert Expect.parse(raw).holds(actual) is ok


@pytest.mark.parametrize(
    "raw",
    [
        {},
        {"equals": "a", "max": 1},
        {"max": "4"},
        {"equals": True},
        {"one_of": []},
        {"lt": 1},
        "no",
    ],
)
def test_expect_rejects_malformed(raw: Any) -> None:
    with pytest.raises(SpecError):
        Expect.parse(raw)


def _sshd(default: str | None = "prohibit-password") -> SshdOption:
    return SshdOption("PermitRootLogin", Expect.parse({"equals": "no"}), default)


def test_sshd_option_uses_the_default_when_unset() -> None:
    out = _sshd().evaluate(FakeHost({CFG: "UsePAM yes\n"}))
    assert out.status is Status.FAIL
    assert "sshd default" in out.evidence


def test_sshd_option_passes_with_explicit_value_and_cites_the_line() -> None:
    out = _sshd().evaluate(FakeHost({CFG: "UsePAM yes\nPermitRootLogin no\n"}))
    assert out.status is Status.PASS
    assert "/etc/ssh/sshd_config:2" in out.evidence


def test_sshd_option_without_default_fails_when_unset() -> None:
    assert _sshd(None).evaluate(FakeHost({CFG: ""})).status is Status.FAIL


def test_sshd_option_not_applicable_without_sshd() -> None:
    assert _sshd().evaluate(FakeHost()).status is Status.NOT_APPLICABLE


def test_sysctl_reads_proc_sys() -> None:
    check = Sysctl("net.ipv4.ip_forward", Expect.parse({"equals": 0}))
    host = FakeHost({"/proc/sys/net/ipv4/ip_forward": "1\n"})
    assert check.evaluate(host).status is Status.FAIL
    host.files["/proc/sys/net/ipv4/ip_forward"] = "0\n"
    assert check.evaluate(host).status is Status.PASS
    assert check.evaluate(FakeHost()).status is Status.NOT_APPLICABLE


@pytest.mark.parametrize(
    ("mode", "uid", "gid", "status"),
    [
        (0o640, 0, 42, Status.PASS),
        (0o600, 0, 0, Status.PASS),
        (0o000, 0, 0, Status.PASS),
        (0o644, 0, 0, Status.FAIL),
        (0o4640, 0, 0, Status.FAIL),
        (0o640, 1000, 0, Status.FAIL),
    ],
)
def test_file_mode_bits_and_owner(mode: int, uid: int, gid: int, status: Status) -> None:
    check = FileMode("/etc/shadow", 0o640, 0, None)
    host = FakeHost(stats={"/etc/shadow": FileStat(mode, uid, gid)})
    assert check.evaluate(host).status is status


def test_file_mode_group_and_absence() -> None:
    check = FileMode("/etc/passwd", 0o644, 0, 0)
    assert check.evaluate(FakeHost()).status is Status.NOT_APPLICABLE
    out = check.evaluate(FakeHost(stats={"/etc/passwd": FileStat(0o644, 0, 5)}))
    assert out.status is Status.FAIL
    assert "gid 5" in out.evidence


def _pam(**kw: Any) -> PamModule:
    base: dict[str, Any] = {
        "files": ("/etc/pam.d/common-auth", "/etc/pam.d/system-auth"),
        "module": "pam_unix.so",
        "types": (),
        "required": False,
        "forbid_args": (),
        "require_args": (),
    }
    base.update(kw)
    return PamModule(**base)


def test_pam_forbidden_argument_fails_with_location() -> None:
    host = FakeHost(
        {"/etc/pam.d/common-auth": "auth sufficient pam_unix.so try_first_pass nullok\n"}
    )
    out = _pam(forbid_args=("nullok",)).evaluate(host)
    assert out.status is Status.FAIL
    assert "common-auth:1" in out.evidence


def test_pam_forbidden_argument_matches_name_not_prefix() -> None:
    host = FakeHost({"/etc/pam.d/common-auth": "auth sufficient pam_unix.so nullok_secure\n"})
    assert _pam(forbid_args=("nullok",)).evaluate(host).status is Status.PASS


def test_pam_required_module_must_be_in_every_existing_file() -> None:
    check = _pam(module="pam_faillock.so", types=("auth",), required=True)
    one = FakeHost({"/etc/pam.d/system-auth": "auth required pam_faillock.so preauth\n"})
    assert check.evaluate(one).status is Status.PASS
    both = FakeHost(
        {
            "/etc/pam.d/system-auth": "auth required pam_faillock.so preauth\n",
            "/etc/pam.d/common-auth": "auth required pam_unix.so\n",
        }
    )
    assert check.evaluate(both).status is Status.FAIL


def test_pam_type_filter_ignores_other_stacks() -> None:
    check = _pam(module="pam_faillock.so", types=("auth",), required=True)
    host = FakeHost({"/etc/pam.d/system-auth": "account required pam_faillock.so\n"})
    assert check.evaluate(host).status is Status.FAIL


def test_pam_required_args() -> None:
    check = _pam(module="pam_pwquality.so", required=True, require_args=("retry",))
    good = FakeHost({"/etc/pam.d/system-auth": "password requisite pam_pwquality.so retry=3\n"})
    bad = FakeHost({"/etc/pam.d/system-auth": "password requisite pam_pwquality.so\n"})
    assert check.evaluate(good).status is Status.PASS
    assert check.evaluate(bad).status is Status.FAIL


def test_pam_not_applicable_when_no_file_exists() -> None:
    assert _pam(forbid_args=("nullok",)).evaluate(FakeHost()).status is Status.NOT_APPLICABLE


def test_sudoers_policy() -> None:
    policy = SudoersPolicy(("NOPASSWD",), ("use_pty",), ("visiblepw",))
    good = FakeHost({"/etc/sudoers": "Defaults use_pty\n%sudo ALL=(ALL) PASSWD: ALL\n"})
    assert policy.evaluate(good).status is Status.PASS
    tagged = FakeHost({"/etc/sudoers": "Defaults use_pty\nbob ALL=(ALL) NOPASSWD: ALL\n"})
    assert "NOPASSWD at /etc/sudoers:2" in policy.evaluate(tagged).evidence
    negated = FakeHost({"/etc/sudoers": "Defaults use_pty\nDefaults !use_pty\n"})
    assert policy.evaluate(negated).status is Status.FAIL
    visible = FakeHost({"/etc/sudoers": "Defaults use_pty, visiblepw\n"})
    assert policy.evaluate(visible).status is Status.FAIL
    assert policy.evaluate(FakeHost()).status is Status.NOT_APPLICABLE


def test_sudoers_tag_must_be_a_tag_not_a_negated_or_longer_word() -> None:
    policy = SudoersPolicy(("NOPASSWD",), (), ())
    host = FakeHost({"/etc/sudoers": "bob ALL=(ALL) /usr/bin/echo XNOPASSWD:\n"})
    assert policy.evaluate(host).status is Status.PASS


def test_services_not_running() -> None:
    check = ServicesNotRunning(("telnet.socket", "vsftpd.service"))
    assert check.evaluate(FakeHost(services=frozenset({"ssh.service"}))).status is Status.PASS
    out = check.evaluate(FakeHost(services=frozenset({"telnet.socket"})))
    assert out.status is Status.FAIL
    assert out.evidence == "running: telnet.socket"


@pytest.mark.parametrize(
    "spec",
    [
        "x",
        {"kind": "shell", "cmd": "id"},
        {"kind": "sysctl", "key": "net.ipv4.ip_forward"},
        {"kind": "sysctl", "key": "../../etc/shadow", "expect": {"equals": 0}},
        {"kind": "sysctl", "key": "a.b", "expect": {"equals": 0}, "extra": 1},
        {"kind": "sshd_option", "option": "Permit Root", "expect": {"equals": "no"}},
        {"kind": "file_mode", "path": "/etc/../root/x", "max_mode": "0600"},
        {"kind": "file_mode", "path": "/etc/x", "max_mode": 640},
        {"kind": "file_mode", "path": "/etc/x", "max_mode": "0640", "uid": -1},
        {"kind": "pam_module", "files": ["/etc/shadow"], "module": "x.so", "required": True},
        {"kind": "pam_module", "files": ["/etc/pam.d/a"], "module": "x.so"},
        {"kind": "pam_module", "files": ["/etc/pam.d/a"], "module": "x.so", "required": "yes"},
        {
            "kind": "pam_module",
            "files": ["/etc/pam.d/a"],
            "module": "x.so",
            "types": ["login"],
            "required": True,
        },
        {"kind": "sudoers"},
        {"kind": "services_not_running", "units": []},
        {"kind": "services_not_running", "units": ["telnet; rm -rf /"]},
    ],
)
def test_parse_check_rejects_malformed_specs(spec: Any) -> None:
    with pytest.raises(SpecError):
        parse_check(spec)


def test_parse_check_builds_each_kind() -> None:
    assert isinstance(
        parse_check({"kind": "sshd_option", "option": "X11Forwarding", "expect": {"equals": "no"}}),
        SshdOption,
    )
    fm = parse_check({"kind": "file_mode", "path": "/etc//shadow", "max_mode": "0640", "uid": 0})
    assert isinstance(fm, FileMode)
    assert fm.path == "/etc/shadow"
    assert fm.max_mode == 0o640
