"""Host back ends: the fixture tree stays inside its root, SSH is bounded and quoted."""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

import pytest
from helpers import FIXTURES

from linux_hardening_auditor.hosts import (
    MAX_FILE_BYTES,
    CollectError,
    CommandResult,
    FileStat,
    SshHost,
    TreeHost,
    check_path,
    parse_stat_manifest,
    parse_units,
)


def _tree(tmp_path: Path, stat: str = "", services: str = "") -> Path:
    meta = tmp_path / ".lha-meta"
    meta.mkdir(parents=True)
    (meta / "stat.tsv").write_text(stat, encoding="utf-8")
    (meta / "services.txt").write_text(services, encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize(
    "bad", ["", "etc/shadow", "/etc/../root", "/etc/sh adow", "/etc/x\n", "/a\x00"]
)
def test_check_path_rejects_unsafe_paths(bad: str) -> None:
    with pytest.raises(CollectError):
        check_path(bad)


def test_check_path_normalises() -> None:
    assert check_path("/etc//ssh/./sshd_config") == "/etc/ssh/sshd_config"
    assert check_path("/") == "/"


def test_parse_units_and_rejects_garbage() -> None:
    text = "ssh.service loaded active running OpenSSH\n\ntelnet.socket loaded active listening T\n"
    assert parse_units(text) == frozenset({"ssh.service", "telnet.socket"})
    assert parse_units("") == frozenset()
    with pytest.raises(CollectError):
        parse_units("● broken loaded failed failed X\n")


def test_parse_stat_manifest() -> None:
    got = parse_stat_manifest("# c\n640\t0\t42\t/etc/shadow\n000\t0\t0\t/etc/gshadow\n")
    assert got == {"/etc/shadow": FileStat(0o640, 0, 42), "/etc/gshadow": FileStat(0, 0, 0)}


@pytest.mark.parametrize(
    "bad",
    [
        "640 0 0 /etc/x",
        "800\t0\t0\t/etc/x",
        "640\t-1\t0\t/etc/x",
        "640\t0\t0\trel",
        "640\t0\t0\t/a\n640\t0\t0\t/a",
    ],
)
def test_parse_stat_manifest_rejects_bad_lines(bad: str) -> None:
    with pytest.raises(CollectError):
        parse_stat_manifest(bad)


def test_fixture_requires_its_metadata(tmp_path: Path) -> None:
    with pytest.raises(CollectError, match="not a directory"):
        TreeHost.fixture(tmp_path / "nope")
    with pytest.raises(CollectError, match=r"lacks .lha-meta/stat.tsv"):
        TreeHost.fixture(tmp_path)


def test_fixture_reads_files_and_reports_absence(tmp_path: Path) -> None:
    root = _tree(tmp_path, "600\t0\t0\t/etc/a\n", "ssh.service loaded active running X\n")
    (root / "etc").mkdir()
    (root / "etc" / "a").write_bytes(b"hello\n")
    host = TreeHost.fixture(root)
    assert host.read_text("/etc/a") == "hello\n"
    assert host.read_text("/etc/missing") is None
    assert host.stat("/etc/a") == FileStat(0o600, 0, 0)
    assert host.stat("/etc/missing") is None
    assert host.list_dir("/etc") == ["a"]
    assert host.list_dir("/nope") is None
    assert host.running_services() == frozenset({"ssh.service"})
    with pytest.raises(CollectError, match="not a regular file"):
        host.read_text("/etc")


def test_fixture_file_without_a_stat_entry_is_an_error(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    (root / "etc").mkdir()
    (root / "etc" / "b").write_text("x", encoding="utf-8")
    with pytest.raises(CollectError, match="no entry"):
        TreeHost.fixture(root).stat("/etc/b")


def test_fixture_refuses_oversized_files(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    (root / "big").write_bytes(b"x" * (MAX_FILE_BYTES + 1))
    with pytest.raises(CollectError, match="limit"):
        TreeHost.fixture(root).read_text("/big")


def test_fixture_symlink_escaping_the_tree_is_refused(tmp_path: Path) -> None:
    root = _tree(tmp_path / "root")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("not for the audit", encoding="utf-8")
    link = root / "etc"
    if sys.platform == "win32":
        import _winapi  # directory junctions need no extra rights, unlike symlinks

        _winapi.CreateJunction(str(outside), str(link))
    else:
        link.symlink_to(outside, target_is_directory=True)
    with pytest.raises(CollectError, match="outside the audited tree"):
        TreeHost.fixture(root).read_text("/etc/secret.txt")


def test_local_audit_is_refused_off_linux() -> None:
    if sys.platform.startswith("linux"):
        pytest.skip("this check is about non-Linux hosts")
    with pytest.raises(CollectError, match="only run on Linux"):
        TreeHost.local()


def test_local_services_come_from_systemctl_and_failures_raise(tmp_path: Path) -> None:
    calls: list[Sequence[str]] = []

    def ok(argv: Sequence[str], timeout: float) -> CommandResult:
        calls.append(argv)
        return CommandResult(0, "cron.service loaded active running C\n", "")

    host = TreeHost(tmp_path, stats=None, services=None, runner=ok)
    assert host.running_services() == frozenset({"cron.service"})
    assert calls[0][0] == "systemctl"

    def bad(argv: Sequence[str], timeout: float) -> CommandResult:
        return CommandResult(1, "", "Failed to connect to bus")

    with pytest.raises(CollectError, match="Failed to connect"):
        TreeHost(tmp_path, stats=None, services=None, runner=bad).running_services()

    def hang(argv: Sequence[str], timeout: float) -> CommandResult:
        raise subprocess.TimeoutExpired(list(argv), timeout)

    with pytest.raises(CollectError, match="systemctl failed"):
        TreeHost(tmp_path, stats=None, services=None, runner=hang).running_services()


class Script:
    """A fake runner that returns queued results and records calls."""

    def __init__(self, *results: CommandResult | BaseException) -> None:
        self.results = list(results)
        self.calls: list[list[str]] = []

    def __call__(self, argv: Sequence[str], timeout: float) -> CommandResult:
        self.calls.append(list(argv))
        item = self.results.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


def _ssh(script: Script, retries: int = 2) -> tuple[SshHost, list[float]]:
    sleeps: list[float] = []
    return SshHost(
        "admin@web1.example", runner=script, retries=retries, sleep=sleeps.append
    ), sleeps


@pytest.mark.parametrize("target", ["-oProxyCommand=x", "a b", "root@", "@host", "h;id", ""])
def test_ssh_target_is_validated_so_it_cannot_become_an_option(target: str) -> None:
    with pytest.raises(CollectError, match="invalid ssh target"):
        SshHost(target)


@pytest.mark.parametrize(
    ("kw", "msg"), [({"port": 0}, "port"), ({"timeout": 0}, "timeout"), ({"retries": 9}, "retries")]
)
def test_ssh_bounds_are_validated(kw: dict[str, float], msg: str) -> None:
    with pytest.raises(CollectError, match=msg):
        SshHost("host", **kw)  # type: ignore[arg-type]


def test_ssh_read_quotes_the_path_and_uses_batch_mode() -> None:
    script = Script(CommandResult(0, "PermitRootLogin no\n", ""))
    host, _ = _ssh(script)
    assert host.read_text("/etc/ssh/sshd_config") == "PermitRootLogin no\n"
    argv = script.calls[0]
    assert argv[:2] == ["ssh", "-o"]
    assert "BatchMode=yes" in argv
    assert argv[argv.index("--") + 1] == "admin@web1.example"
    assert "cat -- /etc/ssh/sshd_config" in argv[-1]


def test_ssh_missing_file_is_none_and_other_errors_raise() -> None:
    host, _ = _ssh(Script(CommandResult(3, "", "")))
    assert host.read_text("/etc/nope") is None
    host, _ = _ssh(Script(CommandResult(1, "", "cat: Permission denied")))
    with pytest.raises(CollectError, match="Permission denied"):
        host.read_text("/etc/shadow")


def test_ssh_retries_transport_failures_with_backoff_then_succeeds() -> None:
    script = Script(
        CommandResult(255, "", "Connection timed out"),
        subprocess.TimeoutExpired(["ssh"], 15),
        CommandResult(0, "640 0 42\n", ""),
    )
    host, sleeps = _ssh(script)
    assert host.stat("/etc/shadow") == FileStat(0o640, 0, 42)
    assert len(script.calls) == 3
    assert sleeps == [0.5, 1.0]


def test_ssh_gives_up_after_bounded_attempts() -> None:
    script = Script(*[CommandResult(255, "", "Connection refused")] * 3)
    host, sleeps = _ssh(script)
    with pytest.raises(CollectError, match="Connection refused \\(3 attempts\\)"):
        host.list_dir("/etc/sudoers.d")
    assert len(sleeps) == 2


def test_ssh_does_not_retry_a_command_failure() -> None:
    script = Script(CommandResult(1, "", "boom"), CommandResult(0, "", ""))
    host, _ = _ssh(script)
    with pytest.raises(CollectError):
        host.read_text("/etc/a")
    assert len(script.calls) == 1


def test_ssh_unparseable_stat_and_oversized_output_raise() -> None:
    host, _ = _ssh(Script(CommandResult(0, "drwx root\n", "")))
    with pytest.raises(CollectError, match="unexpected stat"):
        host.stat("/etc/shadow")
    host, _ = _ssh(Script(CommandResult(0, "x" * (MAX_FILE_BYTES + 1), "")))
    with pytest.raises(CollectError, match="output over"):
        host.read_text("/etc/a")


def test_ssh_list_dir_and_services() -> None:
    script = Script(
        CommandResult(0, "b\na\n", ""),
        CommandResult(0, "sshd.service loaded active running S\n", ""),
    )
    host, _ = _ssh(script)
    assert host.list_dir("/etc/sudoers.d") == ["a", "b"]
    assert host.running_services() == frozenset({"sshd.service"})
    assert script.calls[1][-1].startswith("systemctl list-units")


def test_ssh_cannot_start_client() -> None:
    host, _ = _ssh(Script(FileNotFoundError("ssh")))
    with pytest.raises(CollectError, match="cannot start ssh"):
        host.read_text("/etc/a")


def test_shipped_fixtures_load() -> None:
    for name in ("hardened", "weak", "rocky"):
        assert TreeHost.fixture(FIXTURES / name).read_text("/etc/passwd")
