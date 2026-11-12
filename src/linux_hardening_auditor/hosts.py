"""Read-only access to a host's configuration: a fixture tree, the local Linux host, or SSH."""

from __future__ import annotations

import re
import shlex
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

MAX_FILE_BYTES = 1024 * 1024
MAX_PATH_LEN = 4096
META_DIR = ".lha-meta"
STAT_MANIFEST = "stat.tsv"
SERVICES_FILE = "services.txt"
SYSTEMCTL_UNITS = (
    "systemctl",
    "list-units",
    "--type=service,socket",
    "--state=running,listening",
    "--no-legend",
    "--plain",
    "--no-pager",
)
_UNIT = re.compile(r"^[A-Za-z0-9@._:\\-]{1,200}\.(service|socket)$")
_PATH_CHARS = re.compile(r"^/[A-Za-z0-9._+@:/-]*$")
_SSH_TARGET = re.compile(r"^(?:[a-z_][a-z0-9_.-]{0,31}@)?[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")


class CollectError(Exception):
    """A configuration source could not be read."""


@dataclass(frozen=True)
class FileStat:
    """Permission bits and ownership of one path."""

    mode: int
    uid: int
    gid: int


class Host(Protocol):
    """What a check may read from a host."""

    @property
    def name(self) -> str:
        """Label used in reports."""
        ...

    def read_text(self, path: str) -> str | None:
        """File content, or None when the file does not exist."""
        ...

    def stat(self, path: str) -> FileStat | None:
        """Mode and owner, or None when the path does not exist."""
        ...

    def list_dir(self, path: str) -> list[str] | None:
        """Sorted entry names, or None when the directory does not exist."""
        ...

    def running_services(self) -> frozenset[str]:
        """Names of running services and listening sockets."""
        ...


def check_path(path: str) -> str:
    """Validate an absolute Linux path and return it normalised."""
    if not isinstance(path, str) or not path or len(path) > MAX_PATH_LEN:
        raise CollectError(f"invalid path: {path!r}")
    if not _PATH_CHARS.fullmatch(path):
        raise CollectError(f"path must be absolute and use safe characters: {path!r}")
    parts = [p for p in path.split("/") if p not in ("", ".")]
    if ".." in parts:
        raise CollectError(f"path must not contain '..': {path!r}")
    return "/" + "/".join(parts)


def parse_units(text: str) -> frozenset[str]:
    """Unit names from `systemctl list-units --plain --no-legend` output."""
    units: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        unit = line.split()[0]
        if not _UNIT.fullmatch(unit):
            raise CollectError(f"unexpected unit name in service list: {unit!r}")
        units.add(unit)
    return frozenset(units)


def parse_stat_manifest(text: str) -> dict[str, FileStat]:
    """Parse `mode<TAB>uid<TAB>gid<TAB>path` lines, as from `stat -c '%a\\t%u\\t%g\\t%n'`."""
    out: dict[str, FileStat] = {}
    for number, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        fields = raw.split("\t")
        if len(fields) != 4:
            raise CollectError(f"{STAT_MANIFEST}:{number}: want 4 tab-separated fields")
        mode_s, uid_s, gid_s, path = fields
        if not re.fullmatch(r"[0-7]{3,4}", mode_s) or not uid_s.isdigit() or not gid_s.isdigit():
            raise CollectError(f"{STAT_MANIFEST}:{number}: bad mode, uid or gid")
        key = check_path(path)
        if key in out:
            raise CollectError(f"{STAT_MANIFEST}:{number}: duplicate path {key}")
        out[key] = FileStat(int(mode_s, 8), int(uid_s), int(gid_s))
    return out


def _read_capped(p: Path) -> str:
    """Read a local file as UTF-8, refusing anything over the size cap."""
    try:
        size = p.stat().st_size
        if size > MAX_FILE_BYTES:
            raise CollectError(f"{p.name}: {size} bytes is over the {MAX_FILE_BYTES} byte limit")
        return p.read_bytes().decode("utf-8", errors="replace")
    except OSError as exc:
        raise CollectError(f"cannot read {p}: {exc.strerror or exc}") from exc


@dataclass(frozen=True)
class CommandResult:
    """Exit code and output of one command."""

    returncode: int
    stdout: str
    stderr: str


Runner = Callable[[Sequence[str], float], CommandResult]


def run_command(argv: Sequence[str], timeout: float) -> CommandResult:
    """Run a command without a shell; raises subprocess.TimeoutExpired on timeout."""
    proc = subprocess.run(  # noqa: S603 - fixed argv, never a shell
        list(argv),
        capture_output=True,
        timeout=timeout,
        check=False,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdin=subprocess.DEVNULL,
    )
    return CommandResult(proc.returncode, proc.stdout, proc.stderr)


class TreeHost:
    """A directory standing in for `/`, read without leaving it."""

    def __init__(
        self,
        root: Path,
        *,
        stats: dict[str, FileStat] | None,
        services: frozenset[str] | None,
        label: str | None = None,
        runner: Runner = run_command,
        timeout: float = 15.0,
    ) -> None:
        """Use the given metadata, or the real stat and systemctl when it is None."""
        self.root = root.resolve()
        self._stats = stats
        self._services = services
        self._label = label or str(root)
        self._runner = runner
        self._timeout = timeout

    @classmethod
    def fixture(cls, root: Path) -> TreeHost:
        """A fixture tree whose modes and services come from its `.lha-meta/` files."""
        if not root.is_dir():
            raise CollectError(f"fixture root is not a directory: {root}")
        meta = root / META_DIR
        stat_file, services_file = meta / STAT_MANIFEST, meta / SERVICES_FILE
        for needed in (stat_file, services_file):
            if not needed.is_file():
                raise CollectError(f"fixture lacks {META_DIR}/{needed.name}: {root}")
        stats = parse_stat_manifest(_read_capped(stat_file))
        services = parse_units(_read_capped(services_file))
        return cls(root, stats=stats, services=services, label=f"fixture:{root.name}")

    @classmethod
    def local(cls, runner: Runner = run_command) -> TreeHost:
        """The Linux host this process runs on (refused anywhere else)."""
        if not sys.platform.startswith("linux"):
            raise CollectError("--local audits only run on Linux; use --fixture or --ssh")
        return cls(Path("/"), stats=None, services=None, label="local", runner=runner)

    @property
    def name(self) -> str:
        """Label used in reports."""
        return self._label

    def _local_path(self, path: str) -> Path:
        """Map a Linux path into the tree, refusing anything that escapes it."""
        clean = check_path(path)
        candidate = (self.root / clean.lstrip("/")).resolve()
        if candidate != self.root and not candidate.is_relative_to(self.root):
            raise CollectError(f"{clean} resolves outside the audited tree")
        return candidate

    def read_text(self, path: str) -> str | None:
        """File content, or None when the file does not exist."""
        p = self._local_path(path)
        if not p.exists():
            return None
        if not p.is_file():
            raise CollectError(f"{path} is not a regular file")
        return _read_capped(p)

    def stat(self, path: str) -> FileStat | None:
        """Mode and owner from the manifest (fixtures) or os.stat (local)."""
        p = self._local_path(path)
        if not p.exists():
            return None
        if self._stats is None:
            st = p.stat()
            return FileStat(st.st_mode & 0o7777, st.st_uid, st.st_gid)
        found = self._stats.get(check_path(path))
        if found is None:
            raise CollectError(f"{path} exists but has no entry in {META_DIR}/{STAT_MANIFEST}")
        return found

    def list_dir(self, path: str) -> list[str] | None:
        """Sorted entry names, or None when the directory does not exist."""
        p = self._local_path(path)
        if not p.is_dir():
            return None
        try:
            return sorted(child.name for child in p.iterdir())
        except OSError as exc:
            raise CollectError(f"cannot list {path}: {exc.strerror or exc}") from exc

    def running_services(self) -> frozenset[str]:
        """Services from the fixture's list, or from systemctl on the local host."""
        if self._services is not None:
            return self._services
        try:
            result = self._runner(SYSTEMCTL_UNITS, self._timeout)
        except (subprocess.TimeoutExpired, OSError) as exc:
            raise CollectError(f"systemctl failed: {exc}") from exc
        if result.returncode != 0:
            raise CollectError(f"systemctl exited {result.returncode}: {result.stderr.strip()}")
        return parse_units(result.stdout)


class SshHost:
    """A remote host read through the system `ssh` client in batch mode."""

    MISSING = 3

    def __init__(
        self,
        target: str,
        *,
        port: int = 22,
        timeout: float = 15.0,
        retries: int = 2,
        backoff: float = 0.5,
        runner: Runner = run_command,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        """Validate the target and bounds; nothing is contacted until a read."""
        if not _SSH_TARGET.fullmatch(target):
            raise CollectError(f"invalid ssh target (want [user@]host): {target!r}")
        if not 1 <= port <= 65535:
            raise CollectError(f"invalid ssh port: {port}")
        if not 0 < timeout <= 300:
            raise CollectError(f"timeout must be in (0, 300] seconds: {timeout}")
        if not 0 <= retries <= 5:
            raise CollectError(f"retries must be between 0 and 5: {retries}")
        self.target, self.port, self.timeout = target, port, timeout
        self.retries, self.backoff = retries, backoff
        self._runner, self._sleep = runner, sleep

    @property
    def name(self) -> str:
        """Label used in reports."""
        return f"ssh:{self.target}"

    def argv(self, remote: str) -> list[str]:
        """The ssh command line for one remote command."""
        return [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            f"ConnectTimeout={max(1, int(self.timeout))}",
            "-p",
            str(self.port),
            "--",
            self.target,
            remote,
        ]

    def run(self, remote: str) -> CommandResult:
        """Run one remote command, retrying transport failures with bounded backoff."""
        last = ""
        for attempt in range(self.retries + 1):
            if attempt:
                self._sleep(self.backoff * 2 ** (attempt - 1))
            try:
                result = self._runner(self.argv(remote), self.timeout)
            except subprocess.TimeoutExpired:
                last = f"timed out after {self.timeout:g} s"
                continue
            except OSError as exc:
                raise CollectError(f"cannot start ssh: {exc}") from exc
            if result.returncode == 255:
                last = result.stderr.strip() or "ssh exited 255"
                continue
            if len(result.stdout) > MAX_FILE_BYTES:
                raise CollectError(f"{self.name}: output over {MAX_FILE_BYTES} bytes")
            return result
        raise CollectError(f"{self.name}: {last} ({self.retries + 1} attempts)")

    def _guarded(self, test: str, path: str, command: str) -> str | None:
        """Run `command` on a path if `test -<test>` holds, else None."""
        q = shlex.quote(check_path(path))
        result = self.run(
            f"export LC_ALL=C; test -{test} {q} || exit {self.MISSING}; {command} -- {q}"
        )
        if result.returncode == self.MISSING:
            return None
        if result.returncode != 0:
            raise CollectError(f"{self.name}: {command} {path}: {result.stderr.strip()}")
        return result.stdout

    def read_text(self, path: str) -> str | None:
        """File content, or None when the file does not exist."""
        return self._guarded("f", path, "cat")

    def stat(self, path: str) -> FileStat | None:
        """Mode and owner via `stat -c`."""
        out = self._guarded("e", path, "stat -c '%a %u %g'")
        if out is None:
            return None
        fields = out.split()
        if len(fields) != 3 or not all(f.isdigit() for f in fields):
            raise CollectError(f"{self.name}: unexpected stat output for {path}: {out!r}")
        return FileStat(int(fields[0], 8), int(fields[1]), int(fields[2]))

    def list_dir(self, path: str) -> list[str] | None:
        """Sorted entry names via `ls -1A`."""
        out = self._guarded("d", path, "ls -1A")
        return None if out is None else sorted(line for line in out.splitlines() if line)

    def running_services(self) -> frozenset[str]:
        """Running services and listening sockets via systemctl."""
        result = self.run(" ".join(SYSTEMCTL_UNITS))
        if result.returncode != 0:
            raise CollectError(f"{self.name}: systemctl exited {result.returncode}")
        return parse_units(result.stdout)
