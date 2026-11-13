"""The check kinds a YAML rule can use, each a read-only test against a Host."""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass
from typing import Any

from .hosts import CollectError, Host, check_path
from .parsers import pam_lines, sshd_options, sudoers


class Status(enum.StrEnum):
    """Outcome of one rule on one host."""

    PASS = "pass"  # noqa: S105 - a status name, not a password
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"


@dataclass(frozen=True)
class Outcome:
    """A status and the evidence behind it."""

    status: Status
    evidence: str


class SpecError(ValueError):
    """A rule's check block is malformed."""


def _require_keys(spec: dict[str, Any], required: set[str], optional: set[str]) -> None:
    """Reject missing or unknown keys in a check block."""
    keys = set(spec) - {"kind"}
    missing, unknown = required - keys, keys - required - optional
    if missing:
        raise SpecError(f"missing key(s): {', '.join(sorted(missing))}")
    if unknown:
        raise SpecError(f"unknown key(s): {', '.join(sorted(unknown))}")


def _str(spec: dict[str, Any], key: str) -> str:
    """A required non-empty string field."""
    value = spec.get(key)
    if not isinstance(value, str) or not value.strip():
        raise SpecError(f"{key} must be a non-empty string")
    return value.strip()


def _str_list(spec: dict[str, Any], key: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    """An optional list of non-empty strings."""
    value = spec.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
        raise SpecError(f"{key} must be a list of non-empty strings")
    if not allow_empty and not value:
        raise SpecError(f"{key} must not be empty")
    return tuple(v.strip() for v in value)


def _int(value: str) -> int | None:
    """Parse a decimal integer, or None."""
    return int(value) if re.fullmatch(r"-?\d+", value) else None


@dataclass(frozen=True)
class Expect:
    """A comparison: equals, one_of, max or min."""

    op: str
    values: tuple[str, ...]

    @classmethod
    def parse(cls, raw: Any) -> Expect:
        """Parse `{equals: x}`, `{one_of: [..]}`, `{max: n}` or `{min: n}`."""
        if not isinstance(raw, dict) or len(raw) != 1:
            raise SpecError("expect must have exactly one of equals, one_of, max, min")
        op, value = next(iter(raw.items()))
        if op == "equals" and isinstance(value, str | int) and not isinstance(value, bool):
            return cls(op, (str(value),))
        if (
            op == "one_of"
            and isinstance(value, list)
            and value
            and all(isinstance(v, str | int) and not isinstance(v, bool) for v in value)
        ):
            return cls(op, tuple(str(v) for v in value))
        if op in ("max", "min") and isinstance(value, int) and not isinstance(value, bool):
            return cls(op, (str(value),))
        raise SpecError(f"invalid expect: {raw!r}")

    def holds(self, actual: str) -> bool:
        """Whether the observed value satisfies the expectation."""
        norm = " ".join(actual.split()).lower()
        if self.op in ("equals", "one_of"):
            return norm in {" ".join(v.split()).lower() for v in self.values}
        number = _int(norm)
        if number is None:
            return False
        limit = int(self.values[0])
        return number <= limit if self.op == "max" else number >= limit

    def describe(self) -> str:
        """Human-readable expectation."""
        if self.op == "one_of":
            return "one of " + ", ".join(self.values)
        return f"{self.op.replace('equals', '=').replace('max', '<=').replace('min', '>=')} {self.values[0]}"


@dataclass(frozen=True)
class SshdOption:
    """An sshd global option, using sshd's own default when unset."""

    option: str
    expect: Expect
    default: str | None

    def evaluate(self, host: Host) -> Outcome:
        """Compare the effective value with the expectation."""
        options = sshd_options(host)
        if options is None:
            return Outcome(Status.NOT_APPLICABLE, "/etc/ssh/sshd_config not found")
        found = options.get(self.option.lower())
        if found is None and self.default is None:
            return Outcome(Status.FAIL, f"{self.option} not set and has no safe default")
        value = found.value if found else str(self.default)
        where = found.where() if found else "sshd default"
        status = Status.PASS if self.expect.holds(value) else Status.FAIL
        return Outcome(status, f"{self.option} {value} ({where}); want {self.expect.describe()}")


_SYSCTL_KEY = re.compile(r"^[a-z0-9_]+(\.[a-z0-9_-]+)+$")


@dataclass(frozen=True)
class Sysctl:
    """A running kernel parameter read from /proc/sys."""

    key: str
    expect: Expect

    def evaluate(self, host: Host) -> Outcome:
        """Compare the running value with the expectation."""
        path = "/proc/sys/" + self.key.replace(".", "/")
        text = host.read_text(path)
        if text is None:
            return Outcome(Status.NOT_APPLICABLE, f"{self.key} not present on this kernel")
        value = " ".join(text.split())
        status = Status.PASS if self.expect.holds(value) else Status.FAIL
        return Outcome(status, f"{self.key} = {value}; want {self.expect.describe()}")


@dataclass(frozen=True)
class FileMode:
    """A file's permission bits stay within a maximum and its owner is as expected."""

    path: str
    max_mode: int
    uid: int | None
    gid: int | None

    def evaluate(self, host: Host) -> Outcome:
        """Fail on extra permission bits or the wrong owner or group."""
        st = host.stat(self.path)
        if st is None:
            return Outcome(Status.NOT_APPLICABLE, f"{self.path} not present")
        problems = []
        extra = st.mode & ~self.max_mode
        if extra:
            problems.append(
                f"mode {st.mode:04o} adds {extra:04o} to the allowed {self.max_mode:04o}"
            )
        if self.uid is not None and st.uid != self.uid:
            problems.append(f"owner uid {st.uid}, want {self.uid}")
        if self.gid is not None and st.gid != self.gid:
            problems.append(f"group gid {st.gid}, want {self.gid}")
        if problems:
            return Outcome(Status.FAIL, f"{self.path}: " + "; ".join(problems))
        return Outcome(Status.PASS, f"{self.path}: mode {st.mode:04o} uid {st.uid} gid {st.gid}")


@dataclass(frozen=True)
class PamModule:
    """A PAM module is present (or its arguments are safe) in every listed file that exists."""

    files: tuple[str, ...]
    module: str
    types: tuple[str, ...]
    required: bool
    forbid_args: tuple[str, ...]
    require_args: tuple[str, ...]

    def evaluate(self, host: Host) -> Outcome:
        """Check each existing PAM file; not applicable when none exists."""
        seen, problems, good = 0, [], []
        for path in self.files:
            text = host.read_text(path)
            if text is None:
                continue
            seen += 1
            lines = [
                ln
                for ln in pam_lines(text, path)
                if ln.module == self.module and (not self.types or ln.type in self.types)
            ]
            if self.required and not lines:
                problems.append(f"{self.module} missing from {path}")
            for ln in lines:
                names = {a.split("=", 1)[0] for a in ln.args}
                bad = [a for a in self.forbid_args if a in names]
                if bad:
                    problems.append(f"{', '.join(bad)} on {self.module} ({path}:{ln.line})")
                lacking = [a for a in self.require_args if a not in names]
                if lacking:
                    problems.append(f"{self.module} lacks {', '.join(lacking)} ({path}:{ln.line})")
                if not bad and not lacking:
                    good.append(f"{path}:{ln.line}")
        if not seen:
            return Outcome(Status.NOT_APPLICABLE, "none of " + ", ".join(self.files) + " exist")
        if problems:
            return Outcome(Status.FAIL, "; ".join(problems))
        where = ", ".join(good) if good else f"no {self.module} lines"
        return Outcome(Status.PASS, f"{self.module} ok ({where})")


@dataclass(frozen=True)
class SudoersPolicy:
    """No forbidden tags in user rules; required global Defaults are on, forbidden ones off."""

    forbid_tags: tuple[str, ...]
    require_defaults: tuple[str, ...]
    forbid_defaults: tuple[str, ...]

    def evaluate(self, host: Host) -> Outcome:
        """Walk sudoers and its includes in sudo's order."""
        parsed = sudoers(host)
        if parsed is None:
            return Outcome(Status.NOT_APPLICABLE, "/etc/sudoers not found")
        problems = [
            f"{tag} at {rule.source}:{rule.line}"
            for rule in parsed.rules
            for tag in self.forbid_tags
            if re.search(rf"(?<![!\w]){re.escape(tag)}\s*:", rule.text)
        ]
        if "NOPASSWD" in self.forbid_tags:
            # `Defaults !authenticate` has the same effect as NOPASSWD, globally or scoped
            auth = parsed.defaults.get("authenticate")
            no_auth = ([auth] if auth is not None and auth.value == "!" else []) + list(
                parsed.scoped_no_auth
            )
            problems += [f"Defaults !authenticate at {s.where()}" for s in no_auth]
        for name in self.require_defaults:
            got = parsed.defaults.get(name)
            if got is None or got.value == "!":
                where = f" (negated at {got.where()})" if got else ""
                problems.append(f"Defaults {name} not set{where}")
        for name in self.forbid_defaults:
            got = parsed.defaults.get(name)
            if got is not None and got.value != "!":
                problems.append(f"Defaults {name} set at {got.where()}")
        if problems:
            return Outcome(Status.FAIL, "; ".join(problems))
        return Outcome(Status.PASS, f"{len(parsed.files)} sudoers file(s) checked")


_UNIT = re.compile(r"^[A-Za-z0-9@._:\\-]+\.(service|socket)$")


@dataclass(frozen=True)
class ServicesNotRunning:
    """None of the listed services or sockets is running."""

    units: tuple[str, ...]

    def evaluate(self, host: Host) -> Outcome:
        """Fail if any listed unit is running or listening."""
        running = host.running_services()
        hits = sorted(u for u in self.units if u in running)
        if hits:
            return Outcome(Status.FAIL, "running: " + ", ".join(hits))
        return Outcome(Status.PASS, "none running of " + ", ".join(self.units))


Check = SshdOption | Sysctl | FileMode | PamModule | SudoersPolicy | ServicesNotRunning


def parse_check(spec: Any) -> Check:
    """Build a check from its YAML mapping, validating every field."""
    if not isinstance(spec, dict):
        raise SpecError("check must be a mapping")
    kind = spec.get("kind")
    if kind == "sshd_option":
        _require_keys(spec, {"option", "expect"}, {"default"})
        option = _str(spec, "option")
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", option):
            raise SpecError(f"invalid sshd option name: {option}")
        default = spec.get("default")
        if default is not None and not isinstance(default, str | int):
            raise SpecError("default must be a string or integer")
        return SshdOption(
            option, Expect.parse(spec["expect"]), None if default is None else str(default)
        )
    if kind == "sysctl":
        _require_keys(spec, {"key", "expect"}, set())
        key = _str(spec, "key")
        if not _SYSCTL_KEY.fullmatch(key):
            raise SpecError(f"invalid sysctl key: {key}")
        return Sysctl(key, Expect.parse(spec["expect"]))
    if kind == "file_mode":
        _require_keys(spec, {"path", "max_mode"}, {"uid", "gid"})
        mode = spec["max_mode"]
        if not isinstance(mode, str) or not re.fullmatch(r"0?[0-7]{3,4}", mode):
            raise SpecError("max_mode must be an octal string such as '0640'")
        ids: list[int | None] = []
        for key in ("uid", "gid"):
            v = spec.get(key)
            if v is not None and (not isinstance(v, int) or isinstance(v, bool) or v < 0):
                raise SpecError(f"{key} must be a non-negative integer")
            ids.append(v)
        try:
            path = check_path(_str(spec, "path"))
        except CollectError as exc:
            raise SpecError(str(exc)) from exc
        return FileMode(path, int(mode, 8), ids[0], ids[1])
    if kind == "pam_module":
        _require_keys(
            spec, {"files", "module"}, {"types", "required", "forbid_args", "require_args"}
        )
        files = _str_list(spec, "files", allow_empty=False)
        for f in files:
            if not f.startswith("/etc/pam.d/"):
                raise SpecError(f"PAM files must be under /etc/pam.d/: {f}")
        required = spec.get("required", False)
        if not isinstance(required, bool):
            raise SpecError("required must be true or false")
        types = _str_list(spec, "types")
        if not set(types) <= {"auth", "account", "password", "session"}:
            raise SpecError(f"unknown PAM type in {types}")
        check = PamModule(
            files,
            _str(spec, "module"),
            types,
            required,
            _str_list(spec, "forbid_args"),
            _str_list(spec, "require_args"),
        )
        if not (check.required or check.forbid_args or check.require_args):
            raise SpecError("pam_module needs required, forbid_args or require_args")
        return check
    if kind == "sudoers":
        _require_keys(spec, set(), {"forbid_tags", "require_defaults", "forbid_defaults"})
        policy = SudoersPolicy(
            _str_list(spec, "forbid_tags"),
            _str_list(spec, "require_defaults"),
            _str_list(spec, "forbid_defaults"),
        )
        if not (policy.forbid_tags or policy.require_defaults or policy.forbid_defaults):
            raise SpecError("sudoers check needs at least one condition")
        return policy
    if kind == "services_not_running":
        _require_keys(spec, {"units"}, set())
        units = _str_list(spec, "units", allow_empty=False)
        for u in units:
            if not _UNIT.fullmatch(u):
                raise SpecError(f"invalid unit name: {u}")
        return ServicesNotRunning(units)
    raise SpecError(f"unknown check kind: {kind!r}")
