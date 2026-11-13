"""Parsers that follow how sshd, PAM and sudo themselves read their files."""

from __future__ import annotations

import fnmatch
import posixpath
import re
from dataclasses import dataclass, field

from .hosts import CollectError, Host

SSHD_CONFIG = "/etc/ssh/sshd_config"
SUDOERS = "/etc/sudoers"
MAX_INCLUDE_DEPTH = 8
MAX_INCLUDED_FILES = 256


@dataclass(frozen=True)
class Setting:
    """One configuration value and where it was read."""

    value: str
    source: str
    line: int

    def where(self) -> str:
        """`file:line` for evidence."""
        return f"{self.source}:{self.line}"


def _expand(host: Host, pattern: str, base: str) -> list[str]:
    """Expand one Include glob (relative to `base`) in lexical order, as glob(3) does."""
    full = pattern if pattern.startswith("/") else posixpath.join(base, pattern)
    directory, leaf = posixpath.split(full)
    if any(ch in directory for ch in "*?["):
        raise CollectError(f"wildcards in Include directories are not supported: {pattern}")
    if not any(ch in leaf for ch in "*?["):
        return [full]
    names = host.list_dir(directory) or []
    return [posixpath.join(directory, n) for n in sorted(names) if fnmatch.fnmatchcase(n, leaf)]


@dataclass
class _SshdState:
    """Walk state for one sshd_config evaluation."""

    options: dict[str, Setting] = field(default_factory=dict)
    files: int = 0


def sshd_options(host: Host, path: str = SSHD_CONFIG) -> dict[str, Setting] | None:
    """Global sshd options with first-value-wins and in-place Include; None if no config."""
    if host.read_text(path) is None:
        return None
    state = _SshdState()
    _sshd_file(host, path, state, depth=0)
    return state.options


def _sshd_file(host: Host, path: str, state: _SshdState, depth: int) -> None:
    """Read one sshd file; options inside a Match block are not global and are skipped."""
    if depth > MAX_INCLUDE_DEPTH:
        raise CollectError(f"sshd Include nested deeper than {MAX_INCLUDE_DEPTH} at {path}")
    state.files += 1
    if state.files > MAX_INCLUDED_FILES:
        raise CollectError(f"sshd config includes more than {MAX_INCLUDED_FILES} files")
    text = host.read_text(path)
    if text is None:
        return  # sshd ignores Include patterns that match nothing
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"\s*=\s*|\s+", line, maxsplit=1)
        keyword = parts[0].lower()
        value = parts[1].strip() if len(parts) > 1 else ""
        if keyword == "match":
            return  # conditional block: runs to the end of this file
        if keyword == "include":
            for pattern in value.split():
                for included in _expand(host, pattern, "/etc/ssh"):
                    _sshd_file(host, included, state, depth + 1)
            continue
        if keyword not in state.options:
            state.options[keyword] = Setting(value.strip('"'), path, number)


@dataclass(frozen=True)
class PamLine:
    """One PAM stack line."""

    type: str
    control: str
    module: str
    args: tuple[str, ...]
    source: str
    line: int


def pam_lines(text: str, source: str) -> list[PamLine]:
    """Parse a PAM service file; `@include` lines are reported by the caller, not followed."""
    out: list[PamLine] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("@"):
            continue
        tokens = line.split()
        if len(tokens) < 3:
            raise CollectError(f"{source}:{number}: PAM line needs type, control and module")
        ptype = tokens[0].lstrip("-").lower()
        if tokens[1].startswith("["):
            end = next((i for i, t in enumerate(tokens) if t.endswith("]")), None)
            if end is None or end + 1 >= len(tokens):
                raise CollectError(f"{source}:{number}: unterminated [control] in PAM line")
            control, rest = " ".join(tokens[1 : end + 1]), tokens[end + 1 :]
        else:
            control, rest = tokens[1], tokens[2:]
        module = posixpath.basename(rest[0])
        out.append(PamLine(ptype, control, module, tuple(rest[1:]), source, number))
    return out


@dataclass(frozen=True)
class SudoRule:
    """A non-Defaults sudoers line, after joining continuations."""

    text: str
    source: str
    line: int


@dataclass
class Sudoers:
    """Effective global Defaults and the user rules of a sudoers tree."""

    defaults: dict[str, Setting] = field(default_factory=dict)
    rules: list[SudoRule] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    scoped_no_auth: list[Setting] = field(default_factory=list)


def split_defaults(body: str) -> list[tuple[str, bool, str]]:
    """Split a Defaults body into (name, negated, value), honouring double quotes and backslashes."""
    items: list[str] = []
    buf: list[str] = []
    quoted = escaped = False
    for ch in body:
        if escaped:
            buf.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == '"':
            quoted = not quoted
        elif ch == "," and not quoted:
            items.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    if quoted or escaped:
        raise CollectError(f"unterminated quote or escape in Defaults: {body!r}")
    items.append("".join(buf))
    out: list[tuple[str, bool, str]] = []
    for item in (i.strip() for i in items):
        if not item:
            continue
        name, _, value = item.partition("=")
        name = name.strip()
        negated = name.startswith("!")
        name = name.lstrip("!").rstrip("+-").strip()
        out.append((name, negated, value.strip()))
    return out


def _include_target(target: str, including: str) -> str:
    """Resolve an include path as sudo does: relative to the including file's directory."""
    if "%h" in target.replace("%%", ""):
        raise CollectError(
            f"{including}: %h (host name) in include path is not supported: {target}"
        )
    target = target.replace("%%", "%")
    if not target.startswith("/"):
        target = posixpath.join(posixpath.dirname(including), target)
    return target


_INCLUDE = re.compile(r"^[#@](include|includedir)\s+(\S+)\s*$")
_SUDO_DIR_SKIP = re.compile(r"(~$|\.)")


def sudoers(host: Host, path: str = SUDOERS) -> Sudoers | None:
    """Parse sudoers with include and includedir; None if the main file is absent."""
    if host.read_text(path) is None:
        return None
    result = Sudoers()
    _sudo_file(host, path, result, depth=0)
    return result


def _sudo_file(host: Host, path: str, result: Sudoers, depth: int) -> None:
    """Read one sudoers file in order, updating Defaults as sudo does (last one wins)."""
    if depth > MAX_INCLUDE_DEPTH or len(result.files) >= MAX_INCLUDED_FILES:
        raise CollectError(f"sudoers includes nested too deep or too many files at {path}")
    text = host.read_text(path)
    if text is None:
        raise CollectError(f"sudoers include not found: {path}")
    result.files.append(path)
    logical: list[tuple[int, str]] = []
    pending, start = "", 0
    for number, raw in enumerate(text.splitlines(), start=1):
        if not pending:
            start = number
        if raw.endswith("\\"):
            pending += raw[:-1] + " "
            continue
        logical.append((start, pending + raw))
        pending = ""
    if pending:
        logical.append((start, pending))
    for number, raw in logical:
        line = raw.strip()
        inc = _INCLUDE.match(line)
        if inc:
            kind, target = inc.groups()
            target = _include_target(target, path)
            if kind == "include":
                _sudo_file(host, target, result, depth + 1)
            else:
                for name in host.list_dir(target) or []:
                    if not _SUDO_DIR_SKIP.search(name):
                        _sudo_file(host, posixpath.join(target, name), result, depth + 1)
            continue
        if not line or line.startswith("#"):
            continue
        head = line.split(None, 1)
        if head[0] == "Defaults":
            for name, negated, value in split_defaults(head[1] if len(head) > 1 else ""):
                result.defaults[name] = Setting("!" if negated else (value or "on"), path, number)
            continue
        if head[0].startswith("Defaults"):
            # scoped Defaults (Defaults:user, @host, >runas, !cmnd) are not global settings,
            # but a scoped !authenticate still lets those users skip the password
            for name, negated, _ in split_defaults(head[1] if len(head) > 1 else ""):
                if name == "authenticate" and negated:
                    result.scoped_no_auth.append(Setting("!", path, number))
            continue
        if head[0].endswith("_Alias"):
            continue  # aliases are not rules
        result.rules.append(SudoRule(line, path, number))
