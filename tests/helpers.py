"""In-memory host for unit tests."""

from __future__ import annotations

import posixpath
from pathlib import Path

from linux_hardening_auditor.hosts import CollectError, FileStat, check_path

FIXTURES = Path(__file__).parent / "fixtures" / "hosts"


class FakeHost:
    """A host made of a dict of files, stats and running units."""

    def __init__(
        self,
        files: dict[str, str] | None = None,
        stats: dict[str, FileStat] | None = None,
        services: frozenset[str] = frozenset(),
        broken: frozenset[str] = frozenset(),
    ) -> None:
        """Files map absolute paths to content; `broken` paths raise CollectError."""
        self.files = dict(files or {})
        self.stats = dict(stats or {})
        self.services = services
        self.broken = broken
        self.reads: list[str] = []

    @property
    def name(self) -> str:
        """Label used in reports."""
        return "fake"

    def read_text(self, path: str) -> str | None:
        """File content or None."""
        path = check_path(path)
        self.reads.append(path)
        if path in self.broken:
            raise CollectError(f"permission denied: {path}")
        return self.files.get(path)

    def stat(self, path: str) -> FileStat | None:
        """Stat or None."""
        return self.stats.get(check_path(path))

    def list_dir(self, path: str) -> list[str] | None:
        """Names directly under a directory, or None."""
        prefix = check_path(path).rstrip("/") + "/"
        names = {p[len(prefix) :].split("/")[0] for p in self.files if p.startswith(prefix)}
        return sorted(names) if names else None

    def running_services(self) -> frozenset[str]:
        """Running units."""
        return self.services


def join(*parts: str) -> str:
    """posixpath.join shortcut."""
    return posixpath.join(*parts)
