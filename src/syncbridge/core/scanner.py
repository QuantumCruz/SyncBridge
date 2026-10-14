
"""Read-only filesystem inventory for SyncBridge.

The scanner identifies regular files under a selected root directory and
calculates their SHA-256 hashes. It does not modify files, save snapshots,
or make synchronization decisions.
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


CHUNK_SIZE = 1024 * 1024
DEFAULT_EXCLUDES = (".git", ".venv", "__pycache__", ".syncbridge")


@dataclass(frozen=True, slots=True)
class FileRecord:
    relative_path: str
    size: int
    modified_ns: int
    sha256: str


@dataclass(frozen=True, slots=True)
class ScanError:
    relative_path: str
    message: str


@dataclass(slots=True)
class ScanResult:
    root: Path
    files: dict[str, FileRecord] = field(default_factory=dict)
    errors: list[ScanError] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        """False if any directory/file could not be reliably scanned."""
        return not self.errors


class FileScanner:
    """Scan a folder without following symbolic links.

    Patterns without a slash match any file/directory component.
    Patterns with a slash match paths relative to the scan root.
    """

    def __init__(self, root: str | Path, excludes: Iterable[str] = ()) -> None:
        self.root = Path(root).expanduser().resolve(strict=True)
        if not self.root.is_dir():
            raise NotADirectoryError(f"Not a directory: {self.root}")

        extra_patterns = tuple(
            pattern.replace("\\", "/").strip().rstrip("/")
            for pattern in excludes
        )
        self._excludes = DEFAULT_EXCLUDES + tuple(
            pattern for pattern in extra_patterns if pattern
        )

    def scan(self) -> ScanResult:
        """Return a file inventory and any errors encountered.

        An incomplete scan must not be interpreted as proof that missing
        files have been deleted.
        """
        result = ScanResult(root=self.root)
        pending = [self.root]

        while pending:
            directory = pending.pop()
            relative_directory = directory.relative_to(self.root).as_posix()
            if directory == self.root:
                relative_directory = "."

            try:
                with os.scandir(directory) as entries:
                    children = sorted(entries, key=lambda entry: entry.name)
            except OSError as exc:
                result.errors.append(ScanError(relative_directory, str(exc)))
                continue

            for entry in children:
                path = Path(entry.path)
                relative_path = path.relative_to(self.root).as_posix()
                if self._is_excluded(relative_path):
                    continue

                try:
                    # Do not intentionally follow links or special entries.
                    if entry.is_symlink():
                        continue

                    metadata = entry.stat(follow_symlinks=False)
                    if stat.S_ISDIR(metadata.st_mode):
                        pending.append(path)
                    elif stat.S_ISREG(metadata.st_mode):
                        result.files[relative_path] = self._hash_file(
                            path, relative_path, metadata
                        )
                except OSError as exc:
                    result.errors.append(ScanError(relative_path, str(exc)))

        result.files = dict(sorted(result.files.items()))
        result.errors.sort(key=lambda error: error.relative_path)
        return result

    def _is_excluded(self, relative_path: str) -> bool:
        parts = relative_path.split("/")
        for pattern in self._excludes:
            if "/" in pattern:
                if fnmatch.fnmatchcase(relative_path, pattern):
                    return True
                if relative_path.startswith(pattern + "/"):
                    return True
            elif any(fnmatch.fnmatchcase(part, pattern) for part in parts):
                return True
        return False

    @staticmethod
    def _same_file_state(first: os.stat_result, second: os.stat_result) -> bool:
        """Compare stable metadata fields across different filesystem APIs.

        On Windows/Python 3.12, scandir and fstat can disagree on st_ctime.
        Directory entry identity fields can also be unavailable (zero).
        """
        if first.st_size != second.st_size:
            return False

        if first.st_mtime_ns != second.st_mtime_ns:
            return False

        # Only compare identity when both sources supply non-zero values.
        if (
            first.st_dev != 0
            and second.st_dev != 0
            and first.st_ino != 0
            and second.st_ino != 0
        ):
            return (first.st_dev, first.st_ino) == (
                second.st_dev,
                second.st_ino,
            )

        return True

    @classmethod
    def _hash_file(
        cls, path: Path, relative_path: str, initial_stat: os.stat_result
    ) -> FileRecord:
        digest = hashlib.sha256()
        total_bytes = 0

        with path.open("rb") as file:
            opened_stat = os.fstat(file.fileno())

            if not cls._same_file_state(initial_stat, opened_stat):
                raise OSError("File changed before hashing started")

            while chunk := file.read(CHUNK_SIZE):
                digest.update(chunk)
                total_bytes += len(chunk)

            finished_stat = os.fstat(file.fileno())

        current_stat = path.stat(follow_symlinks=False)

        if (
            total_bytes != opened_stat.st_size
            or not cls._same_file_state(opened_stat, finished_stat)
            or not cls._same_file_state(finished_stat, current_stat)
            or not stat.S_ISREG(current_stat.st_mode)
        ):
            raise OSError("File changed while being hashed")

        return FileRecord(
            relative_path=relative_path,
            size=total_bytes,
            modified_ns=finished_stat.st_mtime_ns,
            sha256=digest.hexdigest(),
        )
