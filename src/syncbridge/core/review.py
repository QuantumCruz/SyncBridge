
"""Human-facing review and non-destructive resolution for one SyncBridge share.

A review is read-only. Resolve actions re-fetch authenticated inventories and
compare the committed baseline plus content hashes before touching files.
Only these repairs are available:
  * Restore the missing side of an agreed, otherwise unchanged file.
  * Keep BOTH divergent copies when both peers still hold regular files: the
    local version becomes an additional, clearly named file; the remote
    version is then conditionally downloaded to the original path.

No remote deletion RPC exists yet. Nothing in this module authorizes deletion.
A caller must serialize review actions with synchronization cycles across BOTH
peers; the CLI demo supplies a shared lock. Cross-process filesystem writers
are not blocked, so these methods are not yet suitable for unattended repair.
"""
from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from dataclasses import dataclass
from enum import Enum

from syncbridge.core.conflicts import SyncAction, SyncDecision
from syncbridge.core.coordinator import SyncCoordinator, StaleSyncState
from syncbridge.core.lifecycle import SyncLifecycle
from syncbridge.network.transfer import TransferError, TransferResult


class ReviewError(RuntimeError):
    """A requested review action cannot be completed safely."""


class ReviewKind(str, Enum):
    CONFLICT = "conflict"
    MISSING_HERE = "missing_here"
    MISSING_THERE = "missing_there"
    DELETED_BOTH = "deleted_both"


@dataclass(frozen=True, slots=True)
class ReviewIssue:
    code: str
    kind: ReviewKind
    path: str
    title: str
    explanation: str
    next_step: str
    options: tuple[str, ...]
    baseline_revision: int
    signature: tuple


@dataclass(frozen=True, slots=True)
class ReviewOutcome:
    message: str
    transferred: TransferResult
    preserved_copy: str | None = None


# Public, stable support-code catalog. Do not change code meanings in place.
HELP = {
    "SB-DEL-101": "A file present at the last successful sync is missing on this device. You can restore it, or wait for a deletion-approval feature.",
    "SB-DEL-102": "A file present at the last successful sync is missing on the other device. You can restore it, or wait for a deletion-approval feature.",
    "SB-DEL-103": "The file was removed from both devices after the last successful sync. Recording deletion requires explicit approval, not yet supported.",
    "SB-CFL-201": "Both devices changed the same file since the last successful sync. Neither will automatically overwrite the other.",
    "SB-CFL-202": "Both devices have different files with the same name and no agreed common version.",
    "SB-CFL-203": "One device removed the file while the other edited it. Automatic restoration or deletion would discard someone's intent.",
    "SB-RSL-409": "The file or synchronization history changed since review. Refresh review and decide again.",
    "SB-RSL-410": "This review action cannot be performed without risk. No deletion has been authorized; inspect the file and try a different action.",
    "SB-CON-401": "The other device could not be reached. Confirm it is running and both devices are on the same reachable network.",
    "SB-AUT-403": "The other device did not grant the required permission. Both devices must be paired and grant access to this share.",
    "SB-SYN-500": "The devices disagree about their shared history or a previous commit is pending. Keep both folders unchanged and retry recovery.",
    "SB-ERR-900": "An unexpected error occurred. Keep your files and use the full technical details when reporting the issue.",
}


def help_for(code: str) -> str:
    return HELP.get(
        code,
        "Unknown SyncBridge issue code. Confirm the installed application version.",
    )


def explain_error(error: Exception) -> tuple[str, str, str]:
    """Support code, readable explanation, and a concrete next action."""
    value = str(error).lower()

    if (
        isinstance(error, StaleSyncState)
        or "changed since" in value
        or "mismatch" in value
    ):
        return (
            "SB-RSL-409",
            "One of the files changed while SyncBridge was checking it.",
            "Run Review again before choosing an action.",
        )

    if any(
        phrase in value
        for phrase in (
            "not authorized",
            "permission",
            "not paired",
            "not trusted",
        )
    ):
        return (
            "SB-AUT-403",
            "The other computer has not allowed this operation.",
            "Verify pairing and folder access on both computers.",
        )

    if isinstance(
        error, (ConnectionError, TimeoutError, OSError)
    ) or any(
        phrase in value
        for phrase in (
            "cannot reach",
            "timed out",
            "connection refused",
            "connection closed",
            "disconnected",
        )
    ):
        return (
            "SB-CON-401",
            "The other computer is not reachable right now.",
            "Check that it is running, then try again.",
        )

    if any(
        phrase in value
        for phrase in ("baseline", "proposal", "revision")
    ):
        return (
            "SB-SYN-500",
            "The computers have not agreed on their latest synchronization state.",
            "Do not remove files. Retry synchronization to recover the pending agreement.",
        )

    if isinstance(error, (ReviewError, TransferError)):
        return (
            "SB-RSL-410",
            "SyncBridge stopped an operation to protect your files.",
            "Review the file's current state before retrying.",
        )

    return (
        "SB-ERR-900",
        "SyncBridge could not complete the operation.",
        "Keep the files unchanged and include the support code when reporting the issue.",
    )


def _record(record) -> tuple[int, str] | None:
    return (
        None
        if record is None
        else (record.size, record.sha256)
    )


def _signature(decision: SyncDecision) -> tuple:
    return (
        decision.action.value,
        _record(decision.base),
        _record(decision.local),
        _record(decision.remote),
    )


def _name(value: str, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 70
        or any(ord(c) < 32 for c in value)
    ):
        raise ValueError(
            f"{label} must be a short printable device name"
        )

    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(
            f"{label} must contain valid Unicode"
        ) from exc

    return value.strip()


class ReviewManager:
    """Build readable issues and carry out explicitly selected safe repairs."""

    def __init__(
        self,
        lifecycle: SyncLifecycle,
        *,
        here: str,
        there: str,
    ):
        if not isinstance(lifecycle, SyncLifecycle):
            raise TypeError(
                "lifecycle must be SyncLifecycle"
            )

        self.lifecycle = lifecycle
        self.coordinator: SyncCoordinator = lifecycle.coordinator
        self.here = _name(here, "here")
        self.there = _name(there, "there")

    def list_issues(self) -> tuple[ReviewIssue, ...]:
        preview = self.coordinator.inspect()
        issues: list[ReviewIssue] = []
        rev = preview.baseline_revision

        for decision in preview.plan.decisions:
            path = decision.path
            action = decision.action

            if action is SyncAction.REVIEW_DELETE_REMOTE:
                issues.append(
                    ReviewIssue(
                        "SB-DEL-101",
                        ReviewKind.MISSING_HERE,
                        path,
                        f"{self.here} no longer has '{path}'",
                        f"{self.there} still has the last synchronized copy. "
                        "SyncBridge has NOT recreated or deleted anything.",
                        f"Choose Restore to copy the file back to {self.here}; "
                        "deleting it on both devices is not yet supported.",
                        ("restore",),
                        rev,
                        _signature(decision),
                    )
                )

            elif action is SyncAction.REVIEW_DELETE_LOCAL:
                issues.append(
                    ReviewIssue(
                        "SB-DEL-102",
                        ReviewKind.MISSING_THERE,
                        path,
                        f"{self.there} no longer has '{path}'",
                        f"{self.here} still has the last synchronized copy. "
                        "SyncBridge has NOT recreated or deleted anything.",
                        f"Choose Restore to copy the file back to {self.there}; "
                        "deleting it on both devices is not yet supported.",
                        ("restore",),
                        rev,
                        _signature(decision),
                    )
                )

            elif action is SyncAction.CONFLICT:
                local = decision.local
                remote = decision.remote
                base = decision.base

                if local is None or remote is None:
                    missing = (
                        self.here
                        if local is None
                        else self.there
                    )
                    present = (
                        self.there
                        if local is None
                        else self.here
                    )

                    title = (
                        f"{missing} removed '{path}', "
                        f"but {present} changed it"
                    )
                    code = "SB-CFL-203"
                    options = ()
                    next_step = (
                        "Open the surviving file and decide how to resolve "
                        "it manually. No automatic deletion or overwrite "
                        "is allowed."
                    )

                elif base is None:
                    title = (
                        f"{self.here} and {self.there} have "
                        f"different files named '{path}'"
                    )
                    code = "SB-CFL-202"
                    options = ("keep_both",)
                    next_step = (
                        "Choose Keep Both to preserve each version "
                        "under a different filename, then synchronize."
                    )

                else:
                    title = (
                        f"{self.here} and {self.there} "
                        f"both changed '{path}'"
                    )
                    code = "SB-CFL-201"
                    options = ("keep_both",)
                    next_step = (
                        "Choose Keep Both to preserve each version "
                        "under a different filename, then synchronize."
                    )

                issues.append(
                    ReviewIssue(
                        code,
                        ReviewKind.CONFLICT,
                        path,
                        title,
                        "These versions differ. SyncBridge has protected "
                        "both instead of selecting a winner.",
                        next_step,
                        options,
                        rev,
                        _signature(decision),
                    )
                )

        # A deletion made on both devices is omitted by the planner.
        # It still requires approval before the shared baseline can advance.
        baseline = self.coordinator.shared_state.load(
            self.coordinator.root,
            self.coordinator.peer_node_id,
            self.coordinator.share_id,
        )

        if baseline is not None:
            missing_both = (
                set(baseline.snapshot.files)
                - set(preview.local.files)
                - set(preview.remote.snapshot.files)
            )

            for path in sorted(missing_both):
                issues.append(
                    ReviewIssue(
                        "SB-DEL-103",
                        ReviewKind.DELETED_BOTH,
                        path,
                        f"'{path}' is missing from both "
                        f"{self.here} and {self.there}",
                        "Both copies are absent, but the last shared "
                        "history still includes the file.",
                        "No automatic approval is available yet. "
                        "Restore a copy from a backup or wait for "
                        "the deletion-approval feature.",
                        (),
                        rev,
                        (
                            "both_deleted",
                            _record(
                                baseline.snapshot.files[path]
                            ),
                            None,
                            None,
                        ),
                    )
                )

        return tuple(
            sorted(
                issues,
                key=lambda issue: (
                    issue.path,
                    issue.code,
                ),
            )
        )

    def _fresh(self, issue: ReviewIssue) -> SyncDecision:
        if not isinstance(issue, ReviewIssue):
            raise TypeError(
                "issue must be ReviewIssue"
            )

        preview = self.coordinator.inspect()

        if preview.baseline_revision != issue.baseline_revision:
            raise StaleSyncState(
                "Baseline changed since the issue was reviewed"
            )

        for decision in preview.plan.decisions:
            if (
                decision.path == issue.path
                and _signature(decision) == issue.signature
            ):
                return decision

        raise StaleSyncState(
            "File changed since it was reviewed; refresh the list"
        )

    def restore(self, issue: ReviewIssue) -> ReviewOutcome:
        """Restore only one absent copy, never clobber an existing target."""
        if issue.kind not in (
            ReviewKind.MISSING_HERE,
            ReviewKind.MISSING_THERE,
        ):
            raise ReviewError(
                "Restore is offered only for a one-sided, "
                "unchanged deletion"
            )

        decision = self._fresh(issue)
        peer = self.coordinator.peer_node_id
        host = self.coordinator.host
        port = self.coordinator.transfer_port
        transfer = self.coordinator.transfer_sender
        share = self.coordinator.share_id

        if (
            transfer.share_id != share
            or transfer.destination_root.resolve()
            != self.coordinator.root
        ):
            raise ReviewError(
                "Restore requires the correct approved share-bound receiver"
            )

        if issue.kind is ReviewKind.MISSING_HERE:
            if (
                decision.local is not None
                or decision.remote is None
            ):
                raise StaleSyncState(
                    "Reviewed file no longer matches the restore action"
                )

            result = transfer.fetch_file(
                host,
                port,
                peer,
                share,
                decision.path,
                expected_source_sha256=decision.remote.sha256,
            )
            destination = self.here

        else:
            if (
                decision.local is None
                or decision.remote is not None
            ):
                raise StaleSyncState(
                    "Reviewed file no longer matches the restore action"
                )

            result = transfer.send_file(
                host,
                port,
                peer,
                self.coordinator.root,
                decision.path,
                share_id=share,
            )
            destination = self.there

        expected = (
            decision.remote
            if issue.kind is ReviewKind.MISSING_HERE
            else decision.local
        )

        if not result.completed:
            raise ReviewError(
                "Restore paused. Try the same operation again to resume"
            )

        if (
            result.path != decision.path
            or (result.total, result.sha256)
            != (expected.size, expected.sha256)
        ):
            raise StaleSyncState(
                "Restored contents did not match the reviewed version"
            )

        return ReviewOutcome(
            f"Restored '{decision.path}' on {destination}. "
            "Choose Sync to confirm both computers agree.",
            result,
        )

    def keep_both(self, issue: ReviewIssue) -> ReviewOutcome:
        """Preserve the local version, then conditionally download the remote."""
        if (
            issue.kind is not ReviewKind.CONFLICT
            or "keep_both" not in issue.options
        ):
            raise ReviewError(
                "Keep Both is unavailable for this kind of conflict"
            )

        decision = self._fresh(issue)

        if (
            decision.local is None
            or decision.remote is None
        ):
            raise ReviewError(
                "Both file versions must exist to Keep Both"
            )

        transfer = self.coordinator.transfer_sender
        share = self.coordinator.share_id

        if (
            transfer.share_id != share
            or transfer.destination_root.resolve()
            != self.coordinator.root
            or not transfer.allow_overwrite
        ):
            raise ReviewError(
                "Keep Both requires the correct share-bound receiver "
                "with conditional updates enabled"
            )

        root = self.coordinator.root
        pieces = decision.path.split("/")
        source = root.joinpath(*pieces)

        if source.is_symlink() or not source.is_file():
            raise StaleSyncState(
                "The local conflict file disappeared or became a link"
            )

        parent = source.parent

        if any(
            part.is_symlink()
            for part in (
                root,
                *tuple(source.parents)[:len(pieces)],
            )
        ):
            raise ReviewError(
                "Cannot preserve a conflict through a symbolic link"
            )

        # Stage outside the scanner's visible inventory.
        stage_dir = root / ".syncbridge"

        if (
            stage_dir.is_symlink()
            or (
                stage_dir.exists()
                and not stage_dir.is_dir()
            )
        ):
            raise ReviewError(
                "Unsafe SyncBridge staging directory"
            )

        stage_dir.mkdir(exist_ok=True)

        fd, stage_name = tempfile.mkstemp(
            prefix="review-",
            dir=stage_dir,
        )
        stage = type(root)(stage_name)
        saved = None

        try:
            with (
                source.open("rb") as reader,
                os.fdopen(fd, "wb") as writer,
            ):
                before = os.fstat(reader.fileno())

                if not stat.S_ISREG(before.st_mode):
                    raise ReviewError(
                        "Local conflict source must be a regular file"
                    )

                digest = hashlib.sha256()

                while block := reader.read(1024 * 1024):
                    digest.update(block)
                    writer.write(block)

                writer.flush()
                os.fsync(writer.fileno())

                after = os.fstat(reader.fileno())

                if (
                    (
                        before.st_dev,
                        before.st_ino,
                        before.st_size,
                        before.st_mtime_ns,
                    )
                    != (
                        after.st_dev,
                        after.st_ino,
                        after.st_size,
                        after.st_mtime_ns,
                    )
                    or before.st_size != decision.local.size
                    or digest.hexdigest()
                    != decision.local.sha256
                ):
                    raise StaleSyncState(
                        "Local file changed while preserving "
                        "its conflict copy"
                    )

            suffix = (
                f" (conflict copy "
                f"{decision.local.sha256[:8]})"
            )

            candidate = (
                parent
                / f"{source.stem}{suffix}{source.suffix}"
            )

            if len(
                candidate.name.encode("utf-8")
            ) > 255:
                raise ReviewError(
                    "Filename too long to preserve both versions"
                )

            if (
                candidate.exists()
                or candidate.is_symlink()
            ):
                raise ReviewError(
                    "A preserved conflict copy already exists; "
                    "review it first"
                )

            try:
                # Publish only if no file already occupies that name.
                os.link(stage, candidate)

            except FileExistsError as exc:
                raise ReviewError(
                    "A preserved conflict copy already exists; "
                    "review it first"
                ) from exc

            except OSError as exc:
                raise ReviewError(
                    "Could not safely publish the preserved copy"
                ) from exc

            saved = candidate

        finally:
            stage.unlink(missing_ok=True)

        if saved is None:
            raise ReviewError(
                "Could not preserve the local conflict copy"
            )

        result = transfer.fetch_file(
            self.coordinator.host,
            self.coordinator.transfer_port,
            self.coordinator.peer_node_id,
            share,
            decision.path,
            expected_source_sha256=decision.remote.sha256,
            expected_destination_sha256=decision.local.sha256,
        )

        if not result.completed:
            raise ReviewError(
                "Download paused; local version remains "
                f"saved at '{saved.name}'"
            )

        if (
            result.path != decision.path
            or (result.total, result.sha256)
            != (
                decision.remote.size,
                decision.remote.sha256,
            )
        ):
            raise StaleSyncState(
                "Downloaded version did not match the reviewed conflict"
            )

        return ReviewOutcome(
            f"Both versions preserved. {self.here}'s version "
            f"is now '{saved.name}'; {self.there}'s version "
            f"remains '{decision.path}'. Choose Sync to copy "
            "both filenames to both computers.",
            result,
            saved.relative_to(root).as_posix(),
        )
