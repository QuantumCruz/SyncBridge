
"""Two independent SyncBridge peers with clear reviews and safe repair choices.

Run: python scripts/two_process_demo.py

This demo approves freshly generated, temporary identities only. Real pairing
requires human fingerprint verification. No remote delete operation is offered.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import traceback
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

from syncbridge.core.review import ReviewManager, explain_error, help_for
from syncbridge.network.security import TrustStore, load_or_create_identity
from syncbridge.runtime import SyncBridgeRuntime
from syncbridge.storage.config import AppConfig, ConfigStore, ShareConfig

ROLES = ("alice", "bob")


def profile(session: Path, role: str) -> Path:
    return session / role.capitalize() / "Profile"


def folder(session: Path, role: str) -> Path:
    return session / role.capitalize() / "Shared"


def free_ports(amount: int) -> list[int]:
    ports: list[int] = []

    while len(ports) < amount:
        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
        ) as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]

        if port not in ports:
            ports.append(port)

    return ports


def initialize() -> Path:
    session = Path(
        tempfile.mkdtemp(
            prefix="syncbridge-two-process-"
        )
    ).resolve()

    identities = {}

    for role in ROLES:
        profile(session, role).mkdir(parents=True)
        folder(session, role).mkdir(parents=True)

        identities[role] = load_or_create_identity(
            profile(session, role) / "identity.json"
        )

    share_id = uuid4().hex
    allocation = free_ports(6)

    ports = {
        "alice": allocation[:3],
        "bob": allocation[3:],
    }

    for role in ROLES:
        other = (
            "bob" if role == "alice" else "alice"
        )
        remote_identity = identities[other]

        trust = TrustStore(
            profile(session, role) / "trust.json"
        )

        trust.add_verified(
            remote_identity.public_key_hex,
            confirmed_fingerprint=remote_identity.fingerprint,
            name=f"{other.capitalize()} (demo)",
        )

        store = ConfigStore(
            profile(session, role) / "settings.json"
        )

        rports = ports[other]

        store.save(
            AppConfig(
                device_name=f"{role.capitalize()} (demo)",
                shares=(
                    ShareConfig(
                        share_id=share_id,
                        peer_node_id=remote_identity.node_id,
                        local_root=str(
                            folder(session, role)
                        ),
                        display_name="Demo Shared Folder",
                        remote_host="127.0.0.1",
                        manifest_port=rports[0],
                        transfer_port=rports[1],
                        agreement_port=rports[2],
                        enabled=True,
                        grant_manifest=True,
                        grant_read=True,
                        grant_write=True,
                        grant_agreement=True,
                    ),
                ),
            )
        )

    (
        folder(session, "alice") / "from_alice.txt"
    ).write_text(
        "Hello from Alice!\n",
        encoding="utf-8",
    )

    (
        folder(session, "bob") / "from_bob.txt"
    ).write_text(
        "Hello from Bob!\n",
        encoding="utf-8",
    )

    (
        session / "demo.json"
    ).write_text(
        json.dumps(
            {"local_ports": ports},
            indent=2,
        ),
        encoding="utf-8",
    )

    print(f"Demo session: {session}")
    print(f"Alice: {identities['alice'].node_id}")
    print(f"Bob:   {identities['bob'].node_id}")

    return session


@contextmanager
def cycle_lock(session: Path):
    """Prevent both local demo processes from writing during the same cycle."""
    path = session / "sync-cycle.lock"

    with path.open("a+b", buffering=0) as handle:
        if handle.seek(0, os.SEEK_END) == 0:
            handle.write(b"0")

        handle.seek(0)
        acquired = False

        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(
                    handle.fileno(),
                    msvcrt.LK_NBLCK,
                    1,
                )
            else:
                import fcntl

                fcntl.flock(
                    handle.fileno(),
                    fcntl.LOCK_EX | fcntl.LOCK_NB,
                )

            acquired = True

        except (OSError, BlockingIOError):
            pass

        try:
            yield acquired

        finally:
            if acquired:
                handle.seek(0)

                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(
                        handle.fileno(),
                        msvcrt.LK_UNLCK,
                        1,
                    )
                else:
                    import fcntl

                    fcntl.flock(
                        handle.fileno(),
                        fcntl.LOCK_UN,
                    )


def review_manager(
    runtime: SyncBridgeRuntime,
    role: str,
) -> ReviewManager:
    other = (
        "Bob" if role == "alice" else "Alice"
    )

    return ReviewManager(
        runtime.lifecycle,
        here=role.capitalize(),
        there=other,
    )


def show_issues(manager: ReviewManager):
    issues = manager.list_issues()

    if not issues:
        print(
            "\nNo unresolved conflicts or deletions."
        )
        return issues

    print(
        f"\n{len(issues)} file(s) need your decision:"
    )

    for index, issue in enumerate(issues, 1):
        print(
            f"\n  {index}. "
            f"[{issue.code}] {issue.title}"
        )

        print(
            f"     {issue.explanation}"
        )

        print(
            f"     NEXT: {issue.next_step}"
        )

    return issues


def preview(runtime, manager):
    plan = runtime.lifecycle.run_once().preview.plan
    issues = show_issues(manager)

    issues_paths = {
        item.path for item in issues
    }

    operations = [
        d
        for d in plan.decisions
        if d.path not in issues_paths
    ]

    if operations:
        print(
            "\nFiles ready to be synchronized:"
        )

        for decision in operations:
            if decision.action.value == "upload":
                print(
                    f"  Send '{decision.path}' "
                    "to the other computer"
                )

            elif decision.action.value == "download":
                print(
                    f"  Receive '{decision.path}' "
                    "from the other computer"
                )

    if not operations and not issues:
        print(
            "Both folders are already up to date."
        )

    print(
        "This preview has not changed any files."
    )


def synchronize(runtime, manager):
    report = runtime.lifecycle.run_once(
        apply=True
    )

    print("\n" + "=" * 46)

    for transfer in report.uploaded:
        print(
            f"Sent '{transfer.path}' "
            f"({transfer.total} bytes) "
            "to the other computer."
        )

    for transfer in report.downloaded:
        print(
            f"Received '{transfer.path}' "
            f"({transfer.total} bytes) "
            "from the other computer."
        )

    if report.complete:
        print(
            "SUCCESS: Both computers now agree "
            "on the synchronized files."
        )

        print(
            "Shared history revision: "
            f"{report.checkpoint.baseline.revision}"
        )

    elif report.status.value == "needs_review":
        print(
            "SYNC PAUSED: Some file changes "
            "need your decision. "
            "No conflicting file was overwritten."
        )

        show_issues(manager)

        print(
            "Press 6 to review and resolve supported issues."
        )

    elif report.status.value == "not_converged":
        print(
            "[SB-SYN-500] The folders changed "
            "while syncing. Please try again."
        )

    elif report.status.value == "paused":
        print(
            "Synchronization paused. "
            "No shared history was committed."
        )

    else:
        print(
            f"Sync status: {report.status.value}"
        )

    print("=" * 46)


def resolve(runtime, manager):
    issues = show_issues(manager)

    if not issues:
        return

    answer = input(
        "\nEnter an issue number to see its actions, "
        "or Enter to cancel: "
    ).strip()

    if not answer:
        return

    if (
        not answer.isascii()
        or not answer.isdecimal()
        or not 1 <= int(answer) <= len(issues)
    ):
        print(
            "Please enter a number shown in the review list."
        )
        return

    issue = issues[int(answer) - 1]

    if not issue.options:
        print(
            "No safe automatic resolution is "
            "available for this case yet."
        )

        print(
            "Both computers' existing files "
            "have been left untouched."
        )
        return

    print(
        f"\n[{issue.code}] {issue.title}"
    )

    if "restore" in issue.options:
        print(
            "  [R] Restore the missing copy "
            "from the computer that still has it"
        )

        print(
            "      (does not delete or overwrite "
            "an existing file)"
        )

    if "keep_both" in issue.options:
        print(
            "  [B] Keep BOTH versions "
            "under different filenames"
        )

        print(
            "      (preserves the original local "
            "version before downloading the other)"
        )

    print(
        "  [X] Cancel; leave everything unchanged"
    )

    choice = input(
        "Choose an action: "
    ).strip().lower()

    if (
        choice == "r"
        and "restore" in issue.options
    ):
        print(
            f"To confirm restoring '{issue.path}', "
            "type RESTORE."
        )

        if input(
            "Confirmation: "
        ).strip() == "RESTORE":
            result = manager.restore(issue)
            print("\n" + result.message)

    elif (
        choice == "b"
        and "keep_both" in issue.options
    ):
        print(
            f"To confirm preserving both copies "
            f"of '{issue.path}', type KEEP BOTH."
        )

        if input(
            "Confirmation: "
        ).strip() == "KEEP BOTH":
            result = manager.keep_both(issue)
            print("\n" + result.message)

    else:
        print(
            "No changes made."
        )


def peer_main(role: str, session: Path):
    if role not in ROLES:
        raise ValueError(
            "Unknown peer role"
        )

    manifest = json.loads(
        (
            session / "demo.json"
        ).read_text("utf-8")
    )

    runtime = SyncBridgeRuntime(
        ConfigStore(
            profile(session, role) / "settings.json"
        ),
        bind_address="127.0.0.1",
        listen_ports=tuple(
            manifest["local_ports"][role]
        ),
    )

    try:
        status = runtime.start(
            background=False
        )

        manager = review_manager(
            runtime, role
        )
        shared = folder(
            session, role
        )

        print(
            f"\n========== {role.upper()} =========="
        )
        print(
            f"Process ID: {os.getpid()}"
        )
        print(
            f"Shared folder: {shared}"
        )
        print(
            f"Device identity: {status.node_id}"
        )
        print(
            "Ports: "
            f"{status.manifest_port} "
            f"{status.transfer_port} "
            f"{status.agreement_port}"
        )
        print(
            "Automatic changes: OFF. "
            "You control when to sync."
        )

        if os.name == "nt":
            os.startfile(
                str(shared)
            )

        while True:
            try:
                choice = input(
                    "\n[1] Preview  [2] Sync  "
                    "[3] Open folder  [4] Status "
                    "[5] Help  [6] Review / fix files  "
                    "[7] Explain code  [0] Exit > "
                ).strip()

            except (
                EOFError,
                KeyboardInterrupt,
            ):
                break

            if choice == "0":
                break

            if choice == "3":
                print(shared)

                if os.name == "nt":
                    os.startfile(
                        str(shared)
                    )

                continue

            if choice == "4":
                baseline = runtime.shared_state.load(
                    shared,
                    runtime.coordinator.peer_node_id,
                    runtime.coordinator.share_id,
                )

                print(
                    f"Device: {role.capitalize()}, "
                    f"process {os.getpid()}"
                )
                print(
                    "Last mutually confirmed sync: "
                    f"revision {baseline.revision if baseline else 0}"
                )
                continue

            if choice == "5":
                print(
                    "1: See what would be copied and why files need attention."
                )
                print(
                    "2: Synchronize safe changes. "
                    "Conflicts and deletions require review."
                )
                print(
                    "6: Resolve a missing copy by restoring it, "
                    "or keep both conflicting versions."
                )
                print(
                    "   Choosing a resolution does not delete files. "
                    "Run Sync afterward."
                )
                print(
                    "7: Enter a support code "
                    "(such as SB-DEL-101) for an explanation."
                )
                print(
                    "Only one computer may start a sync "
                    "or resolution at a time."
                )
                continue

            if choice == "7":
                code = input(
                    "Enter support code: "
                ).strip().upper()

                print(
                    f"[{code}] {help_for(code)}"
                )
                continue

            if choice not in {
                "1",
                "2",
                "6",
            }:
                print(
                    "Unknown option. Press 5 for help."
                )
                continue

            try:
                if choice == "1":
                    preview(
                        runtime,
                        manager,
                    )

                else:
                    with cycle_lock(
                        session
                    ) as acquired:
                        if not acquired:
                            print(
                                "The other computer is already "
                                "synchronizing. Wait and try again."
                            )

                        elif choice == "2":
                            synchronize(
                                runtime,
                                manager,
                            )

                        else:
                            resolve(
                                runtime,
                                manager,
                            )

            except Exception as exc:
                code, message, next_step = explain_error(
                    exc
                )

                print(
                    f"\n[{code}] {message}"
                    f"\nNext step: {next_step}"
                )
                print(
                    f"Technical detail: "
                    f"{type(exc).__name__}: {exc}"
                )

                # Full diagnostics remain accessible to developers.
                traceback.print_exc()

    finally:
        runtime.stop()
        print(
            "\nPeer stopped. "
            f"Temporary session retained: {session}"
        )


def main():
    if (
        len(sys.argv) == 4
        and sys.argv[1] == "peer"
    ):
        _, _, role, address = sys.argv

        try:
            peer_main(
                role.lower(),
                type(Path())(address).resolve(strict=True),
            )

        except Exception:
            traceback.print_exc()
            input(
                "Press Enter to close this window..."
            )

        return

    if len(sys.argv) != 1:
        raise SystemExit(
            "Usage: python scripts/two_process_demo.py"
        )

    session = initialize()
    script = str(
        Path(__file__).resolve()
    )

    print(
        "\nCommands to launch the peers manually:"
    )

    for role in (
        "bob",
        "alice",
    ):
        print(
            f'"{sys.executable}" '
            f'"{script}" '
            f'peer {role} "{session}"'
        )

    if os.name == "nt":
        children = []

        try:
            for role in (
                "bob",
                "alice",
            ):
                children.append(
                    subprocess.Popen(
                        [
                            sys.executable,
                            "-u",
                            script,
                            "peer",
                            role,
                            str(session),
                        ],
                        cwd=str(
                            Path(__file__).resolve().parent.parent
                        ),
                        creationflags=subprocess.CREATE_NEW_CONSOLE,
                    )
                )

        except OSError:
            for process in children:
                process.terminate()

            raise

        print(
            "\nTwo peer consoles are opening. "
            "Use option 6 to review issues."
        )

    else:
        print(
            "\nRun those commands in separate terminals."
        )

    print(
        f"Demo session: {session}"
    )


if __name__ == "__main__":
    main()
