
"""Local, owner-controlled recovery center for SyncBridge.

Usage:
    python scripts/recovery_center.py "C:\\path\\to\\Alice\\Profile"

With no argument, open the default SyncBridge user profile. The app must
be closed while restoring. Restored files are NEW local changes: review
the next sync before applying them to another device.
"""
from __future__ import annotations

import sys
from pathlib import Path

from syncbridge.core.recovery_center import (
    RecoveryCenter,
    RecoveryCenterError,
)
from syncbridge.storage.config import ConfigStore


def main() -> int:
    if len(sys.argv) > 2:
        print(
            'Usage: python scripts/recovery_center.py '
            '["PROFILE_FOLDER"]'
        )
        return 2

    try:
        profile = (
            Path(sys.argv[1]).expanduser()
            if len(sys.argv) == 2
            else ConfigStore().path.parent
        )

        settings = ConfigStore(
            profile / "settings.json"
        ).load()

        enabled = [
            item
            for item in settings.shares
            if item.enabled
        ]

        if len(enabled) != 1:
            print(
                "Recovery needs exactly one enabled shared "
                "folder in this profile. "
                "No files have been changed."
            )
            return 1

        center = RecoveryCenter(
            profile,
            enabled[0].local_root,
        )

    except (
        OSError,
        ValueError,
        RuntimeError,
    ) as exc:
        print(
            f"Cannot open recovery information: {exc}"
        )
        return 1

    print("\n=== SYNCBRIDGE FILE RECOVERY ===")
    print(
        f"This computer's folder: {center.root}"
    )
    print(
        f"Private recovery storage: "
        f"{center.vault.directory}"
    )
    print(
        "Restoring never overwrites a file "
        "and never deletes your backup."
    )

    while True:
        items = center.list_items()

        if not items:
            print(
                "\nThere are no recorded recovery copies "
                "in this profile."
            )
            return 0

        print("\nRecovery records:")

        for index, item in enumerate(items, 1):
            print(
                f"\n  {index}. {item.path}"
            )
            print(
                f"     [{item.code}] {item.message}"
            )

            if item.size is not None:
                print(
                    f"     Original size: "
                    f"{item.size:,} bytes"
                )

            print(
                "     Action: Restore file"
                if item.can_restore
                else "     Action: Cannot safely restore automatically"
            )

        try:
            choice = input(
                "\nEnter a number to restore, "
                "R to refresh, or 0 to exit: "
            ).strip()

        except (
            EOFError,
            KeyboardInterrupt,
        ):
            print(
                "\nRecovery closed. No files changed."
            )
            return 0

        if choice == "0":
            return 0

        if choice.lower() == "r":
            continue

        if (
            not choice.isascii()
            or not choice.isdecimal()
        ):
            print(
                "Enter a listed number, R, or 0."
            )
            continue

        number = int(choice)

        if not 1 <= number <= len(items):
            print(
                "That number is not on the list."
            )
            continue

        selected = items[number - 1]

        if not selected.can_restore:
            print(
                f"[{selected.code}] This copy cannot "
                "be restored automatically."
            )
            continue

        print(
            f"\nRestore '{selected.path}' "
            "to THIS computer?"
        )
        print(
            "This is a new local change. "
            "On your next synchronization, the file "
            "may also be copied to the paired computer."
        )

        try:
            confirmed = input(
                "Type RESTORE to confirm: "
            ).strip()

        except (
            EOFError,
            KeyboardInterrupt,
        ):
            return 0

        if confirmed != "RESTORE":
            print(
                "Cancelled. No files changed."
            )
            continue

        try:
            restored = center.restore(
                selected.request_id
            )

        except RecoveryCenterError as exc:
            print(
                f"\nRestoration stopped: {exc}"
            )

        else:
            print(
                f"\nSUCCESS: Restored to {restored}"
            )
            print(
                "The private recovery copy has been kept."
            )
            print(
                "Review the next synchronization "
                "before applying changes."
            )


if __name__ == "__main__":
    raise SystemExit(main())
