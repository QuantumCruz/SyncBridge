# SyncBridge

> **Discontinued / archived project.** SyncBridge is no longer under active development. This repository is preserved as a record of its implementation, tests, and engineering lessons. It is not recommended for production file synchronization.

## What it aimed to do

SyncBridge was a Python-based Windows desktop project intended to synchronize folders between two computers over local networks and compatible private network overlays, without relying on a paid always-on relay. The intended user experience was simple: open the application on both machines, pair, choose folders, and let synchronization happen automatically.

## What worked

Development produced substantial automated coverage of storage, change detection, transfer coordination, and recovery scenarios. Local pairing and selected integration tests worked, including tests for interrupted transfers and restart behavior.

These successes did **not** establish reliable, intuitive end-to-end synchronization between ordinary users' computers.

## Why development stopped

Real-world desktop testing exposed a gap between passing component tests and a trustworthy product. Connection and pairing states were difficult to understand, and seeing or browsing remote files was not the same as having seamless automatic folder synchronization. The application accumulated too much complexity relative to its central promise: two people should be able to pair and synchronize without troubleshooting the internal protocol.

Rather than continue presenting an unfinished synchronization product as ready for users, development was discontinued.

## Engineering lessons

- Passing unit and integration tests does not replace real-device, end-to-end acceptance testing.
- A successful network connection is not equivalent to successful synchronization.
- User-visible state should describe what the application has actually accomplished, not only what the protocol thinks is happening.
- Reliable synchronization requires careful conflict handling, recovery, identity, and filesystem semantics.
- Architecture should be validated against the simplest complete user journey early, before accumulating additional features.

## Status and installation

**Status:** discontinued. No further releases or maintenance are planned.

The repository's `pyproject.toml` is currently empty. This project should **not** be treated as an installable or supported Python package. The historical source and tests are retained for reference.

## Postmortem

The central failure was one of product integration and usability, not simply a missing networking feature. Engineering effort went into individually testable subsystems, while the essential user promise—pair two computers and reliably synchronize selected folders with minimal interaction—remained inconsistent in practice.

Future projects should establish an early acceptance test with two clean machines, explicit proof of automatic synchronization in both directions, and predictable behavior after interruption. Those tests should guide architecture before feature expansion.

## License

MIT License. See [LICENSE](LICENSE).
