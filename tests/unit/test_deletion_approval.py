
"""Authenticated cross-device deletion-consent tests.

Requests and approvals must not delete files or advance shared baselines.
"""
from __future__ import annotations

from uuid import uuid4

import pytest

from syncbridge.core.scanner import FileScanner
from syncbridge.network.deletion_approval import (
    DeletionApprovalClient,
    DeletionApprovalError,
    DeletionApprovalService,
    DeletionApprovalStore,
    describe_status,
)
from syncbridge.network.security import (
    DeviceIdentity,
    TrustStore,
)
from syncbridge.storage.shared_state import (
    SharedStateDatabase,
)


@pytest.fixture
def pair(tmp_path):
    alice = DeviceIdentity.generate()
    bob = DeviceIdentity.generate()

    at = TrustStore(tmp_path / "at.json")
    bt = TrustStore(tmp_path / "bt.json")

    at.add_verified(
        bob.public_key_hex,
        confirmed_fingerprint=bob.fingerprint,
        name="Bob",
    )
    bt.add_verified(
        alice.public_key_hex,
        confirmed_fingerprint=alice.fingerprint,
        name="Alice",
    )

    ar = tmp_path / "Alice"
    br = tmp_path / "Bob"
    ar.mkdir()
    br.mkdir()

    for root in (ar, br):
        (root / "document.txt").write_text(
            "Important document",
            encoding="utf-8",
        )

    share = uuid4().hex

    ad = SharedStateDatabase(
        tmp_path / "ad.sqlite"
    )
    bd = SharedStateDatabase(
        tmp_path / "bd.sqlite"
    )

    for root, db, peer in (
        (ar, ad, bob.node_id),
        (br, bd, alice.node_id),
    ):
        snapshot = FileScanner(root).scan()

        proposal = db.stage(
            root,
            peer,
            share,
            snapshot,
            expected_revision=0,
        )

        db.confirm_local(
            root,
            peer,
            share,
            proposal.proposal_id,
            snapshot,
        )

        db.confirm_remote(
            root,
            peer,
            share,
            proposal.proposal_id,
            authenticated_peer_id=peer,
            acknowledged_sha256=proposal.sha256,
        )

        db.finalize(
            root,
            peer,
            share,
            proposal.proposal_id,
            snapshot,
        )

    # Bob expresses deletion intent. Alice retains the last agreed copy.
    (br / "document.txt").unlink()

    inbox = DeletionApprovalStore(
        tmp_path / "deletions.sqlite"
    )

    service = DeletionApprovalService(
        alice,
        at,
        ad,
        inbox,
        {share: ar},
        allowed_requesters={
            share: [bob.node_id]
        },
        bind_address="127.0.0.1",
        listen_port=0,
        handshake_timeout=2,
        io_timeout=3,
    )

    client = DeletionApprovalClient(
        bob,
        bt,
        handshake_timeout=2,
        io_timeout=3,
    )

    service.start()

    try:
        yield (
            alice,
            bob,
            ar,
            br,
            share,
            ad,
            bd,
            inbox,
            service,
            client,
        )
    finally:
        service.stop()


def request(
    pair,
    *,
    request_id=None,
    path="document.txt",
    revision=None,
    baseline_hash=None,
    file_hash=None,
    size=None,
    share=None,
):
    (
        alice, bob, ar, br,
        pair_share, ad, bd,
        inbox, service, client,
    ) = pair

    base = bd.load(
        br,
        alice.node_id,
        pair_share,
    )

    old = base.snapshot.files[
        "document.txt"
    ]

    return client.request(
        "127.0.0.1",
        service.bound_port,
        alice.node_id,
        pair_share if share is None else share,
        path,
        baseline_revision=(
            base.revision
            if revision is None
            else revision
        ),
        baseline_sha256=(
            base.sha256
            if baseline_hash is None
            else baseline_hash
        ),
        file_sha256=(
            old.sha256
            if file_hash is None
            else file_hash
        ),
        file_size=(
            old.size
            if size is None
            else size
        ),
        request_id=request_id,
    )


def test_request_creates_pending_inbox_without_deleting_file(pair):
    alice, bob, ar, br, share, ad, bd, inbox, service, client = pair

    rid, state = request(pair)

    assert state == "pending"

    item, = service.incoming(
        share,
        bob.node_id,
    )

    assert item.request_id == rid
    assert item.path == "document.txt"
    assert item.state == "pending"

    assert (
        ar / "document.txt"
    ).read_text() == "Important document"

    assert bd.load(
        br, alice.node_id, share
    ).revision == 1


def test_approval_is_local_and_does_not_delete_anything(pair):
    alice, bob, ar, br, share, ad, bd, inbox, service, client = pair

    rid, state = request(pair)

    assert client.status(
        "127.0.0.1",
        service.bound_port,
        alice.node_id,
        share,
        rid,
    ) == "pending"

    approved = service.decide(
        share,
        bob.node_id,
        rid,
        approve=True,
    )

    assert approved.state == "approved"

    assert client.status(
        "127.0.0.1",
        service.bound_port,
        alice.node_id,
        share,
        rid,
    ) == "approved"

    assert (ar / "document.txt").exists()
    assert not (br / "document.txt").exists()

    assert ad.load(
        ar, bob.node_id, share
    ).revision == 1


def test_decline_is_reported_and_keeps_original_file(pair):
    alice, bob, ar, br, share, ad, bd, inbox, service, client = pair

    rid, _ = request(pair)

    assert service.decide(
        share,
        bob.node_id,
        rid,
        approve=False,
    ).state == "declined"

    assert client.status(
        "127.0.0.1",
        service.bound_port,
        alice.node_id,
        share,
        rid,
    ) == "declined"

    assert (ar / "document.txt").exists()

    with pytest.raises(
        DeletionApprovalError,
        match="already decided",
    ):
        service.decide(
            share, bob.node_id, rid, approve=True
        )


def test_approved_request_stale_if_file_changes_after_consent(pair):
    alice, bob, ar, br, share, ad, bd, inbox, service, client = pair

    rid, _ = request(pair)

    service.decide(
        share, bob.node_id, rid, approve=True
    )

    (ar / "document.txt").write_text(
        "Alice edited it again"
    )

    assert client.status(
        "127.0.0.1",
        service.bound_port,
        alice.node_id,
        share,
        rid,
    ) == "stale"

    assert (
        ar / "document.txt"
    ).read_text() == "Alice edited it again"


def test_approval_rejected_if_file_changed_before_review(pair):
    alice, bob, ar, br, share, ad, bd, inbox, service, client = pair

    rid, _ = request(pair)

    (ar / "document.txt").write_text("New edit")

    with pytest.raises(
        DeletionApprovalError,
        match="removed or edited",
    ):
        service.decide(
            share, bob.node_id, rid, approve=True
        )

    assert service.incoming(
        share, bob.node_id
    )[0].state == "pending"


def test_request_denied_when_original_file_changed(pair):
    alice, bob, ar, br, share, ad, bd, inbox, service, client = pair

    (ar / "document.txt").write_text(
        "Unexpected modification"
    )

    with pytest.raises(
        DeletionApprovalError,
        match="removed or edited",
    ):
        request(pair)

    assert service.incoming(
        share, bob.node_id
    ) == ()


def test_wrong_baseline_revision_rejected(pair):
    with pytest.raises(
        DeletionApprovalError,
        match="history changed",
    ):
        request(
            pair,
            revision=2,
        )


def test_wrong_baseline_digest_rejected(pair):
    with pytest.raises(
        DeletionApprovalError,
        match="history changed",
    ):
        request(
            pair,
            baseline_hash="f" * 64,
        )


def test_bad_file_sha_rejected(pair):
    with pytest.raises(
        DeletionApprovalError,
        match="not part",
    ):
        request(
            pair,
            file_hash="f" * 64,
        )


def test_bad_file_size_rejected(pair):
    with pytest.raises(
        DeletionApprovalError,
        match="not part",
    ):
        request(
            pair,
            size=1,
        )


def test_unknown_share_and_revoked_access_refused(pair):
    alice, bob, ar, br, share, ad, bd, inbox, service, client = pair

    with pytest.raises(
        DeletionApprovalError,
        match="permission",
    ):
        request(
            pair,
            share=uuid4().hex,
        )

    service.revoke_requester(
        share,
        bob.node_id,
    )

    with pytest.raises(
        DeletionApprovalError,
        match="permission",
    ):
        request(pair)

    service.authorize_requester(
        share,
        bob.node_id,
    )

    assert request(pair)[1] == "pending"


def test_unknown_request_id_is_not_disclosed(pair):
    alice, bob, ar, br, share, ad, bd, inbox, service, client = pair

    request(pair)

    with pytest.raises(
        DeletionApprovalError,
        match="not found",
    ):
        client.status(
            "127.0.0.1",
            service.bound_port,
            alice.node_id,
            share,
            uuid4().hex,
        )


def test_request_idempotent_and_persistent_after_server_restart(pair):
    alice, bob, ar, br, share, ad, bd, inbox, service, client = pair

    rid = uuid4().hex

    assert request(
        pair,
        request_id=rid,
    ) == (rid, "pending")

    assert request(
        pair,
        request_id=rid,
    ) == (rid, "pending")

    service.stop()
    service.start()

    assert service.incoming(
        share, bob.node_id
    )[0].request_id == rid

    assert client.status(
        "127.0.0.1",
        service.bound_port,
        alice.node_id,
        share,
        rid,
    ) == "pending"


def test_reused_id_with_new_details_rejected(pair):
    alice, bob, ar, br, share, ad, bd, inbox, service, client = pair

    rid, _ = request(pair)

    with pytest.raises(
        DeletionApprovalError,
        match="different",
    ):
        inbox.submit(
            ar,
            bob.node_id,
            share,
            rid,
            "other.txt",
            1,
            ad.load(
                ar, bob.node_id, share
            ).sha256,
            "a" * 64,
            1,
        )


def test_approving_unknown_id_and_peer_refused(pair):
    alice, bob, ar, br, share, ad, bd, inbox, service, client = pair

    rid, _ = request(pair)

    with pytest.raises(
        DeletionApprovalError,
        match="not found",
    ):
        service.decide(
            share,
            bob.node_id,
            uuid4().hex,
            approve=True,
        )

    with pytest.raises(
        DeletionApprovalError,
        match="permission",
    ):
        service.decide(
            share,
            uuid4().hex,
            rid,
            approve=True,
        )


def test_request_rejects_unsafe_paths(pair):
    for path in (
        "../document.txt",
        "a\\b",
        ".syncbridge/secret",
        "CON.txt",
    ):
        with pytest.raises(ValueError):
            request(
                pair,
                path=path,
            )


def test_no_baseline_cannot_request_deletion(pair):
    alice, bob, ar, br, share, ad, bd, inbox, service, client = pair

    different = uuid4().hex

    service._shares[different] = ar
    service._allowed[different] = {
        bob.node_id
    }

    with pytest.raises(
        DeletionApprovalError,
        match="history changed",
    ):
        request(
            pair,
            share=different,
        )


def test_invalid_ports_and_ids_fail_without_contact(pair):
    alice, bob, ar, br, share, ad, bd, inbox, service, client = pair

    with pytest.raises(ValueError):
        client.status(
            "127.0.0.1",
            True,
            alice.node_id,
            share,
            uuid4().hex,
        )

    with pytest.raises(ValueError):
        client.status(
            "invalid",
            45845,
            alice.node_id,
            share,
            uuid4().hex,
        )

    with pytest.raises(ValueError):
        client.status(
            "127.0.0.1",
            service.bound_port,
            "bad",
            share,
            uuid4().hex,
        )


def test_unpaired_client_refused(pair):
    alice, bob, ar, br, share, ad, bd, inbox, service, client = pair

    client.trust_store.remove(
        alice.node_id
    )

    with pytest.raises(
        DeletionApprovalError
    ):
        request(pair)

    assert service.incoming(
        share, bob.node_id
    ) == ()


def test_requests_do_not_advance_or_stage_baselines(pair):
    alice, bob, ar, br, share, ad, bd, inbox, service, client = pair

    rid, _ = request(pair)

    service.decide(
        share,
        bob.node_id,
        rid,
        approve=True,
    )

    assert ad.load(
        ar, bob.node_id, share
    ).revision == 1

    assert bd.load(
        br, alice.node_id, share
    ).revision == 1

    assert ad.pending(
        ar, bob.node_id, share
    ) is None

    assert bd.pending(
        br, alice.node_id, share
    ) is None


def test_status_explanations_have_specific_codes():
    assert describe_status(
        "pending",
        "Alice",
    ).code == "SB-DEL-104"

    assert "Alice" in describe_status(
        "pending",
        "Alice",
    ).next_step

    assert describe_status(
        "approved",
        "Alice",
    ).code == "SB-DEL-107"

    assert "NOT deleted" in describe_status(
        "approved",
        "Alice",
    ).explanation

    assert describe_status(
        "declined",
        "Bob",
    ).code == "SB-DEL-105"

    assert describe_status(
        "stale",
        "Bob",
    ).code == "SB-DEL-106"

    with pytest.raises(ValueError):
        describe_status(
            "unknown",
            "Bob",
        )


def test_approval_database_cannot_be_synchronized(pair):
    alice, bob, ar, br, share, ad, bd, inbox, service, client = pair

    bad_store = DeletionApprovalStore(
        ar / "requests.sqlite"
    )

    with pytest.raises(
        ValueError,
        match="outside synchronized",
    ):
        DeletionApprovalService(
            alice,
            service.trust_store,
            ad,
            bad_store,
            {share: ar},
        )
