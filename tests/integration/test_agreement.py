
"""Localhost baseline agreement integration tests with durable SQLite stores."""

from __future__ import annotations

from uuid import uuid4

import pytest

from syncbridge.core.baseline import BaselineCoordinator
from syncbridge.network.agreement import AgreementClient, AgreementError, AgreementService
from syncbridge.network.security import DeviceIdentity, TrustStore
from syncbridge.storage.shared_state import SharedStateDatabase


@pytest.fixture
def peers(tmp_path):
    a, b = DeviceIdentity.generate(), DeviceIdentity.generate()
    at, bt = TrustStore(tmp_path / 'at.json'), TrustStore(tmp_path / 'bt.json')
    at.add_verified(b.public_key_hex, confirmed_fingerprint=b.fingerprint, name='Bob')
    bt.add_verified(a.public_key_hex, confirmed_fingerprint=a.fingerprint, name='Alice')

    ar, br = tmp_path / 'a', tmp_path / 'b'
    ar.mkdir()
    br.mkdir()

    aid = uuid4().hex
    ad = SharedStateDatabase(tmp_path / 'alice.sqlite')
    bd = SharedStateDatabase(tmp_path / 'bob.sqlite')

    server = AgreementService(
        b, bt, bd, {aid: br}, allowed_peers={aid: [a.node_id]},
        bind_address='127.0.0.1', listen_port=0,
        handshake_timeout=2, io_timeout=3
    )
    client = AgreementClient(a, at, handshake_timeout=2, io_timeout=3)
    server.start()

    def coord():
        return BaselineCoordinator(
            ar, b.node_id, aid, '127.0.0.1', server.bound_port,
            agreement_client=client, shared_state=ad
        )

    try:
        yield a, b, ar, br, aid, ad, bd, server, client, coord
    finally:
        server.stop()


def test_empty_first_agreement_and_repeat_is_noop(peers):
    a, b, ar, br, aid, ad, bd, server, client, coord = peers

    first = coord().checkpoint()

    assert first.newly_committed and not first.recovered_pending
    assert first.baseline.revision == 1
    assert first.baseline.sha256 == bd.load(br, a.node_id, aid).sha256
    assert first.baseline.snapshot.files == {}

    again = coord().checkpoint()

    assert not again.newly_committed and again.baseline.revision == 1
    assert ad.pending(ar, b.node_id, aid) is None


def test_identical_files_checkpoint_and_revision_advances(peers):
    a, b, ar, br, aid, ad, bd, server, client, coord = peers

    for folder in (ar, br):
        (folder / 'nested').mkdir()
        (folder / 'nested' / 'file.txt').write_text('First')

    assert coord().checkpoint().baseline.revision == 1

    for folder in (ar, br):
        (folder / 'nested' / 'file.txt').write_text('Second')

    second = coord().checkpoint()

    assert second.baseline.revision == 2
    assert second.baseline.sha256 == bd.load(br, a.node_id, aid).sha256


def test_different_folders_refused_without_staging_remote(peers):
    a, b, ar, br, aid, ad, bd, server, client, coord = peers

    (ar / 'only-a.txt').write_text('A')

    with pytest.raises(AgreementError, match='inventory differs'):
        coord().checkpoint()

    assert ad.pending(ar, b.node_id, aid) is not None
    assert bd.pending(br, a.node_id, aid) is None
    assert bd.load(br, a.node_id, aid) is None


def test_fail_then_correct_files_and_retry_same_proposal(peers):
    a, b, ar, br, aid, ad, bd, server, client, coord = peers

    (ar / 'x').write_text('same')

    with pytest.raises(AgreementError, match='inventory differs'):
        coord().checkpoint()

    prior = ad.pending(ar, b.node_id, aid).proposal_id

    (br / 'x').write_text('same')

    recovered = coord().checkpoint()

    assert recovered.recovered_pending
    assert recovered.baseline.revision == 1
    assert bd.load(br, a.node_id, aid).revision == 1
    assert ad.pending(ar, b.node_id, aid) is None


def test_post_remote_commit_response_lost_recovered(peers, monkeypatch):
    a, b, ar, br, aid, ad, bd, server, client, coord = peers

    for root in (ar, br):
        (root / 'x').write_text('agreed')

    original = client.commit

    def drop(*args, **kwargs):
        original(*args, **kwargs)
        raise AgreementError('Connection lost after remote commit')

    monkeypatch.setattr(client, 'commit', drop)

    with pytest.raises(AgreementError, match='Connection lost'):
        coord().checkpoint()

    assert bd.load(br, a.node_id, aid).revision == 1
    assert ad.load(ar, b.node_id, aid) is None
    assert ad.pending(ar, b.node_id, aid) is not None

    monkeypatch.setattr(client, 'commit', original)

    recovered = coord().checkpoint()

    assert recovered.recovered_pending and recovered.baseline.revision == 1
    assert ad.pending(ar, b.node_id, aid) is None


def test_changes_after_remote_commit_block_local_finalize(peers, monkeypatch):
    a, b, ar, br, aid, ad, bd, server, client, coord = peers

    for root in (ar, br):
        (root / 'x').write_text('same')

    original = client.commit

    def update_after_commit(*args, **kwargs):
        result = original(*args, **kwargs)
        (ar / 'x').write_text('local edit after commit')
        return result

    monkeypatch.setattr(client, 'commit', update_after_commit)

    with pytest.raises(AgreementError, match='Local folder changed'):
        coord().checkpoint()

    assert bd.load(br, a.node_id, aid).revision == 1
    assert ad.load(ar, b.node_id, aid) is None
    assert ad.pending(ar, b.node_id, aid) is not None

    monkeypatch.setattr(client, 'commit', original)

    with pytest.raises(AgreementError, match='no longer matches'):
        coord().checkpoint()

    (ar / 'x').write_text('same')

    assert coord().checkpoint().baseline.revision == 1


def test_revoked_peer_blocked(peers):
    a, b, ar, br, aid, ad, bd, server, client, coord = peers

    server.revoke_peer(aid, a.node_id)

    with pytest.raises(AgreementError, match='not authorized'):
        coord().checkpoint()

    assert ad.load(ar, b.node_id, aid) is None

    server.authorize_peer(aid, a.node_id)

    assert coord().checkpoint().baseline.revision == 1


def test_unpaired_peer_blocked(peers):
    a, b, ar, br, aid, ad, bd, server, client, coord = peers

    client.trust_store.remove(b.node_id)

    with pytest.raises(AgreementError):
        coord().checkpoint()

    assert bd.load(br, a.node_id, aid) is None


def test_abort_before_commit_on_both_sides(peers):
    a, b, ar, br, aid, ad, bd, server, client, coord = peers

    (ar / 'x').write_text('a')

    with pytest.raises(AgreementError):
        coord().checkpoint()

    assert coord().abort_uncommitted()
    assert not coord().abort_uncommitted()
    assert ad.pending(ar, b.node_id, aid) is None

    (br / 'x').write_text('a')

    assert coord().checkpoint().baseline.revision == 1


def test_abort_after_remote_commit_is_refused(peers, monkeypatch):
    a, b, ar, br, aid, ad, bd, server, client, coord = peers

    original = client.commit

    def drop(*args, **kwargs):
        original(*args, **kwargs)
        raise AgreementError('Reply lost')

    monkeypatch.setattr(client, 'commit', drop)

    with pytest.raises(AgreementError, match='Reply lost'):
        coord().checkpoint()

    assert bd.load(br, a.node_id, aid).revision == 1

    with pytest.raises(AgreementError, match='Cannot abort'):
        coord().abort_uncommitted()

    assert ad.pending(ar, b.node_id, aid) is not None


def test_abort_remote_prepared_proposal(peers):
    a, b, ar, br, aid, ad, bd, server, client, coord = peers

    (ar / 'x').write_text('same')
    (br / 'x').write_text('same')

    original = client.commit

    def fail(*args, **kwargs):
        raise AgreementError('Commit call unavailable')

    client.commit = fail

    with pytest.raises(AgreementError, match='unavailable'):
        coord().checkpoint()

    assert bd.pending(br, a.node_id, aid) is not None
    assert coord().abort_uncommitted()
    assert bd.pending(br, a.node_id, aid) is None
    assert ad.pending(ar, b.node_id, aid) is None

    client.commit = original

    assert coord().checkpoint().baseline.revision == 1


def test_remote_baseline_revision_different_blocks_checkpoint(peers):
    a, b, ar, br, aid, ad, bd, server, client, coord = peers

    assert coord().checkpoint().baseline.revision == 1

    for root in (ar, br):
        (root / 'x').write_text('new')

    from syncbridge.core.scanner import FileScanner

    snapshot = FileScanner(br).scan()
    proposal = bd.stage(br, a.node_id, aid, snapshot, expected_revision=1)

    bd.confirm_local(br, a.node_id, aid, proposal.proposal_id, snapshot)
    bd.confirm_remote(
        br, a.node_id, aid, proposal.proposal_id,
        authenticated_peer_id=a.node_id, acknowledged_sha256=proposal.sha256
    )
    bd.finalize(br, a.node_id, aid, proposal.proposal_id, snapshot)

    with pytest.raises(AgreementError, match='revisions differ'):
        coord().checkpoint()

    assert ad.load(ar, b.node_id, aid).revision == 1


def test_remote_pending_other_proposal_blocks(peers):
    a, b, ar, br, aid, ad, bd, server, client, coord = peers

    from syncbridge.core.scanner import FileScanner

    snapshot = FileScanner(br).scan()
    bd.stage(br, a.node_id, aid, snapshot, expected_revision=0)

    with pytest.raises(AgreementError, match='unresolved'):
        coord().checkpoint()

    assert ad.pending(ar, b.node_id, aid) is None


def test_status_reflects_pending_and_committed(peers):
    a, b, ar, br, aid, ad, bd, server, client, coord = peers

    status = client.status('127.0.0.1', server.bound_port, b.node_id, aid)

    assert status.revision == 0
    assert status.sha256 is None
    assert status.pending_id is None

    result = coord().checkpoint()
    status = client.status('127.0.0.1', server.bound_port, b.node_id, aid)

    assert status.revision == 1
    assert status.sha256 == result.baseline.sha256


def test_wrong_share_refused(peers):
    a, b, ar, br, aid, ad, bd, server, client, coord = peers

    with pytest.raises(AgreementError, match='not authorized'):
        client.status('127.0.0.1', server.bound_port, b.node_id, uuid4().hex)


def test_stopping_and_restarting_server(peers):
    a, b, ar, br, aid, ad, bd, server, client, coord = peers

    server.stop()
    server.start()

    assert coord().checkpoint().baseline.revision == 1


def test_refuse_invalid_ids_and_ports(peers):
    a, b, ar, br, aid, ad, bd, server, client, coord = peers

    with pytest.raises(ValueError):
        client.status('127.0.0.1', True, b.node_id, aid)

    with pytest.raises(ValueError):
        client.status('invalid', 1234, b.node_id, aid)

    with pytest.raises(ValueError):
        client.status('127.0.0.1', 1234, 'bad', aid)


def test_existing_baseline_noop_requires_remote_current_inventory(peers):
    a, b, ar, br, aid, ad, bd, server, client, coord = peers

    assert coord().checkpoint().baseline.revision == 1

    (br / 'new-remote').write_text('remote changed after checkpoint')

    with pytest.raises(AgreementError, match='Remote live inventory differs'):
        coord().checkpoint()

    assert ad.load(ar, b.node_id, aid).revision == 1
    assert bd.load(br, a.node_id, aid).revision == 1
