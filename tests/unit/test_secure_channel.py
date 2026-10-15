
import json
import os
import socket
import struct
import threading
import time

import pytest

from syncbridge.network.security import AuthenticationError, DeviceIdentity, TrustStore
from syncbridge.network.secure_channel import (
    SecureSocket, open_secure_channel, accept_secure_channel,
)


def paired(tmp_path):
    a, b = DeviceIdentity.generate(), DeviceIdentity.generate()
    a_store = TrustStore(tmp_path / "alice-trust.json")
    b_store = TrustStore(tmp_path / "bob-trust.json")
    a_store.add_verified(b.public_key_hex, confirmed_fingerprint=b.fingerprint, name='B')
    b_store.add_verified(a.public_key_hex, confirmed_fingerprint=a.fingerprint, name='A')
    return a, b, a_store, b_store


def channels(a, b, a_store, b_store):
    left, right = socket.socketpair()
    server = []
    errors = []
    def serve():
        try:
            server.append(accept_secure_channel(right,b,b_store, timeout=1))
        except BaseException as exc:
            errors.append(exc)
    t=threading.Thread(target=serve)
    t.start()
    try:
        client=open_secure_channel(left,a,a_store,b.node_id,timeout=1)
    finally:
        t.join(2)
    assert not errors
    assert len(server)==1
    return client,server[0],left,right


def test_bidirectional_encrypt_stream_multiple_records(tmp_path):
    a,b,a_store,b_store=paired(tmp_path)
    (client, peer_b),(server,peer_a),left,right=channels(a,b,a_store,b_store)
    try:
        assert peer_b.node_id == b.node_id
        assert peer_a.node_id == a.node_id
        content=os.urandom(150000)
        sending_errors=[]
        def send_large():
            try:
                client.sendall(content)
            except Exception as exc:
                sending_errors.append(exc)
        sender=threading.Thread(target=send_large)
        sender.start()
        received=bytearray()
        while len(received)<len(content):
            received.extend(server.recv(9991))
        sender.join(2)
        assert not sender.is_alive()
        assert not sending_errors
        assert received==content
        reply=b'hello world'*123
        server.sendall(reply)
        assert client.recv(17)==reply[:17]
        assert client.recv(len(reply))==reply[17:]
    finally:
        client.close(); server.close()


def test_separate_sessions_have_independent_counters(tmp_path):
    a,b,x,y=paired(tmp_path)
    (c1,_),(s1,_),_,_=channels(a,b,x,y)
    (c2,_),(s2,_),_,_=channels(a,b,x,y)
    try:
        assert c1._send_seq==c2._send_seq==0
        c1.sendall(b"first")
        assert s1.recv(5) == b"first"
        assert c1._send_seq==1 and c2._send_seq==0
        c2.sendall(b"second")
        assert s2.recv(6) == b"second"
    finally:
        for sock in (c1,s1,c2,s2): sock.close()


def test_unpaired_local_refused_without_network_io(tmp_path):
    a,b,x,y=paired(tmp_path)
    x.remove(b.node_id)
    left,right=socket.socketpair()
    try:
        with pytest.raises(AuthenticationError,match='not paired'):
            open_secure_channel(left,a,x,b.node_id)
    finally:
        left.close(); right.close()


def test_unpaired_remote_rejects(tmp_path):
    a,b,x,y=paired(tmp_path)
    y.remove(a.node_id)
    left,right=socket.socketpair()
    errors=[]
    def serve():
        try: accept_secure_channel(right,b,y,timeout=.3)
        except Exception as exc: errors.append(exc)
        finally: right.close()
    t=threading.Thread(target=serve); t.start()
    try:
        with pytest.raises(AuthenticationError): open_secure_channel(left,a,x,b.node_id,timeout=.3)
    finally:
        left.close(); t.join(1)
    assert len(errors)==1


def test_fake_remote_rejected_even_if_knows_b_public_key(tmp_path):
    a,b,x,y=paired(tmp_path)
    fake=DeviceIdentity.generate()
    left,right=socket.socketpair()
    errors=[]
    def serve():
        try: accept_secure_channel(right,fake,y,timeout=.3)
        except Exception as exc: errors.append(exc)
        finally: right.close()
    t=threading.Thread(target=serve); t.start()
    try:
        with pytest.raises(AuthenticationError,match='differs'):
            open_secure_channel(left,a,x,b.node_id,timeout=.3)
    finally:
        left.close(); t.join(1)


def test_tampered_ciphertext_closes_stream(tmp_path):
    a,b,x,y=paired(tmp_path)
    (c,_),(s,_),left,right=channels(a,b,x,y)
    try:
        raw=os.urandom(32)
        right.sendall(struct.pack('!I',len(raw))+raw)
        with pytest.raises(OSError,match='tampered'):
            c.recv(1)
        assert c.fileno()==-1
    finally:
        c.close(); s.close()


def test_oversized_record_rejected_before_payload_read(tmp_path):
    a,b,x,y=paired(tmp_path)
    (c,_),(s,_),left,right=channels(a,b,x,y)
    try:
        right.sendall(struct.pack('!I', 999999))
        with pytest.raises(OSError): c.recv(1)
    finally:
        c.close(); s.close()


def test_clean_eof_returns_empty(tmp_path):
    a,b,x,y=paired(tmp_path)
    (c,_),(s,_),left,right=channels(a,b,x,y)
    s.close()
    try: assert c.recv(2)==b''
    finally: c.close()


def test_timeout_is_restored_after_handshake(tmp_path):
    a,b,x,y=paired(tmp_path)
    left,right=socket.socketpair()
    left.settimeout(2); right.settimeout(2)
    worker=[]
    t=threading.Thread(target=lambda:worker.append(accept_secure_channel(right,b,y,timeout=1)))
    t.start()
    try:
        client,_=open_secure_channel(left,a,x,b.node_id,timeout=1)
        t.join(2)
        assert client.gettimeout()==2
        assert worker[0][0].gettimeout()==2
    finally:
        left.close(); right.close(); t.join(2)


def test_failed_bad_timeout_does_not_modify_socket(tmp_path):
    a,b,x,y=paired(tmp_path)
    left,right=socket.socketpair()
    try:
        for value in (0,-1,float('nan'),float('inf'),True):
            with pytest.raises(ValueError): open_secure_channel(left,a,x,b.node_id,timeout=value)
            with pytest.raises(ValueError): accept_secure_channel(right,b,y,timeout=value)
    finally:
        left.close(); right.close()


def test_empty_sendall_no_record(tmp_path):
    a,b,x,y=paired(tmp_path)
    (c,_),(s,_),_,_=channels(a,b,x,y)
    try:
        c.sendall(b'')
        assert c._send_seq==0
    finally:
        c.close(); s.close()


def test_revoked_identity_is_no_longer_trusted(tmp_path):
    a,b,x,y=paired(tmp_path)
    (c,_),(s,_),_,_=channels(a,b,x,y)
    try:
        x.remove(b.node_id)
        with pytest.raises(AuthenticationError): x.require(b.public_key)
    finally:
        c.close(); s.close()


def test_rejects_bad_encrypted_socket_constructor():
    left,right=socket.socketpair()
    try:
        with pytest.raises(ValueError): SecureSocket(left, b'bad', b'0'*32,initiator=True,remote_public_key=b'0'*32)
        with pytest.raises(ValueError): SecureSocket(left, b'0'*32, b'bad',initiator=True,remote_public_key=b'0'*32)
    finally:
        left.close(); right.close()


def test_recv_validates_size(tmp_path):
    a,b,x,y=paired(tmp_path)
    (c,_),(s,_),_,_=channels(a,b,x,y)
    try:
        with pytest.raises(ValueError): c.recv(-1)
        with pytest.raises(ValueError): c.recv(True)
        assert c.recv(0)==b''
    finally:
        c.close(); s.close()


def test_large_real_tcp_loopback(tmp_path):
    a,b,x,y=paired(tmp_path)
    listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    listener.bind(('127.0.0.1',0)); listener.listen(1)
    ready=threading.Event(); responses=[]; exceptions=[]
    def serve():
        try:
            with listener.accept()[0] as incoming:
                secure,peer=accept_secure_channel(incoming,b,y,timeout=2)
                ready.set()
                assert secure.recv(6)==b'hello!'
                secure.sendall(b'world!')
        except BaseException as exc: exceptions.append(exc)
    t=threading.Thread(target=serve); t.start()
    try:
        with socket.create_connection(listener.getsockname(),timeout=2) as outgoing:
            secure,peer=open_secure_channel(outgoing,a,x,b.node_id,timeout=2)
            assert ready.wait(2)
            secure.sendall(b'hello!')
            assert secure.recv(6)==b'world!'
        t.join(2)
        assert not exceptions
    finally:
        listener.close(); t.join(2)
