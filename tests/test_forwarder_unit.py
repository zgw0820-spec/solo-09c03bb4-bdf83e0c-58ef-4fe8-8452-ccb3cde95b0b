"""Unit tests for the forwarder's pure pieces and reply-acceptance rules."""
import socket
import threading

import pytest
from dnslib import A, DNSHeader, DNSQuestion, DNSRecord, QTYPE, RR, RCODE

from app.forwarder import (
    Forwarder,
    _same_question,
    _servfail,
    parse_upstream,
)


def test_parse_upstream():
    assert parse_upstream("") is None
    assert parse_upstream("   ") is None
    assert parse_upstream("192.0.2.53") == ("192.0.2.53", 53)
    assert parse_upstream("upstream:53") == ("upstream", 53)
    assert parse_upstream("127.0.0.1:5353") == ("127.0.0.1", 5353)
    for bad in ("host:", ":53", "host:notaport", "host:0",
                "host:70000", "[::1]:53"):
        with pytest.raises(ValueError):
            parse_upstream(bad)


def test_same_question_is_strict():
    q = DNSQuestion("www.example.org", QTYPE.A)
    assert _same_question(DNSQuestion("WWW.Example.ORG.", QTYPE.A), q)
    assert not _same_question(DNSQuestion("www.example.org", QTYPE.AAAA), q)
    assert not _same_question(DNSQuestion("other.example.org", QTYPE.A), q)


def test_servfail_keeps_client_id_and_question():
    request = DNSRecord.question("www.example.org", "A")
    request.header.id = 4321
    reply = _servfail(request)
    assert reply.header.id == 4321
    assert reply.header.rcode == RCODE.SERVFAIL
    assert reply.header.qr == 1
    assert len(reply.questions) == 1


def test_disabled_forwarder_is_not_enabled():
    f = Forwarder("", timeout=0.2)
    assert f.enabled is False
    assert f.upstream_display is None


def test_unresolvable_upstream_returns_servfail():
    # ``.invalid`` is reserved and must never resolve.
    f = Forwarder("no-such-host.invalid:53", timeout=0.2)
    assert f.enabled is True  # configured -> SERVFAIL, not REFUSED
    request = DNSRecord.question("www.example.org", "A")
    reply = f.forward(request)
    assert reply.header.rcode == RCODE.SERVFAIL
    assert reply.header.id == request.header.id


def test_client_reply_rewrites_id_but_keeps_upstream_rcode_and_records():
    request = DNSRecord.question("www.example.org", "A")
    request.header.id = 777
    upstream = DNSRecord(
        DNSHeader(id=1234, qr=1, ra=1, rcode=RCODE.NXDOMAIN),
        questions=list(request.questions),
    )
    upstream.add_answer(
        RR("www.example.org", QTYPE.A, rdata=A("203.0.113.9"), ttl=60)
    )
    reply = Forwarder._client_reply(request, upstream)
    assert reply.header.id == 777
    assert reply.header.rcode == RCODE.NXDOMAIN
    assert [str(rr.rdata) for rr in reply.rr] == ["203.0.113.9"]


class _SpoofUpstream:
    """UDP server that sends a bad reply before the good one."""

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(5)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        data, peer = self.sock.recvfrom(65535)
        query = DNSRecord.parse(data)
        # 1) wrong request ID
        bad_id = query.reply()
        bad_id.header.id = (query.header.id + 1) & 0xFFFF
        bad_id.add_answer(
            RR(query.q.qname, QTYPE.A, rdata=A("198.51.100.1"), ttl=60)
        )
        self.sock.sendto(bad_id.pack(), peer)
        # 2) right ID but wrong question
        bad_q = query.reply()
        bad_q.questions = [DNSQuestion("evil.example.net", QTYPE.A)]
        bad_q.add_answer(
            RR("evil.example.net", QTYPE.A, rdata=A("198.51.100.2"), ttl=60)
        )
        self.sock.sendto(bad_q.pack(), peer)
        # 3) garbage that is not DNS at all
        self.sock.sendto(b"\x00\x01not-a-dns-packet", peer)
        # 4) valid reply
        good = query.reply()
        good.add_answer(
            RR(query.q.qname, QTYPE.A, rdata=A("203.0.113.50"), ttl=60)
        )
        self.sock.sendto(good.pack(), peer)
        self.sock.close()


def test_mismatched_replies_are_ignored_until_valid_one():
    upstream = _SpoofUpstream()
    f = Forwarder(f"127.0.0.1:{upstream.port}", timeout=2)
    request = DNSRecord.question("www.example.org", "A")
    reply = f.forward(request)
    assert reply.header.rcode == RCODE.NOERROR
    assert [str(rr.rdata) for rr in reply.rr] == ["203.0.113.50"]
    upstream.thread.join(timeout=5)
