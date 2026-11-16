"""Bounded out-of-zone A forwarding over a single UDP upstream.

Only queries for names outside the fixed local zone are sent here.  The
local zone is always answered from the immutable SQLite snapshot; nothing
that arrives from the upstream is ever written to the zone.

Safety properties:

* every forward uses its own ephemeral UDP socket and a fresh request ID;
* a reply is accepted only when source address, source port, request ID
  and the question (name/type/class) all match the forwarded query;
* mismatched or late replies are ignored on that socket and can never be
  delivered to another client (each exchange owns its socket, and the
  kernel is connected to the configured upstream address);
* at most ``FORWARD_MAX_INFLIGHT`` exchanges run at once per machine; a
  query that cannot get a slot is not queued and gets SERVFAIL at once;
* waiting for the upstream is bounded by ``FORWARD_TIMEOUT`` (and by
  ``FORWARD_MAX_INFLIGHT`` in total), so a stuck upstream cannot pile up
  threads indefinitely.
"""
from __future__ import annotations

import logging
import random
import socket
import threading
import time
from typing import Optional, Tuple

from dnslib import CLASS, DNSHeader, DNSRecord, QTYPE, RCODE

from .config import settings

log = logging.getLogger("forward")

DEFAULT_UPSTREAM_PORT = 53


def parse_upstream(value: str) -> Optional[Tuple[str, int]]:
    """Parse ``host`` or ``host:port`` into ``(host, port)``.

    An empty value means forwarding is disabled.
    """
    value = value.strip()
    if not value:
        return None
    if value.startswith("["):
        raise ValueError("IPv6 upstreams are not supported")
    if value.count(":") > 1:
        # Bare IPv6 literal (unsupported) rather than host:port.
        raise ValueError("IPv6 upstreams are not supported")
    host, sep, port_text = value.rpartition(":")
    if sep:
        if not host or not port_text.isdigit():
            raise ValueError(f"invalid upstream address: {value!r}")
        port = int(port_text)
        if not 1 <= port <= 65535:
            raise ValueError(f"upstream port out of range: {value!r}")
        return host, port
    return value, DEFAULT_UPSTREAM_PORT


def _norm_name(name: object) -> str:
    return str(name).rstrip(".").lower()


def _same_question(reply_q, query_q) -> bool:
    return (
        _norm_name(reply_q.qname) == _norm_name(query_q.qname)
        and reply_q.qtype == query_q.qtype
        and reply_q.qclass == query_q.qclass
    )


def _servfail(request: DNSRecord) -> DNSRecord:
    return DNSRecord(
        DNSHeader(
            id=request.header.id,
            qr=1,
            opcode=request.header.opcode,
            rd=request.header.rd,
            ra=1,
            aa=0,
            rcode=RCODE.SERVFAIL,
        ),
        questions=list(request.questions),
    )


class Forwarder:
    """Single-upstream forwarder shared by every UDP request thread."""

    def __init__(
        self,
        upstream: Optional[str] = None,
        max_inflight: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> None:
        raw = settings.dns_upstream if upstream is None else upstream
        self.max_inflight = max(
            1,
            settings.forward_max_inflight
            if max_inflight is None
            else max_inflight,
        )
        self.timeout = max(
            0.05,
            settings.forward_timeout if timeout is None else timeout,
        )
        self._semaphore = threading.BoundedSemaphore(self.max_inflight)
        self._addr_lock = threading.Lock()
        self._addr: Optional[Tuple[str, int]] = None
        self._host: Optional[str] = None
        self._port: int = DEFAULT_UPSTREAM_PORT
        self.error: Optional[str] = None
        self.config = raw.strip()

        try:
            parsed = parse_upstream(raw)
        except ValueError as exc:
            parsed = None
            self.error = str(exc)
            log.error("forwarding disabled: %s", exc)

        if parsed is not None:
            self._host, self._port = parsed
            # Best-effort eager resolution; a temporary failure (e.g. the
            # upstream container not ready yet) is retried per query.
            self._ensure_addr()
            if self._addr is not None:
                log.info(
                    "forwarding out-of-zone A queries to udp://%s:%s "
                    "(max_inflight=%s, timeout=%ss)",
                    self._addr[0],
                    self._addr[1],
                    self.max_inflight,
                    self.timeout,
                )

    # -- configuration --------------------------------------------------
    @property
    def enabled(self) -> bool:
        # Any non-empty configuration counts: a bad/hostname-not-ready
        # upstream yields SERVFAIL (with the reason reported on
        # /api/version) instead of silently reverting to REFUSED.
        return bool(self.config)

    @property
    def upstream_display(self) -> Optional[str]:
        if self._addr is not None:
            return f"{self._addr[0]}:{self._addr[1]}"
        if self._host is not None:
            return f"{self._host}:{self._port}"
        return self.config or None

    def _ensure_addr(self) -> Optional[Tuple[str, int]]:
        if self._addr is not None:
            return self._addr
        if self._host is None:
            return None
        with self._addr_lock:
            if self._addr is not None:
                return self._addr
            try:
                info = socket.getaddrinfo(
                    self._host,
                    self._port,
                    family=socket.AF_INET,
                    type=socket.SOCK_DGRAM,
                )
                self._addr = (info[0][4][0], self._port)
                self.error = None
            except OSError as exc:
                self.error = (
                    f"cannot resolve upstream {self._host!r}: {exc}"
                )
                log.warning("forwarding unavailable: %s", self.error)
                return None
        return self._addr

    # -- public ---------------------------------------------------------
    def is_forwardable(self, request: DNSRecord) -> bool:
        """Only classic, single-question, IN/A queries leave the machine."""
        return (
            request.header.opcode == 0
            and request.header.qr == 0
            and len(request.questions) == 1
            and request.q.qtype == QTYPE.A
            and request.q.qclass == CLASS.IN
        )

    def forward(self, request: DNSRecord) -> DNSRecord:
        """Return a client-ready reply for one out-of-zone A query."""
        addr = self._ensure_addr()
        if addr is None:
            return _servfail(request)

        # Over capacity is rejected immediately instead of queueing: a
        # saturated machine must not accumulate blocked request threads.
        if not self._semaphore.acquire(blocking=False):
            log.warning(
                "forward capacity exceeded (%s in flight), SERVFAIL %s",
                self.max_inflight,
                _norm_name(request.q.qname),
            )
            return _servfail(request)
        try:
            return self._exchange(request, addr)
        except Exception as exc:  # never let a resolver thread die
            log.warning(
                "forwarding failed for %s: %s: %s",
                _norm_name(request.q.qname),
                type(exc).__name__,
                exc,
            )
            return _servfail(request)
        finally:
            self._semaphore.release()

    # -- internals ------------------------------------------------------
    def _exchange(
        self, request: DNSRecord, addr: Tuple[str, int]
    ) -> DNSRecord:
        deadline = time.monotonic() + self.timeout
        qid = random.randint(0, 0xFFFF)
        query = DNSRecord(
            DNSHeader(
                id=qid,
                qr=0,
                opcode=0,
                # The upstream is treated as a recursive resolver.
                rd=1,
                aa=0,
                tc=0,
                ra=0,
            ),
            questions=list(request.questions),
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Connecting makes the kernel drop datagrams from every other
            # source address/port; the source tuple is still verified.
            sock.connect(addr)
            sock.send(query.pack())

            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    log.warning(
                        "upstream timed out after %ss for %s",
                        self.timeout,
                        _norm_name(request.q.qname),
                    )
                    return _servfail(request)
                sock.settimeout(max(0.001, remaining))
                try:
                    data, source = sock.recvfrom(65535)
                except socket.timeout:
                    log.warning(
                        "upstream timed out after %ss for %s",
                        self.timeout,
                        _norm_name(request.q.qname),
                    )
                    return _servfail(request)
                except OSError as exc:
                    # e.g. ICMP port unreachable surfaced on the socket.
                    log.warning("upstream socket error: %s", exc)
                    return _servfail(request)

                if source != addr:
                    log.warning(
                        "ignored reply from unexpected source %s:%s",
                        source[0],
                        source[1],
                    )
                    continue
                try:
                    reply = DNSRecord.parse(data)
                except Exception:
                    log.warning("ignored malformed upstream reply")
                    continue

                if reply.header.id != qid or reply.header.qr != 1:
                    log.warning(
                        "ignored mismatched reply id=%s (expected %s)",
                        reply.header.id,
                        qid,
                    )
                    continue
                if len(reply.questions) != 1 or not _same_question(
                    reply.q, request.q
                ):
                    log.warning(
                        "ignored reply with mismatched question for %s",
                        _norm_name(request.q.qname),
                    )
                    continue

                return self._client_reply(request, reply)
        finally:
            sock.close()

    @staticmethod
    def _client_reply(request: DNSRecord, upstream: DNSRecord) -> DNSRecord:
        """Rewrite the ID for the client, keeping upstream rcode/records."""
        return DNSRecord(
            DNSHeader(
                id=request.header.id,
                qr=1,
                opcode=request.header.opcode,
                rd=request.header.rd,
                ra=1,
                aa=0,
                tc=upstream.header.tc,
                rcode=upstream.header.rcode,
            ),
            questions=list(request.questions),
            rr=list(upstream.rr),
            auth=list(upstream.auth),
            ar=list(upstream.ar),
        )
