"""Authoritative UDP DNS service for the fixed intranet zone.

Every in-zone answer is built from one immutable version snapshot fetched
in a single storage read, so a reply can never mix records of two
versions.  While a transfer is in progress the old version stays active
and keeps being answered.

Queries outside the zone are optionally forwarded to one configured UDP
upstream (A records only, strictly bounded); forwarding never reads or
writes the zone snapshot.
"""
from __future__ import annotations

import logging
from typing import List

from dnslib import A, DNSRecord, RR, QTYPE, RCODE
from dnslib.server import BaseResolver, DNSServer

from .config import settings
from .forwarder import Forwarder
from .storage import storage

log = logging.getLogger("dns")


def _normalise(qname: str) -> str:
    return qname.rstrip(".").lower()


class ZoneResolver(BaseResolver):
    def __init__(self, forwarder: Forwarder | None = None) -> None:
        self._forwarder = (
            forwarder if forwarder is not None else Forwarder()
        )

    def resolve(self, request: DNSRecord, handler) -> DNSRecord:
        if not request.questions or request.q is None:
            reply = request.reply()
            reply.header.rcode = RCODE.REFUSED
            return reply
        q = request.q
        qname = _normalise(str(q.qname))
        zone = settings.dns_zone.rstrip(".").lower()

        in_zone = qname == zone or qname.endswith("." + zone)
        if not in_zone:
            if self._forwarder.enabled and self._forwarder.is_forwardable(
                request
            ):
                # Out-of-zone A query: one bounded UDP exchange with the
                # configured upstream.  Result is never stored locally.
                return self._forwarder.forward(request)
            # Not forwardable (no upstream / non-A / odd opcode): keep the
            # authoritative service boundary explicitly visible.
            reply = request.reply()
            reply.header.rcode = RCODE.REFUSED
            return reply

        reply = request.reply()
        if QTYPE[q.qtype] != "A":
            # In-zone but not an A query: authoritative NOERROR/NODATA.
            reply.header.rcode = RCODE.NOERROR
            return reply

        # One consistent snapshot -> one version per answer.
        serial, records, _ = storage.get_active_version()
        name_map = {}
        for rec in records:
            name_map.setdefault(rec["name"], []).append(rec["ip"])

        ips: List[str] = name_map.get(qname, [])
        if not ips:
            reply.header.rcode = RCODE.NXDOMAIN
            log.debug("NXDOMAIN %s (serial=%s)", qname, serial)
            return reply

        for ip in ips:
            reply.add_answer(
                RR(
                    q.qname,
                    QTYPE.A,
                    rdata=A(ip),
                    ttl=30,
                )
            )
        log.debug("ANSWER %s -> %s (serial=%s)", qname, ips, serial)
        return reply


class DnsService:
    def __init__(self) -> None:
        self._server: DNSServer | None = None
        self.forwarder: Forwarder | None = None

    def start(self) -> None:
        self.forwarder = Forwarder()
        resolver = ZoneResolver(self.forwarder)
        # DNSServer is itself a daemon thread; start_thread() runs the
        # UDP serve loop without blocking the FastAPI startup.
        self._server = DNSServer(
            resolver,
            port=settings.dns_port,
            address=settings.dns_host,
            tcp=False,
        )
        self._server.start_thread()
        log.info(
            "UDP DNS listener on %s:%s (zone=%s, role=%s, forwarding=%s)",
            settings.dns_host,
            settings.dns_port,
            settings.dns_zone,
            settings.role,
            "on" if self.forwarder.enabled else "off",
        )

    def stop(self) -> None:
        if self._server is not None:
            try:
                self._server.stop()
            except Exception:  # pragma: no cover
                pass


dns_service = DnsService()
