"""Tiny example upstream DNS for the Docker Compose demo.

It is deliberately *not* a real recursive resolver: it answers a small
fixed set of A records for names outside the intranet zone, NXDOMAIN for
other names, and NODATA for other query types.  Its only purpose is to
make the primary/backup forwarding path demonstrable without depending on
the host network's resolver.
"""
from __future__ import annotations

import argparse
import logging
import os
from typing import Dict

from dnslib import A, DNSRecord, QTYPE, RR, RCODE
from dnslib.server import BaseResolver, DNSServer

log = logging.getLogger("example-upstream")

DEFAULT_RECORDS: Dict[str, str] = {
    "example.org": "203.0.113.10",
    "www.example.org": "203.0.113.11",
    "api.example.org": "203.0.113.12",
}


class ExampleUpstreamResolver(BaseResolver):
    def __init__(self, records: Dict[str, str], ttl: int = 60) -> None:
        self.records = {k.rstrip(".").lower(): v for k, v in records.items()}
        self.ttl = ttl

    def resolve(self, request: DNSRecord, handler) -> DNSRecord:
        reply = request.reply()
        if not request.questions:
            reply.header.rcode = RCODE.FORMERR
            return reply
        q = request.q
        qname = str(q.qname).rstrip(".").lower()
        if QTYPE[q.qtype] != "A":
            reply.header.rcode = RCODE.NOERROR  # NODATA
            return reply
        ip = self.records.get(qname)
        if ip is None:
            reply.header.rcode = RCODE.NXDOMAIN
            return reply
        reply.add_answer(RR(q.qname, QTYPE.A, rdata=A(ip), ttl=self.ttl))
        return reply


def main() -> None:
    parser = argparse.ArgumentParser(description="example upstream DNS")
    parser.add_argument(
        "--host", default=os.environ.get("UPSTREAM_HOST", "0.0.0.0")
    )
    parser.add_argument(
        "--port", type=int, default=int(os.environ.get("UPSTREAM_PORT", "53"))
    )
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    server = DNSServer(
        ExampleUpstreamResolver(DEFAULT_RECORDS),
        address=args.host,
        port=args.port,
        tcp=False,
    )
    log.info(
        "example upstream listening on udp://%s:%s for %s",
        args.host,
        args.port,
        sorted(DEFAULT_RECORDS),
    )
    server.start()


if __name__ == "__main__":
    main()
