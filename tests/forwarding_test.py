"""Forwarding end-to-end: real primary + backup processes, fake upstream.

Scenarios:
  1. in-zone queries stay local; out-of-zone A is forwarded and its answer
     (including rcode) is passed through on both machines
  2. out-of-zone non-A queries are still refused, in-zone AAAA is NODATA
  3. spoofed / mismatched / wrong-id replies are never delivered
  4. at most 4 forwards in flight; excess gets SERVFAIL, zone still works
  5. blocked upstream: forward times out with SERVFAIL after ~1s while
     in-zone DNS, publishing and backup sync keep working
  6. forwarded data never enters the zone, and forwarding recovers
"""
from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx
from dnslib import (
    A,
    DNSQuestion,
    DNSRecord,
    QTYPE,
    RR,
    RCODE,
)

ROOT = Path(__file__).resolve().parent.parent
PY = str(ROOT / ".venv" / "bin" / "python")
DATA = ROOT / "data"
ZONE = "internal.local"
PRIMARY_API = "http://127.0.0.1:18020"
BACKUP_API = "http://127.0.0.1:18021"
PRIMARY_DNS = ("127.0.0.1", 15060)
BACKUP_DNS = ("127.0.0.1", 15061)

UPSTREAM_RECORDS = {
    "www.example.org": "203.0.113.11",
    "api.example.org": "203.0.113.12",
}

failures: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(("  PASS  " if cond else "  FAIL  ") + name +
          (" " + detail if not cond else ""))
    if not cond:
        failures.append(name)


def wait_http(url: str, timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if httpx.get(url, timeout=1.5).status_code == 200:
                return
        except Exception:
            pass
        time.sleep(0.3)
    raise RuntimeError(f"not ready: {url}")


def dns_query(server, name: str, qtype: str = "A", timeout: float = 3.0,
              qid: int | None = None):
    q = DNSRecord.question(name, qtype)
    if qid is not None:
        q.header.id = qid
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    t0 = time.monotonic()
    sock.sendto(q.pack(), server)
    data, _ = sock.recvfrom(65535)
    elapsed = time.monotonic() - t0
    sock.close()
    return DNSRecord.parse(data), elapsed


class FakeUpstream:
    """UDP upstream whose behaviour is switched live via ``mode``."""

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.mode = "normal"       # normal | slow | blackhole | spoof | wrongid
        self.delay = 0.0
        self.lock = threading.Lock()
        self.received = 0
        self.active = 0
        self.max_active = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def reset(self, mode: str = "normal", delay: float = 0.0) -> None:
        with self.lock:
            self.mode = mode
            self.delay = delay
            self.received = 0
            self.active = 0
            self.max_active = 0

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                data, peer = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            with self.lock:
                self.received += 1
                seq = self.received
                self.active += 1
                self.max_active = max(self.max_active, self.active)
                mode = self.mode
                delay = self.delay
            threading.Thread(
                target=self._handle, args=(data, peer, mode, delay, seq),
                daemon=True,
            ).start()

    def _send(self, record: DNSRecord, peer) -> None:
        try:
            self.sock.sendto(record.pack(), peer)
        except OSError:
            pass

    def _handle(self, data, peer, mode, delay, seq) -> None:
        try:
            try:
                query = DNSRecord.parse(data)
            except Exception:
                return
            if mode == "blackhole":
                time.sleep(2.0)  # client has given up long before this
                return
            if mode == "late" and seq == 1:
                # First query deliberately answered after the 1s deadline.
                time.sleep(1.6)
                late = query.reply()
                late.add_answer(
                    RR(query.q.qname, QTYPE.A, rdata=A("198.51.100.88"),
                       ttl=60)
                )
                self._send(late, peer)
                return
            if delay:
                time.sleep(delay)
            qname = str(query.q.qname).rstrip(".").lower()
            if mode == "wrongid":
                bad = query.reply()
                bad.header.id = (query.header.id + 1) & 0xFFFF
                bad.add_answer(
                    RR(query.q.qname, QTYPE.A, rdata=A("198.51.100.77"),
                       ttl=60)
                )
                self._send(bad, peer)
                return
            if mode == "spoof":
                # same request ID but a different question name -> wrong
                bad = query.reply()
                bad.questions = [DNSQuestion("evil.example.net", QTYPE.A)]
                bad.add_answer(
                    RR("evil.example.net", QTYPE.A,
                       rdata=A("198.51.100.66"), ttl=60)
                )
                self._send(bad, peer)
                # correct question but a wrong request ID -> wrong
                bad2 = query.reply()
                bad2.header.id = (query.header.id + 7) & 0xFFFF
                bad2.add_answer(
                    RR(query.q.qname, QTYPE.A,
                       rdata=A("198.51.100.67"), ttl=60)
                )
                self._send(bad2, peer)
                # then the truthful reply
            good = query.reply()
            if query.q.qtype != QTYPE.A:
                self._send(good, peer)  # NOERROR/NODATA
                return
            ip = UPSTREAM_RECORDS.get(qname)
            if ip is None:
                good.header.rcode = RCODE.NXDOMAIN
            else:
                good.add_answer(RR(query.q.qname, QTYPE.A, rdata=A(ip),
                                   ttl=60))
            self._send(good, peer)
        finally:
            with self.lock:
                self.active -= 1

    def stop(self) -> None:
        self._stop.set()
        self.sock.close()


def start(role, api_port, dns_port, db, upstream_url=None,
          timeout="1", max_inflight="4"):
    env = os.environ.copy()
    env.update({
        "DNS_ROLE": role, "DNS_ZONE": ZONE, "DB_PATH": db,
        "DNS_HOST": "127.0.0.1", "DNS_PORT": str(dns_port),
        "API_HOST": "127.0.0.1", "API_PORT": str(api_port),
        "DNS_UPSTREAM": upstream_url or "",
        "FORWARD_MAX_INFLIGHT": max_inflight,
        "FORWARD_TIMEOUT": timeout,
        "SYNC_INTERVAL": "1", "HTTP_TIMEOUT": "3",
        "PYTHONUNBUFFERED": "1",
    })
    if role == "backup":
        env["PRIMARY_API_URL"] = PRIMARY_API
    log = open(DATA / f"{role}-forward.log", "w")
    return subprocess.Popen(
        [PY, "-I", "-m", "uvicorn", "app.main:app",
         "--host", "127.0.0.1", "--port", str(api_port)],
        cwd=str(ROOT), env=env, stdout=log, stderr=subprocess.STDOUT)


def stop(proc) -> None:
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def ips(reply: DNSRecord) -> list[str]:
    return [str(rr.rdata) for rr in reply.rr]


def publish(records) -> httpx.Response:
    return httpx.post(f"{PRIMARY_API}/api/zone", json={"records": records},
                      timeout=5)


def main() -> int:
    upstream = FakeUpstream()
    upstream_addr = f"127.0.0.1:{upstream.port}"

    for f in ("primary-forward.db", "backup-forward.db"):
        for s in ("", "-wal", "-shm"):
            p = DATA / (f + s)
            if p.exists():
                p.unlink()

    primary = start("primary", 18020, 15060,
                    str(DATA / "primary-forward.db"), upstream_addr)
    backup = start("backup", 18021, 15061,
                   str(DATA / "backup-forward.db"), upstream_addr)
    try:
        wait_http(f"{PRIMARY_API}/health")
        wait_http(f"{BACKUP_API}/health")
        time.sleep(0.5)

        print("[0] forwarding configuration is reported")
        info = httpx.get(f"{PRIMARY_API}/api/version").json()
        check("primary reports forwarding enabled",
              info["forward_enabled"] is True, json.dumps(info))
        check("primary reports upstream + bounds",
              info["forward_upstream"] == upstream_addr
              and info["forward_max_inflight"] == 4
              and info["forward_timeout"] == 1.0, json.dumps(info))

        print("[1] publish local zone; local and forwarded answers")
        resp = publish([
            {"name": f"db.{ZONE}", "ip": "10.0.0.11"},
            {"name": f"web.{ZONE}", "ip": "10.0.0.21"},
        ])
        check("publish -> serial 1", resp.status_code == 201
              and resp.json()["serial"] == 1, resp.text)

        r, _ = dns_query(PRIMARY_DNS, f"db.{ZONE}")
        check("in-zone A answered locally",
              r.header.rcode == RCODE.NOERROR and ips(r) == ["10.0.0.11"],
              str(r))
        r, elapsed = dns_query(PRIMARY_DNS, "www.example.org")
        check("out-of-zone A forwarded on primary",
              r.header.rcode == RCODE.NOERROR
              and ips(r) == ["203.0.113.11"], str(r))
        r, _ = dns_query(PRIMARY_DNS, "www.example.org", qid=4242)
        check("client request ID preserved across forwarding",
              r.header.id == 4242, str(r.header))
        r, _ = dns_query(PRIMARY_DNS, "missing.example.org")
        check("upstream NXDOMAIN rcode preserved",
              r.header.rcode == RCODE.NXDOMAIN, str(r))
        r, _ = dns_query(PRIMARY_DNS, f"db.{ZONE}", qtype="AAAA")
        check("in-zone AAAA still NOERROR NODATA",
              r.header.rcode == RCODE.NOERROR and len(r.rr) == 0)
        r, _ = dns_query(PRIMARY_DNS, "www.example.org", qtype="AAAA")
        check("out-of-zone AAAA still REFUSED (only A forwarded)",
              r.header.rcode == RCODE.REFUSED, str(r))
        r, _ = dns_query(PRIMARY_DNS, "www.example.org", qtype="MX")
        check("out-of-zone MX REFUSED (only A forwarded)",
              r.header.rcode == RCODE.REFUSED, str(r))

        print("[2] backup forwards independently of its sync role")
        deadline = time.time() + 10
        while time.time() < deadline:
            if httpx.get(f"{BACKUP_API}/api/version").json()["serial"] == 1:
                break
            time.sleep(0.3)
        r, _ = dns_query(BACKUP_DNS, f"db.{ZONE}")
        check("backup serves synced in-zone record",
              ips(r) == ["10.0.0.11"], str(r))
        r, _ = dns_query(BACKUP_DNS, "api.example.org")
        check("backup forwards out-of-zone A",
              r.header.rcode == RCODE.NOERROR
              and ips(r) == ["203.0.113.12"], str(r))

        print("[3] spoofed/mismatched replies are not accepted")
        upstream.reset("spoof")
        r, _ = dns_query(PRIMARY_DNS, "www.example.org")
        check("mismatched question/garbage ignored, valid reply used",
              r.header.rcode == RCODE.NOERROR
              and ips(r) == ["203.0.113.11"], str(r))
        upstream.reset("wrongid")
        r, elapsed = dns_query(PRIMARY_DNS, "www.example.org")
        check("only wrong-ID reply -> SERVFAIL, spoofed IP not delivered",
              r.header.rcode == RCODE.SERVFAIL and ips(r) == [],
              str(r))
        check("wrong-ID SERVFAIL respects the 1s budget",
              elapsed < 2.0, f"{elapsed:.2f}s")

        print("[3b] a late reply cannot leak into a later client's answer")
        upstream.reset("late")
        r1, e1 = dns_query(PRIMARY_DNS, "slow.example.org", timeout=4)
        check("late upstream reply -> client got SERVFAIL",
              r1.header.rcode == RCODE.SERVFAIL and ips(r1) == [],
              str(r1))
        # The 1.6s-late reply for slow.example.org arrives while this next
        # query (different name, own socket) is in flight; it must not be
        # delivered anywhere.
        r2, e2 = dns_query(PRIMARY_DNS, "www.example.org", timeout=4)
        check("next client got its own answer, not the late one",
              ips(r2) == ["203.0.113.11"] and e2 < 1.5,
              f"{ips(r2)} in {e2:.2f}s")
        time.sleep(0.8)  # let the late packet actually land
        r3, _ = dns_query(PRIMARY_DNS, "www.example.org", timeout=4)
        check("late packet left no stale state behind",
              ips(r3) == ["203.0.113.11"], str(r3))
        upstream.reset("normal")

        print("[4] concurrency: at most 4 in flight, excess -> SERVFAIL")
        upstream.reset("slow", delay=0.6)
        results: list = [None] * 8
        barrier = threading.Barrier(8)

        def worker(i: int) -> None:
            barrier.wait()
            try:
                results[i] = dns_query(
                    PRIMARY_DNS, f"host{i}.example.org", timeout=3
                )[0]
            except Exception as exc:  # pragma: no cover
                results[i] = exc

        threads = [threading.Thread(target=worker, args=(i,))
                   for i in range(8)]
        for t in threads:
            t.start()
        # While forwards are saturated, a local query must still answer.
        time.sleep(0.15)
        r_local, local_elapsed = dns_query(PRIMARY_DNS, f"web.{ZONE}")
        for t in threads:
            t.join(timeout=10)
        check("in-zone query unaffected during forward saturation",
              ips(r_local) == ["10.0.0.21"] and local_elapsed < 0.5,
              f"{local_elapsed:.2f}s")
        codes = [getattr(x, "header", None) and x.header.rcode
                 for x in results]
        servfails = sum(1 for c in codes if c == RCODE.SERVFAIL)
        answered = sum(1 for x in results
                       if getattr(x, "header", None)
                       and x.header.rcode == RCODE.NXDOMAIN)
        check("upstream saw at most 4 concurrent queries",
              upstream.max_active <= 4, str(upstream.max_active))
        check("exactly 4 forwarded, rest SERVFAIL immediately",
              upstream.received == 4 and servfails == 4
              and answered == 4,
              f"received={upstream.received} servfail={servfails} "
              f"answered={answered} codes={codes}")
        upstream.reset("normal")
        time.sleep(0.7)  # let the slow handlers drain
        r, _ = dns_query(PRIMARY_DNS, "www.example.org")
        check("forwarding works again after the burst",
              ips(r) == ["203.0.113.11"], str(r))

        print("[5] blocked upstream: SERVFAIL while everything local works")
        upstream.reset("blackhole")
        t0 = time.monotonic()
        r, elapsed = dns_query(PRIMARY_DNS, "www.example.org", timeout=4)
        check("blocked upstream -> SERVFAIL", r.header.rcode == RCODE.SERVFAIL,
              str(r))
        check("SERVFAIL after ~1s timeout", 0.8 <= elapsed <= 2.0,
              f"{elapsed:.2f}s")
        r, in_zone_elapsed = dns_query(PRIMARY_DNS, f"db.{ZONE}")
        check("in-zone DNS still answers while upstream is blocked",
              ips(r) == ["10.0.0.11"] and in_zone_elapsed < 0.5,
              f"{in_zone_elapsed:.2f}s")
        resp = publish([{"name": f"db.{ZONE}", "ip": "10.0.0.12"}])
        check("publishing still works while upstream is blocked",
              resp.status_code == 201 and resp.json()["serial"] == 2,
              resp.text)
        deadline = time.time() + 12
        synced = False
        while time.time() < deadline:
            if httpx.get(f"{BACKUP_API}/api/version").json()["serial"] == 2:
                synced = True
                break
            time.sleep(0.3)
        check("backup sync still works while its upstream is blocked",
              synced)
        r, _ = dns_query(PRIMARY_DNS, f"db.{ZONE}")
        check("in-zone serves the newly published version",
              ips(r) == ["10.0.0.12"], str(r))

        print("[6] forwarding never mutates the zone")
        zone_primary = httpx.get(f"{PRIMARY_API}/api/zone").json()
        zone_backup = httpx.get(f"{BACKUP_API}/api/zone").json()
        check("zone contains only local records (no forwarded data)",
              zone_primary["records"] == [
                  {"name": f"db.{ZONE}", "ip": "10.0.0.12"}
              ], json.dumps(zone_primary))
        check("serial unchanged by forwarding",
              zone_primary["serial"] == 2)
        check("backup zone equals primary zone", zone_backup == zone_primary,
              f"{zone_backup} != {zone_primary}")
        upstream.reset("normal")
        t0 = time.monotonic()
        r, elapsed = dns_query(PRIMARY_DNS, "www.example.org")
        check("forwarding recovers after the upstream unblocks",
              ips(r) == ["203.0.113.11"] and elapsed < 1.0,
              str(r))
    finally:
        upstream.stop()
        stop(primary)
        if backup.poll() is None:
            stop(backup)

    print(f"\n==== forwarding checks: {len(failures)} failures ====")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
