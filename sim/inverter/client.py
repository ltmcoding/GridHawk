"""Inverter cloud client -- MCU-profile TLS.

Replays a scenario's events as real TLS sessions so the collector sees real
packets, not a mock.  The TLS profile is constrained toward what an embedded
stack negotiates: TLS 1.2 only, a short cipher list, no session tickets.

HONESTY NOTE: constrained-OpenSSL still fingerprints as OpenSSL.  Its JA3 is
NOT an mbedTLS or wolfSSL fingerprint.  Do not claim JA3-based detection on the
strength of this client -- either build mbedtls' ssl_client2 and shell out to
it, or drop JA3 from the claimed detection set.
"""

from __future__ import annotations

import argparse
import json
import socket
import ssl
import time


def mcu_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    try:
        ctx.set_ciphers("ECDHE-RSA-AES128-GCM-SHA256:AES128-GCM-SHA256")
    except ssl.SSLError:
        ctx.set_ciphers("DEFAULT")
    ctx.options |= ssl.OP_NO_TICKET
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE      # self-signed test cloud
    return ctx


def one_session(host: str, port: int, kind: str, nbytes: int,
                sni: str, timeout: float = 10.0) -> dict:
    ctx = mcu_context()
    t0 = time.time()
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=sni) as s:
            if kind in ("volume_spike",) or nbytes > 100_000:
                req = f"GET /blob?n={nbytes} HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n"
                s.sendall(req.encode())
                got = 0
                while True:
                    b = s.recv(65536)
                    if not b:
                        break
                    got += len(b)
            else:
                body = b"x" * max(1, nbytes)
                req = (f"POST /telemetry HTTP/1.1\r\nHost: {sni}\r\n"
                       f"Content-Type: application/octet-stream\r\n"
                       f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n")
                s.sendall(req.encode() + body)
                got = 0
                while True:
                    b = s.recv(65536)
                    if not b:
                        break
                    got += len(b)
    return {"kind": kind, "sni": sni, "bytes": nbytes, "rx": got,
            "elapsed": round(time.time() - t0, 4)}


def main() -> None:
    ap = argparse.ArgumentParser(description="replay a scenario as TLS sessions")
    ap.add_argument("--events", required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--speed", type=float, default=60.0,
                    help="time compression: 60 = one simulated minute per real second")
    ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args()

    events = json.load(open(a.events))
    if a.limit:
        events = events[: a.limit]

    start = time.time()
    done = 0
    for ev in events:
        target = start + (ev["t"] / a.speed)
        now = time.time()
        if target > now:
            time.sleep(target - now)
        sni = f"{ev['dst'].replace('.', '-')}.vendor-cloud.test"
        try:
            one_session(a.host, a.port, ev["kind"], ev["nbytes"], sni)
            done += 1
        except OSError as e:
            print(f"  session failed ({ev['kind']}): {e}")
    print(f"replayed {done}/{len(events)} sessions")


if __name__ == "__main__":
    main()
