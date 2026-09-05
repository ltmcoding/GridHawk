"""Fake vendor cloud endpoint.

Accepts telemetry POSTs and serves byte blobs of a requested size, so firmware
pulls have a realistic volume shape.  Self-signed cert generated on first run.
"""

from __future__ import annotations

import argparse
import os
import ssl
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # keep the rig quiet
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        self.rfile.read(n)
        body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # /blob?n=<bytes> -- shapes a firmware pull
        size = 1024
        if "?" in self.path:
            q = self.path.split("?", 1)[1]
            for part in q.split("&"):
                if part.startswith("n="):
                    try:
                        size = max(0, min(int(part[2:]), 64 * 1024 * 1024))
                    except ValueError:
                        pass
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(size))
        self.end_headers()
        chunk = b"\x00" * 8192
        sent = 0
        while sent < size:
            m = min(len(chunk), size - sent)
            self.wfile.write(chunk[:m])
            sent += m


def ensure_cert(certdir: str) -> tuple[str, str]:
    os.makedirs(certdir, exist_ok=True)
    cert = os.path.join(certdir, "cloud.pem")
    key = os.path.join(certdir, "cloud.key")
    if not (os.path.exists(cert) and os.path.exists(key)):
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", key, "-out", cert, "-days", "30",
             "-subj", "/CN=vendor-cloud.test"],
            check=True, capture_output=True,
        )
    return cert, key


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--certdir", default="sim/cloud/certs")
    a = ap.parse_args()

    cert, key = ensure_cert(a.certdir)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    # Match what an embedded client will actually negotiate.
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2

    srv = ThreadingHTTPServer((a.bind, a.port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print(f"vendor-cloud listening on https://{a.bind}:{a.port}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
