"""Make the inverter contact somewhere it should not. The demo's second beat.

One TLS connection to an address outside the allowlist. The monitor should
notice within its next capture window and post an alert.

Run this on the Pi, from a second terminal, while tls_monitor is watching.
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sim.inverter.client import one_session


ROGUE_PAYLOAD_BYTES = 4_096


def main() -> int:
    """Make one connection to an unauthorised address."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True,
                        help="the unauthorised address, as listed in asn_map.json")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--bytes", type=int, default=ROGUE_PAYLOAD_BYTES)
    parser.add_argument("--repeat", type=int, default=1)
    args = parser.parse_args()

    print(f"Contacting {args.host}:{args.port} -- this address is NOT on the "
          f"allowlist.\n")

    for attempt in range(1, args.repeat + 1):
        try:
            result = one_session(args.host, args.port, "rogue", args.bytes,
                                 sni="unknown-endpoint.test")
            print(f"  {attempt}: sent {args.bytes} bytes, "
                  f"received {result['rx']} in {result['elapsed']:.2f}s")
        except OSError as error:
            print(f"  {attempt}: connection failed: {error}")
            print("     Is the rogue endpoint server running on that machine?")
            return 1

    print("\nWatch the monitor and the alert dashboard.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
