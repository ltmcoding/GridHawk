"""Stand in for the inverter's normal cloud traffic during the demo.

Makes real TLS connections to the vendor-cloud machine on a repeating cycle:
a small heartbeat often, a larger telemetry upload less often. This is the
"normal" the monitor should stay quiet about.

Run this on the Pi so the traffic genuinely crosses the interface being
captured.
"""

from __future__ import annotations

import argparse
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sim.inverter.client import one_session


HEARTBEAT_INTERVAL_S = 5.0
TELEMETRY_EVERY_N_HEARTBEATS = 4

HEARTBEAT_BYTES = (200, 400)
TELEMETRY_BYTES = (1_200, 8_000)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, help="vendor cloud address")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--interval", type=float, default=HEARTBEAT_INTERVAL_S)
    args = parser.parse_args()

    random_source = random.Random()
    print(f"Sending inverter traffic to {args.host}:{args.port} "
          f"every {args.interval:.0f}s. Ctrl-C to stop.\n")

    session_number = 0
    try:
        while True:
            session_number += 1
            if session_number % TELEMETRY_EVERY_N_HEARTBEATS == 0:
                kind = "telemetry"
                size = random_source.randint(*TELEMETRY_BYTES)
            else:
                kind = "heartbeat"
                size = random_source.randint(*HEARTBEAT_BYTES)

            try:
                one_session(args.host, args.port, kind, size,
                            sni="vendor-cloud.test")
                print(f"  {session_number:>4}  {kind:<10} {size:>6} bytes")
            except OSError as error:
                print(f"  {session_number:>4}  FAILED: {error}")

            time.sleep(args.interval)

    except KeyboardInterrupt:
        print(f"\nstopped after {session_number} sessions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
