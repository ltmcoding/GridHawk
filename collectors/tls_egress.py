"""Network egress attestation: watch what the inverter talks to.

This is Grid Lockout Layer 2. The inverter is the CLIENT here -- it calls out to
a vendor cloud, and we watch those outbound connections from the site boundary.

METADATA ONLY, AND PERMANENTLY SO
---------------------------------
We have no bench inverter. No device means no firmware to extract, which means
no client certificate, which means no way to sit inside the TLS session. So we
never see what is inside these connections.

Two facts make that permanent rather than a temporary gap:

  * A certificate on its own is public and decrypts nothing. You need the
    matching private key.
  * Even with the key, a captured session cannot be decrypted afterwards. TLS
    1.3 always uses ephemeral key exchange, as does any well-configured 1.2.
    Interception has to happen live, in the middle of the connection.

What we CAN see is still useful: who the device talks to, which network that
belongs to, which country, how much data moves, and how often.

TWO WAYS IN, ONE WAY OUT
------------------------
`from_pcap` reads real captured packets. `from_events` replays a simulated
scenario. Both produce the exact same Observation records, so the detection
rules cannot tell the difference -- there is no separate "test mode" that could
quietly drift away from the real one.
"""

from __future__ import annotations

import json

from core.events import Observation
from collectors import pcap as pcap_reader


# Default port we treat as TLS traffic.
HTTPS_PORT = 443

# Address the simulated inverter transmits from, used when replaying events.
SIMULATED_DEVICE_IP = "172.28.0.5"

# Nominal session duration recorded for replayed events. Replay has no packet
# timing, so this is a placeholder rather than a measurement.
REPLAY_SESSION_DURATION_S = 0.2

# After a connection closes, TCP still exchanges teardown packets: a FIN from
# each side and a final ACK. Those arrive after we have already emitted the
# session, and without this grace period each one starts a BRAND NEW flow under
# the same key -- turning one connection into three "sessions".
#
# Measured on real capture: every session appeared three times (2948, 187 and
# 40 bytes), which split the byte totals AND created a phantom channel of
# 40-byte sessions arriving milliseconds apart. The cadence rule then fired on
# that phantom channel with a "period" of 0.1 seconds.
#
# Two seconds comfortably covers teardown while staying far below any realistic
# reuse of the same ephemeral port.
CLOSED_FLOW_GRACE_S = 2.0


def _build_observation(start_time, source_ip, destination_ip, destination_port,
                       total_bytes, duration, server_name, asn_lookup) -> Observation:
    """Assemble one session record, resolving the destination's network."""
    asn, asn_name, country = asn_lookup(destination_ip)

    return Observation(
        ts=start_time,
        source="tls_egress",
        subject=source_ip,
        fields={
            "dst": destination_ip,
            "dport": destination_port,
            "asn": asn,
            "asn_name": asn_name,
            "cc": country,
            "bytes": total_bytes,
            "duration": duration,
            "sni": server_name,
        },
    )


def _observation_time(observation: Observation) -> float:
    """Sort key."""
    return observation.ts


def from_pcap(path: str, asn_lookup, port: int = HTTPS_PORT) -> list[Observation]:
    """Group captured packets into sessions, one Observation per session.

    Packets arrive interleaved across many connections, so they are grouped by
    the four values that identify a TCP connection: both addresses and both
    ports. Both directions of one connection are deliberately folded into the
    same group, so `bytes` counts the whole conversation.
    """
    open_sessions: dict[tuple, dict] = {}
    recently_closed: dict[tuple, float] = {}
    observations: list[Observation] = []

    def close_session(session):
        observations.append(_build_observation(
            start_time=session["start"],
            source_ip=session["src"],
            destination_ip=session["dst"],
            destination_port=session["dport"],
            total_bytes=session["bytes"],
            duration=round(session["last"] - session["start"], 4),
            server_name=session["sni"],
            asn_lookup=asn_lookup,
        ))

    for packet in pcap_reader.read(path):
        if packet.dport != port and packet.sport != port:
            continue

        # Build the key from the client's point of view regardless of which way
        # this particular packet is travelling, so both directions land in one
        # group.
        travelling_outbound = packet.dport == port
        if travelling_outbound:
            key = (packet.src, packet.dst, packet.sport, packet.dport)
        else:
            key = (packet.dst, packet.src, packet.dport, packet.sport)

        # Ignore the tail of a connection we have already reported.
        closed_at = recently_closed.get(key)
        if closed_at is not None:
            if packet.ts - closed_at <= CLOSED_FLOW_GRACE_S:
                continue
            del recently_closed[key]    # far enough apart to be a new connection

        session = open_sessions.get(key)
        if session is None:
            client_ip, server_ip, _client_port, server_port = key
            session = {
                "src": client_ip,
                "dst": server_ip,
                "dport": server_port,
                "start": packet.ts,
                "last": packet.ts,
                "bytes": 0,
                "sni": None,
            }
            open_sessions[key] = session

        session["last"] = packet.ts
        session["bytes"] += packet.wire_len

        # The requested server name appears once, in the first packet of the
        # handshake.
        if session["sni"] is None and packet.payload:
            session["sni"] = pcap_reader.parse_sni(packet.payload)

        if packet.fin or packet.rst:
            close_session(session)
            del open_sessions[key]
            recently_closed[key] = packet.ts

    # Captures routinely stop mid-conversation. Emit those sessions rather than
    # discarding them, or the last minute of every capture silently disappears.
    for session in open_sessions.values():
        close_session(session)

    observations.sort(key=_observation_time)
    return observations


def from_events(path: str, asn_lookup) -> list[Observation]:
    """Replay a generated scenario as Observations, in scenario time.

    Used for scoring, because scenario timestamps are exact and repeatable.
    """
    with open(path) as handle:
        events = json.load(handle)

    observations = []
    for event in events:
        destination_ip = event["dst"]
        # The simulated cloud names each endpoint after its address.
        server_name = f"{destination_ip.replace('.', '-')}.vendor-cloud.test"

        observations.append(_build_observation(
            start_time=event["t"],
            source_ip=SIMULATED_DEVICE_IP,
            destination_ip=destination_ip,
            destination_port=HTTPS_PORT,
            total_bytes=event["nbytes"],
            duration=REPLAY_SESSION_DURATION_S,
            server_name=server_name,
            asn_lookup=asn_lookup,
        ))

    observations.sort(key=_observation_time)
    return observations
