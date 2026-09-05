"""Static IP -> ASN table for the test rig.

The rig has no real ASNs, so detection rules resolve through this fixture.
Collectors take asn_lookup as a parameter, so swapping in a real source
(Team Cymru DNS, MaxMind, a pyasn table) is a one-line change that does not
touch detection logic.
"""

from __future__ import annotations

import json

UNKNOWN = (0, "UNKNOWN", "??")

TEST_ASN: dict[str, tuple[int, str, str]] = {
    "172.28.0.10": (64500, "VENDOR-CLOUD-PRIMARY", "DE"),
    "172.28.0.11": (64500, "VENDOR-CLOUD-SECONDARY", "DE"),
    "172.28.0.12": (64501, "VENDOR-CDN-FIRMWARE", "NL"),
    "172.28.0.20": (64666, "UNKNOWN-TRANSIT", "CN"),
    "172.28.0.21": (64500, "VENDOR-CLOUD-PRIMARY", "CN"),   # same ASN, wrong country
    "172.28.0.22": (64777, "COMMERCIAL-VPN", "RU"),
}

# What the device is permitted to talk to.  Everything else is a finding.
ALLOWED_ASNS: set[int] = {64500, 64501}
ALLOWED_COUNTRIES: set[str] = {"DE", "NL"}


def asn_lookup(ip: str) -> tuple[int, str, str]:
    return TEST_ASN.get(ip, UNKNOWN)


def load_asn_map(path: str):
    """Build an asn_lookup function from a JSON file of real addresses.

    The demo runs on a real LAN, where the built-in 172.28.x fixtures do not
    apply. The file maps each address the demo will actually contact:

        {
          "192.168.1.50": [64500, "VENDOR-CLOUD-PRIMARY", "DE"],
          "192.168.1.77": [64666, "UNKNOWN-TRANSIT", "CN"]
        }

    Anything not listed resolves to UNKNOWN, which the destination rule treats
    as unallowlisted -- so a forgotten entry shows up as an alert rather than
    silently passing.
    """
    with open(path) as handle:
        raw = json.load(handle)

    table = {}
    for address, record in raw.items():
        table[address] = (int(record[0]), str(record[1]), str(record[2]))

    def lookup(ip: str):
        return table.get(ip, UNKNOWN)

    return lookup
