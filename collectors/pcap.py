"""Minimal classic-pcap reader (stdlib only).

Enough of the format to pull TCP/IPv4 flows off a tcpdump capture without
pulling in scapy.  Handles the link types you actually meet: Ethernet,
BSD loopback (macOS lo0), raw IP and Linux cooked.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

DLT_NULL, DLT_EN10MB, DLT_RAW, DLT_LINUX_SLL, DLT_LOOP = 0, 1, 101, 113, 108


@dataclass
class Packet:
    ts: float
    src: str
    dst: str
    sport: int
    dport: int
    flags: int
    payload: bytes
    wire_len: int

    @property
    def syn(self) -> bool: return bool(self.flags & 0x02) and not (self.flags & 0x10)
    @property
    def fin(self) -> bool: return bool(self.flags & 0x01)
    @property
    def rst(self) -> bool: return bool(self.flags & 0x04)


def _ip(b: bytes) -> str:
    return ".".join(str(x) for x in b)


def _strip_link(data: bytes, dlt: int) -> bytes | None:
    if dlt == DLT_EN10MB:
        if len(data) < 14:
            return None
        etype = struct.unpack("!H", data[12:14])[0]
        off = 14
        while etype in (0x8100, 0x88A8) and len(data) >= off + 4:   # VLAN tags
            etype = struct.unpack("!H", data[off + 2:off + 4])[0]
            off += 4
        return data[off:] if etype == 0x0800 else None
    if dlt in (DLT_NULL, DLT_LOOP):
        if len(data) < 4:
            return None
        fam = struct.unpack("<I", data[:4])[0]
        if fam not in (2, 0x02000000):
            fam = struct.unpack(">I", data[:4])[0]
        return data[4:] if fam == 2 else None
    if dlt == DLT_RAW:
        return data
    if dlt == DLT_LINUX_SLL:
        if len(data) < 16:
            return None
        return data[16:] if struct.unpack("!H", data[14:16])[0] == 0x0800 else None
    return None


def read(path: str):
    """Yield Packet for every TCP/IPv4 packet in a classic pcap file."""
    with open(path, "rb") as fh:
        gh = fh.read(24)
        if len(gh) < 24:
            return
        magic = gh[:4]
        if magic == b"\xa1\xb2\xc3\xd4":
            endian, scale = ">", 1e-6
        elif magic == b"\xd4\xc3\xb2\xa1":
            endian, scale = "<", 1e-6
        elif magic == b"\xa1\xb2\x3c\x4d":
            endian, scale = ">", 1e-9
        elif magic == b"\x4d\x3c\xb2\xa1":
            endian, scale = "<", 1e-9
        else:
            raise ValueError(f"not a classic pcap (magic {magic.hex()}); "
                             "pcapng is unsupported -- capture with tcpdump -w")
        dlt = struct.unpack(endian + "I", gh[20:24])[0]

        while True:
            ph = fh.read(16)
            if len(ph) < 16:
                return
            ts_s, ts_f, incl, _orig = struct.unpack(endian + "IIII", ph)
            data = fh.read(incl)
            if len(data) < incl:
                return
            ipp = _strip_link(data, dlt)
            if not ipp or len(ipp) < 20 or (ipp[0] >> 4) != 4:
                continue
            ihl = (ipp[0] & 0x0F) * 4
            if ipp[9] != 6 or len(ipp) < ihl + 20:      # TCP only
                continue
            total_len = struct.unpack("!H", ipp[2:4])[0]
            src, dst = _ip(ipp[12:16]), _ip(ipp[16:20])
            tcp = ipp[ihl:]
            sport, dport = struct.unpack("!HH", tcp[:4])
            doff = (tcp[12] >> 4) * 4
            flags = tcp[13]
            yield Packet(
                ts=ts_s + ts_f * scale,
                src=src, dst=dst, sport=sport, dport=dport, flags=flags,
                payload=tcp[doff:], wire_len=total_len,
            )


def parse_sni(payload: bytes) -> str | None:
    """Extract server_name from a TLS ClientHello, if this is one."""
    try:
        if len(payload) < 6 or payload[0] != 0x16:      # handshake record
            return None
        if payload[5] != 0x01:                          # ClientHello
            return None
        p = 5 + 4 + 2 + 32                              # hdr, type/len, version, random
        sid = payload[p]; p += 1 + sid
        cs = struct.unpack("!H", payload[p:p + 2])[0]; p += 2 + cs
        cm = payload[p]; p += 1 + cm
        ext_total = struct.unpack("!H", payload[p:p + 2])[0]; p += 2
        end = p + ext_total
        while p + 4 <= end:
            etype, elen = struct.unpack("!HH", payload[p:p + 4]); p += 4
            if etype == 0x0000:                         # server_name
                q = p + 2 + 1                           # list len, name type
                nlen = struct.unpack("!H", payload[q:q + 2])[0]
                return payload[q + 2:q + 2 + nlen].decode("ascii", "replace")
            p += elen
    except (IndexError, struct.error, UnicodeDecodeError):
        return None
    return None
