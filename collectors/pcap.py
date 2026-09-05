"""A minimal reader for classic pcap capture files, using only the stdlib.

This exists so the project has no scapy dependency. A demo that needs
`pip install` on conference Wi-Fi is a demo that fails.

It reads exactly what this project needs and nothing more: IPv4 TCP packets,
plus the server name out of a TLS ClientHello.

A pcap file is laid out as:

    [ 24-byte file header ][ packet ][ packet ][ packet ] ...

and each packet is:

    [ 16-byte record header ][ raw bytes captured off the wire ]

The raw bytes start with a link-layer header whose format depends on the
interface the capture came from -- Ethernet, loopback, and so on. Stripping
that header is what `_strip_link_layer_header` does; after that we have an IP
packet.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass


# --------------------------------------------------------------------------
# File-format constants
# --------------------------------------------------------------------------

FILE_HEADER_SIZE = 24
RECORD_HEADER_SIZE = 16

# The first four bytes identify both the file format and its byte order.
MAGIC_BIG_ENDIAN_MICROSECONDS = b"\xa1\xb2\xc3\xd4"
MAGIC_LITTLE_ENDIAN_MICROSECONDS = b"\xd4\xc3\xb2\xa1"
MAGIC_BIG_ENDIAN_NANOSECONDS = b"\xa1\xb2\x3c\x4d"
MAGIC_LITTLE_ENDIAN_NANOSECONDS = b"\x4d\x3c\xb2\xa1"

MICROSECONDS_PER_SECOND = 1e-6
NANOSECONDS_PER_SECOND = 1e-9

# Link-layer types ("DLT"), telling us what the captured bytes start with.
LINK_TYPE_LOOPBACK_BSD = 0        # macOS lo0
LINK_TYPE_ETHERNET = 1
LINK_TYPE_RAW_IP = 101            # no link header at all
LINK_TYPE_LOOPBACK_OPENBSD = 108
LINK_TYPE_LINUX_COOKED = 113

# Link-layer header sizes.
ETHERNET_HEADER_SIZE = 14
ETHERNET_TYPE_OFFSET = 12         # where the "what's inside" field sits
VLAN_TAG_SIZE = 4
LOOPBACK_HEADER_SIZE = 4          # a 4-byte address-family number
LINUX_COOKED_HEADER_SIZE = 16
LINUX_COOKED_TYPE_OFFSET = 14

# Values of the Ethernet "what's inside" field that we care about.
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_VLAN_STACKED = 0x88A8

# The loopback header carries an address family; 2 is AF_INET (IPv4).
ADDRESS_FAMILY_IPV4 = 2

# IPv4 header fields.
IP_MINIMUM_HEADER_SIZE = 20
IP_VERSION_SHIFT = 4              # version lives in the high nibble of byte 0
IP_HEADER_LENGTH_MASK = 0x0F      # header length in the low nibble, in 4-byte words
IP_HEADER_LENGTH_UNIT = 4
IP_TOTAL_LENGTH_OFFSET = 2
IP_PROTOCOL_OFFSET = 9
IP_SOURCE_OFFSET = 12
IP_DESTINATION_OFFSET = 16
IP_ADDRESS_SIZE = 4
IP_PROTOCOL_TCP = 6

# TCP header fields.
TCP_MINIMUM_HEADER_SIZE = 20
TCP_DATA_OFFSET_BYTE = 12         # high nibble = header length in 4-byte words
TCP_DATA_OFFSET_SHIFT = 4
TCP_DATA_OFFSET_UNIT = 4
TCP_FLAGS_BYTE = 13

# Individual TCP flag bits.
TCP_FLAG_FIN = 0x01
TCP_FLAG_SYN = 0x02
TCP_FLAG_RESET = 0x04
TCP_FLAG_ACK = 0x10

# TLS record and handshake identifiers.
TLS_RECORD_TYPE_HANDSHAKE = 0x16
TLS_HANDSHAKE_TYPE_CLIENT_HELLO = 0x01
TLS_RECORD_HEADER_SIZE = 5
TLS_HANDSHAKE_HEADER_SIZE = 4
TLS_VERSION_SIZE = 2
TLS_RANDOM_SIZE = 32
TLS_EXTENSION_SERVER_NAME = 0x0000


@dataclass
class Packet:
    """One TCP/IPv4 packet, with the parts this project uses."""

    ts: float
    src: str
    dst: str
    sport: int
    dport: int
    flags: int
    payload: bytes
    wire_len: int       # length on the wire, which may exceed what was captured

    @property
    def syn(self) -> bool:
        """True for a connection opening (SYN without ACK)."""
        if self.flags & TCP_FLAG_ACK:
            return False
        return bool(self.flags & TCP_FLAG_SYN)

    @property
    def fin(self) -> bool:
        return bool(self.flags & TCP_FLAG_FIN)

    @property
    def rst(self) -> bool:
        return bool(self.flags & TCP_FLAG_RESET)


def _format_ip_address(raw: bytes) -> str:
    """Turn four raw bytes into dotted-quad text."""
    octets = []
    for byte_value in raw:
        octets.append(str(byte_value))
    return ".".join(octets)


def _strip_link_layer_header(captured: bytes, link_type: int) -> bytes | None:
    """Remove the link-layer header and return the IP packet inside it.

    Returns None when the frame does not contain IPv4 -- ARP, IPv6, and so on.
    """
    if link_type == LINK_TYPE_ETHERNET:
        if len(captured) < ETHERNET_HEADER_SIZE:
            return None

        type_start = ETHERNET_TYPE_OFFSET
        ethertype = struct.unpack("!H", captured[type_start:type_start + 2])[0]
        payload_start = ETHERNET_HEADER_SIZE

        # A VLAN-tagged frame inserts 4 bytes before the real ethertype, and
        # frames can carry more than one tag, so keep unwrapping.
        while ethertype in (ETHERTYPE_VLAN, ETHERTYPE_VLAN_STACKED):
            if len(captured) < payload_start + VLAN_TAG_SIZE:
                return None
            type_start = payload_start + 2
            ethertype = struct.unpack("!H", captured[type_start:type_start + 2])[0]
            payload_start += VLAN_TAG_SIZE

        if ethertype != ETHERTYPE_IPV4:
            return None
        return captured[payload_start:]

    if link_type in (LINK_TYPE_LOOPBACK_BSD, LINK_TYPE_LOOPBACK_OPENBSD):
        if len(captured) < LOOPBACK_HEADER_SIZE:
            return None
        # The address family is written in host byte order, so try little-endian
        # first and fall back to big-endian.
        family = struct.unpack("<I", captured[:LOOPBACK_HEADER_SIZE])[0]
        if family != ADDRESS_FAMILY_IPV4:
            family = struct.unpack(">I", captured[:LOOPBACK_HEADER_SIZE])[0]
        if family != ADDRESS_FAMILY_IPV4:
            return None
        return captured[LOOPBACK_HEADER_SIZE:]

    if link_type == LINK_TYPE_RAW_IP:
        return captured

    if link_type == LINK_TYPE_LINUX_COOKED:
        if len(captured) < LINUX_COOKED_HEADER_SIZE:
            return None
        type_start = LINUX_COOKED_TYPE_OFFSET
        ethertype = struct.unpack("!H", captured[type_start:type_start + 2])[0]
        if ethertype != ETHERTYPE_IPV4:
            return None
        return captured[LINUX_COOKED_HEADER_SIZE:]

    return None


def _read_file_header(handle) -> tuple[str, float, int]:
    """Read the 24-byte file header.

    Returns the struct byte-order character, the timestamp scale, and the
    link-layer type.
    """
    header = handle.read(FILE_HEADER_SIZE)
    if len(header) < FILE_HEADER_SIZE:
        raise ValueError("file is too short to be a pcap capture")

    magic = header[:4]
    if magic == MAGIC_BIG_ENDIAN_MICROSECONDS:
        byte_order, timestamp_scale = ">", MICROSECONDS_PER_SECOND
    elif magic == MAGIC_LITTLE_ENDIAN_MICROSECONDS:
        byte_order, timestamp_scale = "<", MICROSECONDS_PER_SECOND
    elif magic == MAGIC_BIG_ENDIAN_NANOSECONDS:
        byte_order, timestamp_scale = ">", NANOSECONDS_PER_SECOND
    elif magic == MAGIC_LITTLE_ENDIAN_NANOSECONDS:
        byte_order, timestamp_scale = "<", NANOSECONDS_PER_SECOND
    else:
        raise ValueError(
            f"not a classic pcap file (magic bytes {magic.hex()}); "
            "pcapng is not supported -- capture with 'tcpdump -w'"
        )

    link_type = struct.unpack(byte_order + "I", header[20:24])[0]
    return byte_order, timestamp_scale, link_type


def read(path: str):
    """Yield a Packet for every TCP/IPv4 packet in a classic pcap file.

    Anything else in the capture -- UDP, IPv6, ARP, truncated records -- is
    skipped rather than raising, because real captures contain all of it.
    """
    with open(path, "rb") as handle:
        byte_order, timestamp_scale, link_type = _read_file_header(handle)

        while True:
            record_header = handle.read(RECORD_HEADER_SIZE)
            if len(record_header) < RECORD_HEADER_SIZE:
                return          # clean end of file

            seconds, fraction, captured_length, _original_length = struct.unpack(
                byte_order + "IIII", record_header
            )

            captured = handle.read(captured_length)
            if len(captured) < captured_length:
                return          # file truncated mid-packet

            ip_packet = _strip_link_layer_header(captured, link_type)
            if ip_packet is None:
                continue
            if len(ip_packet) < IP_MINIMUM_HEADER_SIZE:
                continue
            if (ip_packet[0] >> IP_VERSION_SHIFT) != 4:
                continue        # not IPv4

            ip_header_length = (ip_packet[0] & IP_HEADER_LENGTH_MASK) * IP_HEADER_LENGTH_UNIT
            if ip_packet[IP_PROTOCOL_OFFSET] != IP_PROTOCOL_TCP:
                continue
            if len(ip_packet) < ip_header_length + TCP_MINIMUM_HEADER_SIZE:
                continue

            total_length = struct.unpack(
                "!H", ip_packet[IP_TOTAL_LENGTH_OFFSET:IP_TOTAL_LENGTH_OFFSET + 2]
            )[0]
            source_ip = _format_ip_address(
                ip_packet[IP_SOURCE_OFFSET:IP_SOURCE_OFFSET + IP_ADDRESS_SIZE]
            )
            destination_ip = _format_ip_address(
                ip_packet[IP_DESTINATION_OFFSET:IP_DESTINATION_OFFSET + IP_ADDRESS_SIZE]
            )

            tcp_segment = ip_packet[ip_header_length:]
            source_port, destination_port = struct.unpack("!HH", tcp_segment[:4])
            tcp_header_length = (
                (tcp_segment[TCP_DATA_OFFSET_BYTE] >> TCP_DATA_OFFSET_SHIFT)
                * TCP_DATA_OFFSET_UNIT
            )
            tcp_flags = tcp_segment[TCP_FLAGS_BYTE]

            yield Packet(
                ts=seconds + fraction * timestamp_scale,
                src=source_ip,
                dst=destination_ip,
                sport=source_port,
                dport=destination_port,
                flags=tcp_flags,
                payload=tcp_segment[tcp_header_length:],
                wire_len=total_length,
            )


def parse_sni(payload: bytes) -> str | None:
    """Pull the requested server name out of a TLS ClientHello.

    The ClientHello has a run of variable-length fields before the extension
    list, so the only way to reach the extensions is to walk past each one in
    turn. Returns None whenever this is not a ClientHello or has no server-name
    extension.
    """
    try:
        if len(payload) < TLS_RECORD_HEADER_SIZE + 1:
            return None
        if payload[0] != TLS_RECORD_TYPE_HANDSHAKE:
            return None
        if payload[TLS_RECORD_HEADER_SIZE] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO:
            return None

        # Skip the fixed-size preamble: record header, handshake header,
        # protocol version, and the 32-byte client random.
        cursor = (TLS_RECORD_HEADER_SIZE + TLS_HANDSHAKE_HEADER_SIZE
                  + TLS_VERSION_SIZE + TLS_RANDOM_SIZE)

        session_id_length = payload[cursor]
        cursor += 1 + session_id_length

        cipher_suites_length = struct.unpack("!H", payload[cursor:cursor + 2])[0]
        cursor += 2 + cipher_suites_length

        compression_methods_length = payload[cursor]
        cursor += 1 + compression_methods_length

        extensions_length = struct.unpack("!H", payload[cursor:cursor + 2])[0]
        cursor += 2
        extensions_end = cursor + extensions_length

        while cursor + 4 <= extensions_end:
            extension_type, extension_length = struct.unpack("!HH", payload[cursor:cursor + 4])
            cursor += 4

            if extension_type == TLS_EXTENSION_SERVER_NAME:
                # Inside: a 2-byte list length, a 1-byte name type, then the
                # 2-byte name length followed by the name itself.
                name_cursor = cursor + 2 + 1
                name_length = struct.unpack("!H", payload[name_cursor:name_cursor + 2])[0]
                name_start = name_cursor + 2
                name_bytes = payload[name_start:name_start + name_length]
                return name_bytes.decode("ascii", "replace")

            cursor += extension_length

    except (IndexError, struct.error, UnicodeDecodeError):
        # Malformed or truncated: not worth an exception, we simply have no SNI.
        return None

    return None
