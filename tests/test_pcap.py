"""Round-trip tests for the pcap reader.

Each test builds a capture file byte by byte, so the expected values are known
exactly rather than inferred from whatever happened to be on the wire.

Run: python3 -m tests.test_pcap
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collectors import pcap

RESULTS = []


def check(name, condition):
    RESULTS.append((name, bool(condition)))
    if condition:
        status = "PASS"
    else:
        status = "FAIL"
    print(f"  [{status}] {name}")


def build_tcp_segment(source_port, destination_port, flags, payload=b""):
    """A 20-byte TCP header with no options, plus its payload."""
    sequence_number = 0
    acknowledgement_number = 0
    data_offset_words = 5                       # 20 bytes / 4
    data_offset_byte = data_offset_words << 4
    window_size = 8192
    checksum = 0
    urgent_pointer = 0

    header = struct.pack(
        "!HHIIBBHHH",
        source_port, destination_port,
        sequence_number, acknowledgement_number,
        data_offset_byte, flags,
        window_size, checksum, urgent_pointer,
    )
    return header + payload


def build_ipv4_packet(source_ip, destination_ip, tcp_segment):
    """A 20-byte IPv4 header wrapping a TCP segment."""
    version_and_header_length = (4 << 4) | 5    # IPv4, 20-byte header
    type_of_service = 0
    total_length = 20 + len(tcp_segment)
    identification = 0
    flags_and_fragment = 0
    time_to_live = 64
    protocol = pcap.IP_PROTOCOL_TCP
    checksum = 0

    def packed_ip(text):
        parts = []
        for octet in text.split("."):
            parts.append(int(octet))
        return bytes(parts)

    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_and_header_length, type_of_service, total_length,
        identification, flags_and_fragment,
        time_to_live, protocol, checksum,
        packed_ip(source_ip), packed_ip(destination_ip),
    )
    return header + tcp_segment


def write_capture(path, link_type, frames, nanosecond_timestamps=False):
    """Write a classic pcap file containing the given link-layer frames."""
    if nanosecond_timestamps:
        magic = pcap.MAGIC_LITTLE_ENDIAN_NANOSECONDS
        fraction = 500_000_000                  # 0.5 s expressed in nanoseconds
    else:
        magic = pcap.MAGIC_LITTLE_ENDIAN_MICROSECONDS
        fraction = 500_000                      # 0.5 s expressed in microseconds

    with open(path, "wb") as handle:
        handle.write(magic)
        handle.write(struct.pack("<HHiIII", 2, 4, 0, 0, 65535, link_type))
        for index, frame in enumerate(frames):
            seconds = 1_000_000 + index
            handle.write(struct.pack("<IIII", seconds, fraction, len(frame), len(frame)))
            handle.write(frame)


def ethernet_frame(ip_packet, vlan_tags=0):
    """Wrap an IP packet in an Ethernet header, optionally VLAN-tagged."""
    destination_mac = b"\x11" * 6
    source_mac = b"\x22" * 6
    frame = destination_mac + source_mac

    for _ in range(vlan_tags):
        frame += struct.pack("!HH", pcap.ETHERTYPE_VLAN, 0x0064)
    frame += struct.pack("!H", pcap.ETHERTYPE_IPV4)
    return frame + ip_packet


def loopback_frame(ip_packet):
    """Wrap an IP packet in a BSD loopback header (macOS lo0)."""
    return struct.pack("<I", pcap.ADDRESS_FAMILY_IPV4) + ip_packet


def build_client_hello(server_name):
    """A TLS ClientHello carrying one server-name extension."""
    name_bytes = server_name.encode("ascii")

    server_name_extension = (
        struct.pack("!H", len(name_bytes) + 3)      # server-name list length
        + b"\x00"                                    # name type: host_name
        + struct.pack("!H", len(name_bytes))
        + name_bytes
    )
    extensions = (
        struct.pack("!HH", pcap.TLS_EXTENSION_SERVER_NAME, len(server_name_extension))
        + server_name_extension
    )

    body = (
        b"\x03\x03"                                  # client version TLS 1.2
        + b"\xAB" * pcap.TLS_RANDOM_SIZE             # client random
        + b"\x00"                                    # session id length 0
        + struct.pack("!H", 2) + b"\xC0\x2F"         # one cipher suite
        + b"\x01\x00"                                # one compression method
        + struct.pack("!H", len(extensions)) + extensions
    )
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body   # 3-byte length
    record = (
        bytes([pcap.TLS_RECORD_TYPE_HANDSHAKE])
        + b"\x03\x03"
        + struct.pack("!H", len(handshake))
        + handshake
    )
    return record


def main():
    os.makedirs("runs/t", exist_ok=True)
    print("pcap reader round-trip")

    # --- plain Ethernet -------------------------------------------------
    segment = build_tcp_segment(54321, 443, pcap.TCP_FLAG_SYN)
    packet = build_ipv4_packet("10.0.0.5", "10.0.0.10", segment)
    write_capture("runs/t/eth.pcap", pcap.LINK_TYPE_ETHERNET, [ethernet_frame(packet)])

    packets = list(pcap.read("runs/t/eth.pcap"))
    check("ethernet: one packet read", len(packets) == 1)
    if packets:
        first = packets[0]
        check("ethernet: source address", first.src == "10.0.0.5")
        check("ethernet: destination address", first.dst == "10.0.0.10")
        check("ethernet: ports", (first.sport, first.dport) == (54321, 443))
        check("ethernet: SYN recognised", first.syn is True)
        check("ethernet: not FIN or RST", not first.fin and not first.rst)
        check("ethernet: wire length", first.wire_len == 20 + len(segment))
        check("ethernet: timestamp", abs(first.ts - 1_000_000.5) < 1e-6)

    # --- VLAN-tagged, including double tagging --------------------------
    write_capture("runs/t/vlan.pcap", pcap.LINK_TYPE_ETHERNET,
                  [ethernet_frame(packet, vlan_tags=1),
                   ethernet_frame(packet, vlan_tags=2)])
    vlan_packets = list(pcap.read("runs/t/vlan.pcap"))
    check("vlan: both tagged frames parsed", len(vlan_packets) == 2)
    if len(vlan_packets) == 2:
        check("vlan: addresses survive tag stripping",
              vlan_packets[0].src == "10.0.0.5" and vlan_packets[1].dst == "10.0.0.10")

    # --- BSD loopback (macOS lo0) ---------------------------------------
    write_capture("runs/t/loop.pcap", pcap.LINK_TYPE_LOOPBACK_BSD, [loopback_frame(packet)])
    loopback_packets = list(pcap.read("runs/t/loop.pcap"))
    check("loopback: packet parsed", len(loopback_packets) == 1)
    if loopback_packets:
        check("loopback: addresses", loopback_packets[0].src == "10.0.0.5")

    # --- raw IP, no link header -----------------------------------------
    write_capture("runs/t/raw.pcap", pcap.LINK_TYPE_RAW_IP, [packet])
    raw_packets = list(pcap.read("runs/t/raw.pcap"))
    check("raw ip: packet parsed", len(raw_packets) == 1)

    # --- nanosecond timestamps ------------------------------------------
    write_capture("runs/t/nano.pcap", pcap.LINK_TYPE_ETHERNET,
                  [ethernet_frame(packet)], nanosecond_timestamps=True)
    nano_packets = list(pcap.read("runs/t/nano.pcap"))
    check("nanosecond timestamps scaled correctly",
          nano_packets and abs(nano_packets[0].ts - 1_000_000.5) < 1e-6)

    # --- FIN and RST flags ----------------------------------------------
    fin_packet = build_ipv4_packet(
        "10.0.0.5", "10.0.0.10",
        build_tcp_segment(54321, 443, pcap.TCP_FLAG_FIN | pcap.TCP_FLAG_ACK))
    rst_packet = build_ipv4_packet(
        "10.0.0.5", "10.0.0.10",
        build_tcp_segment(54321, 443, pcap.TCP_FLAG_RESET))
    write_capture("runs/t/flags.pcap", pcap.LINK_TYPE_ETHERNET,
                  [ethernet_frame(fin_packet), ethernet_frame(rst_packet)])
    flag_packets = list(pcap.read("runs/t/flags.pcap"))
    check("FIN detected", flag_packets and flag_packets[0].fin is True)
    check("RST detected", len(flag_packets) > 1 and flag_packets[1].rst is True)
    check("SYN+ACK is not treated as a connection opening",
          flag_packets and flag_packets[0].syn is False)

    # --- non-IPv4 frames are skipped, not fatal --------------------------
    arp_frame = b"\x11" * 6 + b"\x22" * 6 + struct.pack("!H", 0x0806) + b"\x00" * 28
    write_capture("runs/t/mixed.pcap", pcap.LINK_TYPE_ETHERNET,
                  [arp_frame, ethernet_frame(packet)])
    mixed_packets = list(pcap.read("runs/t/mixed.pcap"))
    check("non-IPv4 frames skipped without error", len(mixed_packets) == 1)

    # --- truncated file ends cleanly -------------------------------------
    with open("runs/t/eth.pcap", "rb") as handle:
        full = handle.read()
    with open("runs/t/trunc.pcap", "wb") as handle:
        handle.write(full[:-10])
    check("truncated capture ends cleanly", list(pcap.read("runs/t/trunc.pcap")) == [])

    # --- pcapng is rejected with a clear message -------------------------
    with open("runs/t/ng.pcap", "wb") as handle:
        handle.write(b"\x0a\x0d\x0d\x0a" + b"\x00" * 40)
    rejected = False
    try:
        list(pcap.read("runs/t/ng.pcap"))
    except ValueError as error:
        rejected = "pcapng" in str(error)
    check("pcapng rejected with an explanatory error", rejected)

    # --- SNI extraction --------------------------------------------------
    hello = build_client_hello("vendor-cloud.test")
    check("SNI extracted from ClientHello", pcap.parse_sni(hello) == "vendor-cloud.test")
    check("SNI returns None for non-handshake bytes", pcap.parse_sni(b"\x17\x03\x03\x00\x10") is None)
    check("SNI returns None for truncated input", pcap.parse_sni(hello[:12]) is None)

    failed = []
    for name, ok in RESULTS:
        if not ok:
            failed.append(name)
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} passed")
    if failed:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
