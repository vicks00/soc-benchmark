"""Minimal classic-libpcap reader for Ethernet, IPv4, and TCP."""

from __future__ import annotations

import struct
from datetime import UTC, datetime

_MAGIC = {
    0xA1B2C3D4: ("<", 1_000_000),  # little-endian, microsecond resolution
    0xD4C3B2A1: (">", 1_000_000),
    0xA1B23C4D: ("<", 1_000_000_000),  # nanosecond resolution
    0x4D3CB2A1: (">", 1_000_000_000),
}
LINKTYPE_ETHERNET = 1


def read_packets(path) -> list[dict]:
    """Yield one dict per TCP/IPv4 packet: ts, src, dst, sport, dport, flags, payload_len."""
    with open(path, "rb") as capture:
        data = capture.read()
    return read_packet_bytes(data, str(path))


def read_packet_bytes(data: bytes, source: str = "<memory>") -> list[dict]:
    """Parse classic libpcap bytes without writing a temporary file."""
    if len(data) < 24:
        raise ValueError(f"{source}: too short to be a pcap file")

    magic = struct.unpack("<I", data[:4])[0]
    if magic not in _MAGIC:
        magic_be = struct.unpack(">I", data[:4])[0]
        if magic_be not in _MAGIC:
            raise ValueError(
                f"{source}: not a classic libpcap file (magic {magic:#x}). pcapng is not supported."
            )
        magic = magic_be
    endian, tick_div = _MAGIC[magic]

    linktype = struct.unpack(endian + "I", data[20:24])[0]
    if linktype != LINKTYPE_ETHERNET:
        raise ValueError(f"{source}: link type {linktype} is not Ethernet; unsupported.")

    packets, offset = [], 24
    while offset + 16 <= len(data):
        seconds, fraction, caplen, _original_len = struct.unpack(
            endian + "IIII", data[offset : offset + 16]
        )
        offset += 16
        frame = data[offset : offset + caplen]
        offset += caplen
        packet = _parse_frame(frame)
        if packet is None:
            continue
        packet["ts"] = datetime.fromtimestamp(seconds + fraction / tick_div, tz=UTC)
        packets.append(packet)
    return packets


def _parse_frame(frame: bytes) -> dict | None:
    if len(frame) < 14 or struct.unpack(">H", frame[12:14])[0] != 0x0800:  # IPv4 only
        return None
    ip = frame[14:]
    if len(ip) < 20:
        return None
    ihl = (ip[0] & 0x0F) * 4
    if ip[9] != 6:  # TCP only
        return None
    total_len = struct.unpack(">H", ip[2:4])[0]
    src = ".".join(str(b) for b in ip[12:16])
    dst = ".".join(str(b) for b in ip[16:20])

    tcp = ip[ihl:]
    if len(tcp) < 20:
        return None
    sport, dport = struct.unpack(">HH", tcp[0:4])
    data_off = (tcp[12] >> 4) * 4
    flag_bits = tcp[13]
    flags = "".join(
        name
        for bit, name in ((0x02, "S"), (0x10, "A"), (0x01, "F"), (0x04, "R"), (0x08, "P"))
        if flag_bits & bit
    )
    return {
        "src": src,
        "dst": dst,
        "sport": sport,
        "dport": dport,
        "flags": flags,
        "payload_len": max(0, total_len - ihl - data_off),
    }


def flows(packets: list[dict]) -> list[dict]:
    """Collapse packets into bidirectional TCP flows keyed on the client side of the handshake."""
    by_endpoints: dict[tuple, dict] = {}
    for packet in packets:
        forward = (packet["src"], packet["sport"], packet["dst"], packet["dport"])
        reverse = (packet["dst"], packet["dport"], packet["src"], packet["sport"])
        key = reverse if reverse in by_endpoints else forward
        flow = by_endpoints.setdefault(
            key,
            {
                "source_ip": key[0],
                "source_port": key[1],
                "destination_ip": key[2],
                "destination_port": key[3],
                "first_seen": packet["ts"],
                "last_seen": packet["ts"],
                "packets": 0,
                "bytes_to_server": 0,
                "bytes_to_client": 0,
                "saw_syn": False,
            },
        )
        flow["packets"] += 1
        flow["last_seen"] = max(flow["last_seen"], packet["ts"])
        flow["first_seen"] = min(flow["first_seen"], packet["ts"])
        if packet["flags"] == "S":
            flow["saw_syn"] = True
        if (packet["src"], packet["sport"]) == (key[0], key[1]):
            flow["bytes_to_server"] += packet["payload_len"]
        else:
            flow["bytes_to_client"] += packet["payload_len"]
    return sorted(by_endpoints.values(), key=lambda flow: flow["first_seen"])
