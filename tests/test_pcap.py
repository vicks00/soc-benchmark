"""tools/pcap.py: the hand-rolled libpcap reader used by the network-tier scenario."""

from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from tools import pcap


def single_packet_capture() -> bytes:
    """One SYN from 192.0.2.10:49152 to 198.51.100.20:443, as classic libpcap bytes."""
    ethernet = b"\0" * 12 + struct.pack(">H", 0x0800)
    ip = bytearray(20)
    ip[0] = 0x45
    ip[2:4] = struct.pack(">H", 40)
    ip[9] = 6
    ip[12:16] = bytes((192, 0, 2, 10))
    ip[16:20] = bytes((198, 51, 100, 20))
    tcp = bytearray(20)
    tcp[0:4] = struct.pack(">HH", 49152, 443)
    tcp[12] = 0x50
    tcp[13] = 0x02
    frame = ethernet + ip + tcp
    global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    packet_header = struct.pack("<IIII", 1_700_000_000, 500_000, len(frame), len(frame))
    return global_header + packet_header + frame


class PcapTests(unittest.TestCase):
    def test_reads_a_tcp_packet_and_collapses_it_into_a_flow(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.pcap"
            path.write_bytes(single_packet_capture())
            packets = pcap.read_packets(path)

        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0]["src"], "192.0.2.10")
        self.assertEqual(packets[0]["dport"], 443)
        self.assertEqual(packets[0]["flags"], "S")

        flow = pcap.flows(packets)[0]
        self.assertEqual(flow["packets"], 1)
        self.assertTrue(flow["saw_syn"])

    def test_non_libpcap_input_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "not a classic libpcap file"):
            pcap.read_packet_bytes(b"\x00" * 64)


if __name__ == "__main__":
    unittest.main()
