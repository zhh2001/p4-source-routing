import socket
import sys
import unittest
from pathlib import Path

from scapy.all import Ether, IP, UDP


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from source_route import (  # noqa: E402
    ETHERTYPE_IPV4,
    ETHERTYPE_SOURCE_ROUTE,
    PATHS,
    UDP_DESTINATION_PORT,
    UDP_SOURCE_PORT,
    SourceRouteHeader,
    build_packet,
    packet_payload,
)


def internet_checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(
        int.from_bytes(data[index : index + 2], "big")
        for index in range(0, len(data), 2)
    )
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


class SourceRoutePacketTest(unittest.TestCase):
    def test_path_profiles(self):
        self.assertEqual(PATHS["upper"]["route"], (2, 2, 1))
        self.assertEqual(PATHS["lower"]["route"], (3, 2, 1))
        self.assertEqual(PATHS["reverse-upper"]["route"], (2, 1, 1))
        self.assertEqual(PATHS["reverse-lower"]["route"], (3, 1, 1))
        self.assertEqual(PATHS["upper"]["dst_ip"], PATHS["lower"]["dst_ip"])
        self.assertEqual(PATHS["upper"]["src_ip"], PATHS["lower"]["src_ip"])

    def test_serialized_packet(self):
        token = "feedfacecafebeef"
        packet = build_packet("upper", token)
        serialized = bytes(packet)

        self.assertEqual(packet[Ether].type, ETHERTYPE_SOURCE_ROUTE)
        source_route = packet[SourceRouteHeader]
        self.assertEqual(source_route.next_header, ETHERTYPE_IPV4)
        self.assertEqual(source_route.route_length, 3)
        self.assertEqual(source_route.getfieldval("ports"), [2, 2, 1])

        ipv4 = packet[IP]
        self.assertEqual(ipv4.src, "10.0.1.1")
        self.assertEqual(ipv4.dst, "10.0.4.1")
        self.assertEqual(ipv4.ttl, 64)
        self.assertEqual(ipv4.ihl, 5)
        self.assertEqual(ipv4.len, 20 + 8 + len(packet_payload(token)))
        self.assertEqual(ipv4.id, 0x1234)

        udp = packet[UDP]
        self.assertEqual(udp.sport, UDP_SOURCE_PORT)
        self.assertEqual(udp.dport, UDP_DESTINATION_PORT)
        self.assertEqual(bytes(udp.payload), packet_payload(token))
        self.assertNotEqual(udp.chksum, 0)

        ip_offset = 14 + 3 + len(PATHS["upper"]["route"])
        ip_header = serialized[ip_offset : ip_offset + 20]
        self.assertEqual(internet_checksum(ip_header), 0)
        udp_segment = serialized[ip_offset + 20 : ip_offset + ipv4.len]
        pseudo_header = (
            socket.inet_aton(ipv4.src)
            + socket.inet_aton(ipv4.dst)
            + bytes((0, ipv4.proto))
            + len(udp_segment).to_bytes(2, "big")
        )
        self.assertEqual(internet_checksum(pseudo_header + udp_segment), 0)
        self.assertEqual(len(serialized), 14 + 3 + 3 + ipv4.len)

    def test_reverse_packet_endpoints(self):
        packet = build_packet("reverse-lower", "fedcba9876543210")
        self.assertEqual(packet[Ether].src, "00:00:00:00:04:01")
        self.assertEqual(packet[Ether].dst, "00:00:00:00:01:01")
        self.assertEqual(packet[IP].src, "10.0.4.1")
        self.assertEqual(packet[IP].dst, "10.0.1.1")
        self.assertEqual(
            packet[SourceRouteHeader].getfieldval("ports"),
            [3, 1, 1],
        )

    def test_rejects_invalid_input(self):
        with self.assertRaisesRegex(ValueError, "unknown path"):
            build_packet("missing", "token")
        with self.assertRaisesRegex(ValueError, "1 to 64"):
            build_packet("upper", "")
        with self.assertRaisesRegex(ValueError, "0..255"):
            build_packet("upper", "token", ttl=256)


if __name__ == "__main__":
    unittest.main(verbosity=2)
