import socket
import sys
import unittest
from pathlib import Path

from scapy.all import Ether, IP, TCP, UDP


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from source_route import (  # noqa: E402
    ETHERTYPE_IPV4,
    ETHERTYPE_SOURCE_ROUTE,
    PATHS,
    TCP_ACKNOWLEDGMENT,
    TCP_DESTINATION_PORT,
    TCP_SEQUENCE,
    TCP_SOURCE_PORT,
    TCP_WINDOW,
    UDP_DESTINATION_PORT,
    UDP_SOURCE_PORT,
    SourceRouteHeader,
    build_packet,
    build_tcp_packet,
    packet_payload,
    send_frame,
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

    def test_serialized_tcp_packet(self):
        token = "tcp-builder"
        packet = build_tcp_packet("upper", token)
        serialized = bytes(packet)
        ipv4 = packet[IP]
        tcp = packet[TCP]

        self.assertEqual(ipv4.proto, socket.IPPROTO_TCP)
        self.assertEqual(ipv4.len, 20 + 20 + len(packet_payload(token)))
        self.assertEqual(tcp.sport, TCP_SOURCE_PORT)
        self.assertEqual(tcp.dport, TCP_DESTINATION_PORT)
        self.assertEqual(tcp.seq, TCP_SEQUENCE)
        self.assertEqual(tcp.ack, TCP_ACKNOWLEDGMENT)
        self.assertEqual(int(tcp.flags), 0x18)
        self.assertEqual(tcp.dataofs, 5)
        self.assertEqual(tcp.window, TCP_WINDOW)
        self.assertEqual(bytes(tcp.payload), packet_payload(token))
        self.assertNotEqual(tcp.chksum, 0)

        ip_offset = 14 + 3 + len(PATHS["upper"]["route"])
        tcp_segment = serialized[ip_offset + 20 : ip_offset + ipv4.len]
        pseudo_header = (
            socket.inet_aton(ipv4.src)
            + socket.inet_aton(ipv4.dst)
            + bytes((0, ipv4.proto))
            + len(tcp_segment).to_bytes(2, "big")
        )
        self.assertEqual(internet_checksum(pseudo_header + tcp_segment), 0)

    def test_explicit_source_route_encoding(self):
        packet = build_packet(
            "upper",
            "custom-header",
            ttl=2,
            route=(2, 3, 1, 7),
            route_length=4,
            next_header=0x86DD,
            ipv4_fields={"flags": "MF"},
        )
        serialized = bytes(packet)
        ip_offset = 17 + 4

        self.assertEqual(serialized[14:17], b"\x86\xdd\x04")
        self.assertEqual(serialized[17:ip_offset], b"\x02\x03\x01\x07")
        self.assertEqual(serialized[ip_offset] >> 4, 4)
        self.assertEqual(serialized[ip_offset + 8], 2)
        self.assertEqual(
            int.from_bytes(serialized[ip_offset + 6 : ip_offset + 8], "big") & 0x2000,
            0x2000,
        )
        self.assertEqual(
            internet_checksum(serialized[ip_offset : ip_offset + 20]),
            0,
        )

    def test_route_length_boundaries_can_be_serialized(self):
        empty = bytes(
            build_packet(
                "upper",
                "empty-route",
                route=(),
                route_length=0,
            )
        )
        oversized = bytes(
            build_packet(
                "upper",
                "oversized-route",
                route=(2, 2, 1, 1, 1, 1, 1, 1, 1),
                route_length=9,
            )
        )

        self.assertEqual(empty[16], 0)
        self.assertEqual(empty[17] >> 4, 4)
        self.assertEqual(oversized[16], 9)
        self.assertEqual(oversized[17:26], bytes((2, 2, 1, 1, 1, 1, 1, 1, 1)))
        self.assertEqual(oversized[26] >> 4, 4)

    def test_rejects_invalid_input(self):
        with self.assertRaisesRegex(ValueError, "unknown path"):
            build_packet("missing", "token")
        with self.assertRaisesRegex(ValueError, "1 to 64"):
            build_packet("upper", "")
        with self.assertRaisesRegex(ValueError, "0..255"):
            build_packet("upper", "token", ttl=256)
        with self.assertRaisesRegex(ValueError, "route ports"):
            build_packet("upper", "token", route=(256,))
        with self.assertRaisesRegex(ValueError, "route length"):
            build_packet("upper", "token", route_length=256)
        with self.assertRaisesRegex(ValueError, "next header"):
            build_packet("upper", "token", next_header=0x10000)
        with self.assertRaisesRegex(TypeError, "frame must be bytes"):
            send_frame("frame", "missing-interface")
        with self.assertRaisesRegex(ValueError, "at least 14"):
            send_frame(b"short", "missing-interface")


if __name__ == "__main__":
    unittest.main(verbosity=2)
