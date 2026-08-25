import contextlib
import dataclasses
import os
import select
import selectors
import socket
import struct
import subprocess
import sys
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mininet"))
sys.path.insert(0, str(ROOT / "tools"))

from topology import SourceRoutingNetwork  # noqa: E402
from source_route import (  # noqa: E402
    ETHERTYPE_IPV4,
    ETHERTYPE_SOURCE_ROUTE,
    PATHS,
    UDP_DESTINATION_PORT,
    UDP_SOURCE_PORT,
    packet_payload,
)


LINK_INTERFACES = {
    "h1-s1": "s1-eth1",
    "s1-s2": "s2-eth1",
    "s1-s3": "s3-eth1",
    "s2-s4": "s4-eth2",
    "s3-s4": "s4-eth3",
    "s4-h2": "s4-eth1",
}

EXPECTED_PATHS = {
    "upper": (
        ("h1-s1", (2, 2, 1), 64),
        ("s1-s2", (2, 1), 63),
        ("s2-s4", (1,), 62),
        ("s4-h2", None, 61),
    ),
    "lower": (
        ("h1-s1", (3, 2, 1), 64),
        ("s1-s3", (2, 1), 63),
        ("s3-s4", (1,), 62),
        ("s4-h2", None, 61),
    ),
    "reverse-upper": (
        ("s4-h2", (2, 1, 1), 64),
        ("s2-s4", (1, 1), 63),
        ("s1-s2", (1,), 62),
        ("h1-s1", None, 61),
    ),
    "reverse-lower": (
        ("s4-h2", (3, 1, 1), 64),
        ("s3-s4", (1, 1), 63),
        ("s1-s3", (1,), 62),
        ("h1-s1", None, 61),
    ),
}


@dataclasses.dataclass(frozen=True)
class Observation:
    frame: bytes
    ethernet_src: str
    ethernet_dst: str
    ethernet_type: int
    next_header: int | None
    route_length: int | None
    route: tuple[int, ...] | None
    ip_header: bytes
    ip_total_length: int
    ip_identification: int
    ip_ttl: int
    ip_protocol: int
    ip_checksum: int
    ip_src: str
    ip_dst: str
    transport: bytes
    udp_source: int
    udp_destination: int
    udp_length: int
    udp_checksum: int
    payload: bytes


@dataclasses.dataclass(frozen=True)
class PathCapture:
    links: dict[str, list[Observation]]
    delivered_payloads: list[bytes]


def runtime_arguments():
    return {
        "controller": ROOT / "build" / "controller",
        "p4info": ROOT / "build" / "source_routing.p4info.txtpb",
        "device_config": ROOT / "build" / "source_routing.json",
    }


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


def format_mac(value):
    return ":".join(f"{byte:02x}" for byte in value)


def decode_frame(frame):
    if len(frame) < 14:
        raise ValueError("truncated Ethernet frame")
    ethernet_type = int.from_bytes(frame[12:14], "big")
    next_header = None
    route_length = None
    route = None
    if ethernet_type == ETHERTYPE_SOURCE_ROUTE:
        if len(frame) < 17:
            raise ValueError("truncated source-route base")
        next_header, route_length = struct.unpack_from("!HB", frame, 14)
        ip_offset = 17 + route_length
        if len(frame) < ip_offset:
            raise ValueError("truncated source-route stack")
        route = tuple(frame[17:ip_offset])
    elif ethernet_type == ETHERTYPE_IPV4:
        ip_offset = 14
    else:
        raise ValueError(f"unsupported EtherType {ethernet_type:#06x}")

    if len(frame) < ip_offset + 20:
        raise ValueError("truncated IPv4 header")
    version_ihl = frame[ip_offset]
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4
    if version != 4 or ihl < 20 or len(frame) < ip_offset + ihl:
        raise ValueError("invalid IPv4 header")
    ip_total_length = int.from_bytes(frame[ip_offset + 2 : ip_offset + 4], "big")
    if ip_total_length < ihl or len(frame) < ip_offset + ip_total_length:
        raise ValueError("truncated IPv4 packet")

    ip_header = frame[ip_offset : ip_offset + ihl]
    transport = frame[ip_offset + ihl : ip_offset + ip_total_length]
    ip_protocol = frame[ip_offset + 9]
    if ip_protocol != socket.IPPROTO_UDP or len(transport) < 8:
        raise ValueError("packet is not UDP")
    udp_source, udp_destination, udp_length, udp_checksum = struct.unpack_from(
        "!HHHH", transport
    )
    if udp_length < 8 or udp_length > len(transport):
        raise ValueError("invalid UDP length")

    return Observation(
        frame=frame,
        ethernet_src=format_mac(frame[6:12]),
        ethernet_dst=format_mac(frame[0:6]),
        ethernet_type=ethernet_type,
        next_header=next_header,
        route_length=route_length,
        route=route,
        ip_header=ip_header,
        ip_total_length=ip_total_length,
        ip_identification=int.from_bytes(frame[ip_offset + 4 : ip_offset + 6], "big"),
        ip_ttl=frame[ip_offset + 8],
        ip_protocol=ip_protocol,
        ip_checksum=int.from_bytes(frame[ip_offset + 10 : ip_offset + 12], "big"),
        ip_src=socket.inet_ntoa(frame[ip_offset + 12 : ip_offset + 16]),
        ip_dst=socket.inet_ntoa(frame[ip_offset + 16 : ip_offset + 20]),
        transport=transport,
        udp_source=udp_source,
        udp_destination=udp_destination,
        udp_length=udp_length,
        udp_checksum=udp_checksum,
        payload=transport[8:udp_length],
    )


def matches_packet(observation, path, payload):
    return (
        observation.next_header in (None, ETHERTYPE_IPV4)
        and observation.ip_src == path["src_ip"]
        and observation.ip_dst == path["dst_ip"]
        and observation.ip_protocol == socket.IPPROTO_UDP
        and observation.udp_source == UDP_SOURCE_PORT
        and observation.udp_destination == UDP_DESTINATION_PORT
        and observation.payload == payload
    )


def stop_process(process):
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=1.0)


class PacketPathTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0:
            raise RuntimeError("packet-path tests require root privileges")
        cls.runtime = SourceRoutingNetwork(**runtime_arguments())
        try:
            cls.runtime.start()
        except BaseException:
            cls.runtime.close()
            raise
        cls.addClassCleanup(cls.runtime.close)

    def capture_path(self, path_name, token):
        path = PATHS[path_name]
        payload = packet_payload(token)
        receiver = None
        selector = selectors.DefaultSelector()
        observations = {link: [] for link in LINK_INTERFACES}

        with contextlib.ExitStack() as sockets:
            try:
                for link, interface in LINK_INTERFACES.items():
                    capture = sockets.enter_context(
                        socket.socket(
                            socket.AF_PACKET,
                            socket.SOCK_RAW,
                            socket.htons(3),
                        )
                    )
                    capture.bind((interface, 0))
                    capture.setblocking(False)
                    selector.register(capture, selectors.EVENT_READ, link)

                destination = self.runtime.net.get(path["destination_host"])
                receiver = destination.popen(
                    [
                        sys.executable,
                        str(ROOT / "tools" / "source_route.py"),
                        "receive",
                        path_name,
                        token,
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                ready, _, _ = select.select([receiver.stdout], [], [], 2.0)
                if not ready:
                    self.fail(f"token {token}: UDP receiver did not become ready")
                ready_line = receiver.stdout.readline().strip()
                if ready_line != "READY":
                    stderr = receiver.stderr.read().strip()
                    self.fail(
                        f"token {token}: UDP receiver readiness was {ready_line!r}: {stderr}"
                    )

                source = self.runtime.net.get(path["source_host"])
                stdout, stderr, status = source.pexec(
                    [
                        sys.executable,
                        str(ROOT / "tools" / "source_route.py"),
                        "send",
                        path_name,
                        token,
                    ]
                )
                if status != 0:
                    self.fail(
                        f"token {token}: sender failed with status {status}: "
                        f"{stderr.strip() or stdout.strip()}"
                    )

                hard_deadline = time.monotonic() + 2.0
                quiet_deadline = None
                while True:
                    deadline = quiet_deadline or hard_deadline
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    events = selector.select(remaining)
                    if not events:
                        break
                    matched = False
                    for key, _ in events:
                        while True:
                            try:
                                frame = key.fileobj.recv(65535)
                            except BlockingIOError:
                                break
                            try:
                                observation = decode_frame(frame)
                            except ValueError:
                                continue
                            if matches_packet(observation, path, payload):
                                observations[key.data].append(observation)
                                matched = True
                    if matched and sum(map(len, observations.values())) >= 4:
                        quiet_deadline = min(
                            hard_deadline,
                            time.monotonic() + 0.2,
                        )

                receiver_output, receiver_error = receiver.communicate(timeout=3.0)
                if receiver.returncode != 0:
                    self.fail(
                        f"token {token}: UDP receiver failed with status "
                        f"{receiver.returncode}: {receiver_error.strip()}"
                    )
                delivered = [
                    bytes.fromhex(line)
                    for line in receiver_output.splitlines()
                    if line.strip()
                ]
                return PathCapture(observations, delivered)
            finally:
                selector.close()
                stop_process(receiver)

    def assert_path(self, path_name, token, capture):
        path = PATHS[path_name]
        expected_payload = packet_payload(token)
        expected_states = EXPECTED_PATHS[path_name]
        expected_links = {link for link, _, _ in expected_states}

        for link, observed in capture.links.items():
            expected_count = 1 if link in expected_links else 0
            self.assertEqual(
                len(observed),
                expected_count,
                f"token {token} on {link}: got {len(observed)}, want {expected_count}",
            )
        self.assertEqual(
            capture.delivered_payloads,
            [expected_payload],
            f"token {token}: destination delivery count or payload differs",
        )

        ordered = []
        for link, expected_route, expected_ttl in expected_states:
            observation = capture.links[link][0]
            ordered.append(observation)
            self.assertEqual(
                observation.route,
                expected_route,
                f"token {token} on {link}: route stack",
            )
            self.assertEqual(
                observation.ip_ttl,
                expected_ttl,
                f"token {token} on {link}: TTL",
            )
            self.assertEqual(observation.ethernet_src, path["src_mac"])
            self.assertEqual(observation.ethernet_dst, path["dst_mac"])
            self.assertEqual(observation.ip_src, path["src_ip"])
            self.assertEqual(observation.ip_dst, path["dst_ip"])
            self.assertEqual(observation.ip_identification, 0x1234)
            self.assertEqual(observation.ip_protocol, socket.IPPROTO_UDP)
            self.assertEqual(observation.udp_source, UDP_SOURCE_PORT)
            self.assertEqual(observation.udp_destination, UDP_DESTINATION_PORT)
            self.assertEqual(observation.udp_length, 8 + len(expected_payload))
            self.assertEqual(observation.payload, expected_payload)
            self.assertEqual(internet_checksum(observation.ip_header), 0)
            self.assertNotEqual(observation.udp_checksum, 0)
            pseudo_header = (
                socket.inet_aton(observation.ip_src)
                + socket.inet_aton(observation.ip_dst)
                + bytes((0, observation.ip_protocol))
                + len(observation.transport).to_bytes(2, "big")
            )
            self.assertEqual(
                internet_checksum(pseudo_header + observation.transport),
                0,
                f"token {token} on {link}: UDP checksum",
            )

            if expected_route is None:
                self.assertEqual(observation.ethernet_type, ETHERTYPE_IPV4)
                self.assertIsNone(observation.route_length)
                expected_length = 14 + observation.ip_total_length
            else:
                self.assertEqual(
                    observation.ethernet_type,
                    ETHERTYPE_SOURCE_ROUTE,
                )
                self.assertEqual(observation.next_header, ETHERTYPE_IPV4)
                self.assertEqual(observation.route_length, len(expected_route))
                expected_length = (
                    14 + 3 + len(expected_route) + observation.ip_total_length
                )
            self.assertEqual(len(observation.frame), expected_length)

        normalized_headers = set()
        for observation in ordered:
            normalized = bytearray(observation.ip_header)
            normalized[8] = 0
            normalized[10:12] = b"\x00\x00"
            normalized_headers.add(bytes(normalized))
        self.assertEqual(len(normalized_headers), 1)
        self.assertEqual(len({item.transport for item in ordered}), 1)
        self.assertEqual(len({item.udp_checksum for item in ordered}), 1)
        self.assertEqual(len({item.ip_checksum for item in ordered}), 4)

    def test_forward_upper_and_lower_paths(self):
        upper_token = "forward-upper-1"
        lower_token = "forward-lower-1"
        upper = self.capture_path("upper", upper_token)
        lower = self.capture_path("lower", lower_token)
        self.assert_path("upper", upper_token, upper)
        self.assert_path("lower", lower_token, lower)

        upper_ingress = upper.links["h1-s1"][0]
        lower_ingress = lower.links["h1-s1"][0]
        self.assertEqual(upper_ingress.ethernet_src, lower_ingress.ethernet_src)
        self.assertEqual(upper_ingress.ethernet_dst, lower_ingress.ethernet_dst)
        self.assertEqual(upper_ingress.ip_src, lower_ingress.ip_src)
        self.assertEqual(upper_ingress.ip_dst, lower_ingress.ip_dst)
        self.assertEqual(
            upper_ingress.ip_identification, lower_ingress.ip_identification
        )
        self.assertEqual(upper_ingress.udp_source, lower_ingress.udp_source)
        self.assertEqual(upper_ingress.udp_destination, lower_ingress.udp_destination)
        self.assertEqual(len(upper_ingress.payload), len(lower_ingress.payload))

    def test_reverse_upper_and_lower_paths(self):
        upper_token = "reverse-upper-1"
        lower_token = "reverse-lower-1"
        upper = self.capture_path("reverse-upper", upper_token)
        lower = self.capture_path("reverse-lower", lower_token)
        self.assert_path("reverse-upper", upper_token, upper)
        self.assert_path("reverse-lower", lower_token, lower)


if __name__ == "__main__":
    unittest.main(verbosity=2)
