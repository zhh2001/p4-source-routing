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
    build_packet,
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
    ip_ihl: int
    ip_total_length: int
    ip_identification: int
    ip_flags: int
    ip_fragment_offset: int
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


@dataclasses.dataclass(frozen=True)
class FrameCapture:
    links: dict[str, list[bytes]]
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


def decode_frame(frame, require_complete=True):
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
    if ip_total_length < ihl:
        raise ValueError("invalid IPv4 total length")
    if require_complete and len(frame) < ip_offset + ip_total_length:
        raise ValueError("truncated IPv4 packet")

    ip_header = frame[ip_offset : ip_offset + ihl]
    ip_end = min(len(frame), ip_offset + ip_total_length)
    transport = frame[ip_offset + ihl : ip_end]
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
        ip_ihl=ihl // 4,
        ip_total_length=ip_total_length,
        ip_identification=int.from_bytes(frame[ip_offset + 4 : ip_offset + 6], "big"),
        ip_flags=int.from_bytes(frame[ip_offset + 6 : ip_offset + 8], "big") >> 13,
        ip_fragment_offset=int.from_bytes(frame[ip_offset + 6 : ip_offset + 8], "big")
        & 0x1FFF,
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
        observation.ip_src == path["src_ip"]
        and observation.ip_dst == path["dst_ip"]
        and observation.ip_identification == 0x1234
        and observation.ip_protocol == socket.IPPROTO_UDP
        and observation.udp_source == UDP_SOURCE_PORT
        and observation.udp_destination == UDP_DESTINATION_PORT
        and observation.payload == payload
    )


def matches_frame(frame, path, payload, require_complete=True):
    try:
        observation = decode_frame(frame, require_complete=require_complete)
    except ValueError:
        return False
    return matches_packet(observation, path, payload)


def contains_ipv4_identity(frame, path, payload):
    for ip_offset in (14, *range(17, 26)):
        if len(frame) < ip_offset + 20:
            continue
        ihl = (frame[ip_offset] & 0x0F) * 4
        if ihl < 20 or len(frame) < ip_offset + ihl + 8:
            continue
        if frame[ip_offset + 9] != socket.IPPROTO_UDP:
            continue
        if socket.inet_ntoa(frame[ip_offset + 12 : ip_offset + 16]) != path["src_ip"]:
            continue
        if socket.inet_ntoa(frame[ip_offset + 16 : ip_offset + 20]) != path["dst_ip"]:
            continue
        if int.from_bytes(frame[ip_offset + 4 : ip_offset + 6], "big") != 0x1234:
            continue

        udp_offset = ip_offset + ihl
        udp_source, udp_destination, udp_length = struct.unpack_from(
            "!HHH", frame, udp_offset
        )
        if udp_source != UDP_SOURCE_PORT or udp_destination != UDP_DESTINATION_PORT:
            continue
        if udp_length != 8 + len(payload):
            continue
        if len(frame) < udp_offset + udp_length:
            continue
        if frame[udp_offset + 8 : udp_offset + udp_length] == payload:
            return True
    return False


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

    def capture_case(
        self,
        path_name,
        token,
        send_arguments,
        matcher,
        expected_matches,
        allow_empty=False,
    ):
        path = PATHS[path_name]
        receiver = None
        selector = selectors.DefaultSelector()
        frames = {link: [] for link in LINK_INTERFACES}

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
                receiver_arguments = [
                    sys.executable,
                    str(ROOT / "tools" / "source_route.py"),
                    "receive",
                    path_name,
                    token,
                ]
                if allow_empty:
                    receiver_arguments.append("--allow-empty")
                receiver = destination.popen(
                    receiver_arguments,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                ready, _, _ = select.select([receiver.stdout], [], [], 2.0)
                if not ready:
                    stop_process(receiver)
                    _, receiver_error = receiver.communicate()
                    self.fail(
                        f"token {token}: UDP receiver did not become ready: "
                        f"{receiver_error.strip()}"
                    )
                ready_line = receiver.stdout.readline().strip()
                if ready_line != "READY":
                    stop_process(receiver)
                    _, receiver_error = receiver.communicate()
                    self.fail(
                        f"token {token}: UDP receiver readiness was {ready_line!r}: "
                        f"{receiver_error.strip()}"
                    )

                source = self.runtime.net.get(path["source_host"])
                stdout, stderr, status = source.pexec(
                    [
                        sys.executable,
                        str(ROOT / "tools" / "source_route.py"),
                        *send_arguments,
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
                            if matcher(frame):
                                frames[key.data].append(frame)
                                matched = True
                    if matched and sum(map(len, frames.values())) >= expected_matches:
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
                return FrameCapture(frames, delivered)
            finally:
                selector.close()
                stop_process(receiver)

    def capture_path(self, path_name, token):
        path = PATHS[path_name]
        payload = packet_payload(token)
        capture = self.capture_case(
            path_name,
            token,
            ["send", path_name, token],
            lambda frame: matches_frame(frame, path, payload),
            expected_matches=4,
        )
        observations = {
            link: [decode_frame(frame) for frame in frames]
            for link, frames in capture.links.items()
        }
        return PathCapture(observations, capture.delivered_payloads)

    def assert_rejected_packet(
        self,
        token,
        packet,
        expected_states,
        require_complete=True,
    ):
        path_name = "upper"
        path = PATHS[path_name]
        payload = packet_payload(token)
        capture = self.capture_case(
            path_name,
            token,
            ["send-raw", path_name, bytes(packet).hex()],
            lambda frame: matches_frame(
                frame,
                path,
                payload,
                require_complete=require_complete,
            ),
            expected_matches=len(expected_states),
            allow_empty=True,
        )
        expected_links = {link for link, _, _ in expected_states}

        for link, frames in capture.links.items():
            expected_count = 1 if link in expected_links else 0
            self.assertEqual(
                len(frames),
                expected_count,
                f"token {token} on {link}: got {len(frames)}, want {expected_count}",
            )
        self.assertEqual(
            capture.delivered_payloads,
            [],
            f"token {token}: packet unexpectedly reached the UDP receiver",
        )

        observations = []
        for link, expected_route, expected_ttl in expected_states:
            observation = decode_frame(
                capture.links[link][0],
                require_complete=require_complete,
            )
            observations.append(observation)
            self.assertTrue(matches_packet(observation, path, payload))
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
            if expected_route is None:
                self.assertEqual(observation.ethernet_type, ETHERTYPE_IPV4)
                self.assertIsNone(observation.route_length)
            else:
                self.assertEqual(
                    observation.ethernet_type,
                    ETHERTYPE_SOURCE_ROUTE,
                )
                self.assertEqual(observation.route_length, len(expected_route))
        return observations

    def assert_raw_drop(self, token, frame, source_mac, contains_ipv4=True):
        path_name = "upper"
        path = PATHS[path_name]
        payload = packet_payload(token)

        def matcher(candidate):
            if len(candidate) < 14:
                return False
            ethernet_matches = (
                format_mac(candidate[6:12]) == source_mac
                and format_mac(candidate[0:6]) == path["dst_mac"]
                and int.from_bytes(candidate[12:14], "big")
                in (ETHERTYPE_SOURCE_ROUTE, ETHERTYPE_IPV4)
            )
            if not ethernet_matches:
                return False
            if contains_ipv4:
                return contains_ipv4_identity(candidate, path, payload)
            return candidate == frame

        capture = self.capture_case(
            path_name,
            token,
            ["send-raw", path_name, frame.hex()],
            matcher,
            expected_matches=1,
            allow_empty=True,
        )
        for link, frames in capture.links.items():
            expected_count = 1 if link == "h1-s1" else 0
            self.assertEqual(
                len(frames),
                expected_count,
                f"token {token} on {link}: got {len(frames)}, want {expected_count}",
            )
        self.assertEqual(
            capture.delivered_payloads,
            [],
            f"token {token}: malformed packet reached the UDP receiver",
        )
        self.assertEqual(capture.links["h1-s1"][0], frame)
        return capture.links["h1-s1"][0]

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

    def test_invalid_output_ports_drop(self):
        cases = (
            (
                "invalid-port-s1",
                (99, 2, 1),
                (("h1-s1", (99, 2, 1), 64),),
            ),
            (
                "invalid-port-s2",
                (2, 3, 1),
                (
                    ("h1-s1", (2, 3, 1), 64),
                    ("s1-s2", (3, 1), 63),
                ),
            ),
            (
                "invalid-port-s4",
                (2, 2, 99),
                (
                    ("h1-s1", (2, 2, 99), 64),
                    ("s1-s2", (2, 99), 63),
                    ("s2-s4", (99,), 62),
                ),
            ),
        )
        for token, route, expected_states in cases:
            with self.subTest(token=token):
                observations = self.assert_rejected_packet(
                    token,
                    build_packet("upper", token, route=route),
                    expected_states,
                )
                for observation in observations:
                    self.assertEqual(internet_checksum(observation.ip_header), 0)

    def test_route_length_and_exhaustion(self):
        empty_token = "empty-route"
        self.assert_rejected_packet(
            empty_token,
            build_packet(
                "upper",
                empty_token,
                route=(),
                route_length=0,
            ),
            (("h1-s1", (), 64),),
        )

        oversized_token = "oversized-route"
        oversized_route = (2, 2, 1, 1, 1, 1, 1, 1, 1)
        self.assert_rejected_packet(
            oversized_token,
            build_packet(
                "upper",
                oversized_token,
                route=oversized_route,
                route_length=len(oversized_route),
            ),
            (("h1-s1", oversized_route, 64),),
        )

        short_token = "short-route"
        short_observations = self.assert_rejected_packet(
            short_token,
            build_packet("upper", short_token, route=(2,)),
            (
                ("h1-s1", (2,), 64),
                ("s1-s2", None, 63),
            ),
        )
        for observation in short_observations:
            self.assertEqual(internet_checksum(observation.ip_header), 0)

        extra_token = "extra-route"
        extra_observations = self.assert_rejected_packet(
            extra_token,
            build_packet("upper", extra_token, route=(2, 2, 1, 99)),
            (
                ("h1-s1", (2, 2, 1, 99), 64),
                ("s1-s2", (2, 1, 99), 63),
                ("s2-s4", (1, 99), 62),
                ("s4-h2", (99,), 61),
            ),
        )
        self.assertEqual(
            extra_observations[-1].ethernet_type,
            ETHERTYPE_SOURCE_ROUTE,
        )
        for observation in extra_observations:
            self.assertEqual(internet_checksum(observation.ip_header), 0)

    def test_ttl_exhaustion(self):
        ttl_one_token = "ttl-one"
        ttl_one = self.assert_rejected_packet(
            ttl_one_token,
            build_packet("upper", ttl_one_token, ttl=1),
            (("h1-s1", (2, 2, 1), 1),),
        )
        self.assertEqual(internet_checksum(ttl_one[0].ip_header), 0)

        ttl_two_token = "ttl-two"
        ttl_two = self.assert_rejected_packet(
            ttl_two_token,
            build_packet("upper", ttl_two_token, ttl=2),
            (
                ("h1-s1", (2, 2, 1), 2),
                ("s1-s2", (2, 1), 1),
            ),
        )
        self.assertEqual(internet_checksum(ttl_two[0].ip_header), 0)
        self.assertEqual(internet_checksum(ttl_two[1].ip_header), 0)
        self.assertNotEqual(ttl_two[0].ip_checksum, ttl_two[1].ip_checksum)

    def test_ipv4_validation_drop(self):
        checksum_token = "bad-ip-checksum"
        bad_checksum = self.assert_rejected_packet(
            checksum_token,
            build_packet(
                "upper",
                checksum_token,
                ipv4_fields={"chksum": 0},
            ),
            (("h1-s1", (2, 2, 1), 64),),
        )
        self.assertNotEqual(internet_checksum(bad_checksum[0].ip_header), 0)

        options_token = "ipv4-options"
        options = self.assert_rejected_packet(
            options_token,
            build_packet(
                "upper",
                options_token,
                ipv4_fields={"options": b"\x01\x01\x01\x00"},
            ),
            (("h1-s1", (2, 2, 1), 64),),
        )
        self.assertEqual(options[0].ip_ihl, 6)
        self.assertEqual(internet_checksum(options[0].ip_header), 0)

        version_token = "bad-ip-version"
        version_source = "02:00:00:00:00:e4"
        version_packet = bytearray(
            bytes(
                build_packet(
                    "upper",
                    version_token,
                    ipv4_fields={"version": 6},
                )
            )
        )
        version_packet[6:12] = bytes.fromhex(version_source.replace(":", ""))
        bad_version = self.assert_raw_drop(
            version_token,
            bytes(version_packet),
            version_source,
        )
        ip_offset = 17 + 3
        self.assertEqual(bad_version[ip_offset] >> 4, 6)
        self.assertEqual(
            internet_checksum(bad_version[ip_offset : ip_offset + 20]),
            0,
        )

        first_fragment_token = "first-fragment"
        first_fragment = self.assert_rejected_packet(
            first_fragment_token,
            build_packet(
                "upper",
                first_fragment_token,
                ipv4_fields={"flags": "MF"},
            ),
            (("h1-s1", (2, 2, 1), 64),),
        )
        self.assertEqual(first_fragment[0].ip_flags & 1, 1)
        self.assertEqual(first_fragment[0].ip_fragment_offset, 0)
        self.assertEqual(internet_checksum(first_fragment[0].ip_header), 0)

        later_fragment_token = "later-fragment"
        later_fragment = self.assert_rejected_packet(
            later_fragment_token,
            build_packet(
                "upper",
                later_fragment_token,
                ipv4_fields={"frag": 1},
            ),
            (("h1-s1", (2, 2, 1), 64),),
        )
        self.assertEqual(later_fragment[0].ip_flags & 1, 0)
        self.assertEqual(later_fragment[0].ip_fragment_offset, 1)
        self.assertEqual(internet_checksum(later_fragment[0].ip_header), 0)

        length_token = "long-total-length"
        claimed_length = 20 + 8 + len(packet_payload(length_token)) + 32
        long_packet = build_packet(
            "upper",
            length_token,
            ipv4_fields={"len": claimed_length},
        )
        long_length = self.assert_rejected_packet(
            length_token,
            long_packet,
            (("h1-s1", (2, 2, 1), 64),),
            require_complete=False,
        )
        self.assertEqual(long_length[0].ip_total_length, claimed_length)
        self.assertGreater(
            long_length[0].ip_total_length,
            len(bytes(long_packet)) - 20,
        )
        self.assertEqual(internet_checksum(long_length[0].ip_header), 0)

        short_length_token = "short-total-length"
        short_length_source = "02:00:00:00:00:e3"
        short_length_packet = bytearray(
            bytes(
                build_packet(
                    "upper",
                    short_length_token,
                    ipv4_fields={"len": 19},
                )
            )
        )
        short_length_packet[6:12] = bytes.fromhex(short_length_source.replace(":", ""))
        short_length = self.assert_raw_drop(
            short_length_token,
            bytes(short_length_packet),
            short_length_source,
        )
        self.assertEqual(
            int.from_bytes(short_length[ip_offset + 2 : ip_offset + 4], "big"),
            19,
        )
        self.assertEqual(
            internet_checksum(short_length[ip_offset : ip_offset + 20]),
            0,
        )

    def test_malformed_source_route_drop(self):
        next_header_token = "bad-next-header"
        invalid_next = self.assert_rejected_packet(
            next_header_token,
            build_packet(
                "upper",
                next_header_token,
                next_header=0x86DD,
            ),
            (("h1-s1", (2, 2, 1), 64),),
        )
        self.assertEqual(invalid_next[0].next_header, 0x86DD)

        path = PATHS["upper"]
        inconsistent_token = "inconsistent-route"
        inconsistent_source = "02:00:00:00:00:e1"
        inconsistent = bytearray(
            bytes(
                build_packet(
                    "upper",
                    inconsistent_token,
                    route=(2, 2),
                    route_length=2,
                )
            )
        )
        inconsistent[6:12] = bytes.fromhex(inconsistent_source.replace(":", ""))
        inconsistent[16] = 3
        observed = self.assert_raw_drop(
            inconsistent_token,
            bytes(inconsistent),
            inconsistent_source,
        )
        self.assertEqual(observed[16], 3)
        self.assertEqual(observed[17:19], b"\x02\x02")
        self.assertEqual(observed[19] >> 4, 4)

        truncated_token = "truncated-route"
        truncated_source = "02:00:00:00:00:e2"
        truncated = (
            bytes.fromhex(path["dst_mac"].replace(":", ""))
            + bytes.fromhex(truncated_source.replace(":", ""))
            + struct.pack("!HHB", ETHERTYPE_SOURCE_ROUTE, ETHERTYPE_IPV4, 3)
            + b"\x02\x02"
        )
        captured = self.assert_raw_drop(
            truncated_token,
            truncated,
            truncated_source,
            contains_ipv4=False,
        )
        self.assertEqual(captured[: len(truncated)], truncated)


if __name__ == "__main__":
    unittest.main(verbosity=2)
