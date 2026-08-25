#!/usr/bin/env python3

import argparse
import socket
import time

from scapy.all import Ether, IP, UDP, bind_layers, sendp
from scapy.fields import ByteField, FieldLenField, FieldListField, XShortEnumField
from scapy.packet import Packet


ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_SOURCE_ROUTE = 0x88B5
UDP_SOURCE_PORT = 12000
UDP_DESTINATION_PORT = 22000

PATHS = {
    "upper": {
        "route": (2, 2, 1),
        "source_host": "h1",
        "destination_host": "h2",
        "interface": "h1-eth0",
        "src_mac": "00:00:00:00:01:01",
        "dst_mac": "00:00:00:00:04:01",
        "src_ip": "10.0.1.1",
        "dst_ip": "10.0.4.1",
    },
    "lower": {
        "route": (3, 2, 1),
        "source_host": "h1",
        "destination_host": "h2",
        "interface": "h1-eth0",
        "src_mac": "00:00:00:00:01:01",
        "dst_mac": "00:00:00:00:04:01",
        "src_ip": "10.0.1.1",
        "dst_ip": "10.0.4.1",
    },
    "reverse-upper": {
        "route": (2, 1, 1),
        "source_host": "h2",
        "destination_host": "h1",
        "interface": "h2-eth0",
        "src_mac": "00:00:00:00:04:01",
        "dst_mac": "00:00:00:00:01:01",
        "src_ip": "10.0.4.1",
        "dst_ip": "10.0.1.1",
    },
    "reverse-lower": {
        "route": (3, 1, 1),
        "source_host": "h2",
        "destination_host": "h1",
        "interface": "h2-eth0",
        "src_mac": "00:00:00:00:04:01",
        "dst_mac": "00:00:00:00:01:01",
        "src_ip": "10.0.4.1",
        "dst_ip": "10.0.1.1",
    },
}


class SourceRouteHeader(Packet):
    name = "Source Route"
    fields_desc = [
        XShortEnumField("next_header", ETHERTYPE_IPV4, {ETHERTYPE_IPV4: "IPv4"}),
        FieldLenField("route_length", None, count_of="ports", fmt="B"),
        FieldListField(
            "ports",
            [],
            ByteField("output_port", 0),
            count_from=lambda packet: packet.route_length,
        ),
    ]


bind_layers(Ether, SourceRouteHeader, type=ETHERTYPE_SOURCE_ROUTE)
bind_layers(SourceRouteHeader, IP, next_header=ETHERTYPE_IPV4)


def token_bytes(token):
    if isinstance(token, str):
        token = token.encode("ascii")
    elif not isinstance(token, bytes):
        raise TypeError("token must be text or bytes")
    if not 1 <= len(token) <= 64:
        raise ValueError("token must contain 1 to 64 bytes")
    return token


def packet_payload(token):
    return b"source-route|" + token_bytes(token) + b"|" + bytes(range(32))


def build_packet(path_name, token, ttl=64):
    try:
        path = PATHS[path_name]
    except KeyError as error:
        raise ValueError(f"unknown path {path_name!r}") from error
    if not 0 <= ttl <= 255:
        raise ValueError("TTL must be in the range 0..255")

    packet = (
        Ether(
            src=path["src_mac"],
            dst=path["dst_mac"],
            type=ETHERTYPE_SOURCE_ROUTE,
        )
        / SourceRouteHeader(ports=list(path["route"]))
        / IP(
            src=path["src_ip"],
            dst=path["dst_ip"],
            ttl=ttl,
            id=0x1234,
        )
        / UDP(sport=UDP_SOURCE_PORT, dport=UDP_DESTINATION_PORT)
        / packet_payload(token)
    )
    return Ether(bytes(packet))


def send_packet(path_name, token, ttl=64, interface=None):
    path = PATHS[path_name]
    interface = interface or path["interface"]
    sendp(build_packet(path_name, token, ttl), iface=interface, verbose=False)
    return interface


def receive_payloads(path_name, token, timeout=2.0, quiet_time=0.2):
    if timeout <= 0 or quiet_time <= 0:
        raise ValueError("receive timeouts must be positive")
    path = PATHS[path_name]
    expected_payload = packet_payload(token)
    matches = []
    hard_deadline = time.monotonic() + timeout
    quiet_deadline = None

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
        receiver.bind((path["dst_ip"], UDP_DESTINATION_PORT))
        print("READY", flush=True)
        while True:
            deadline = quiet_deadline or hard_deadline
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            receiver.settimeout(remaining)
            try:
                payload, source = receiver.recvfrom(65535)
            except socket.timeout:
                break
            if source != (path["src_ip"], UDP_SOURCE_PORT):
                continue
            if payload != expected_payload:
                continue
            matches.append(payload)
            quiet_deadline = min(
                hard_deadline,
                time.monotonic() + quiet_time,
            )
    return matches


def _parse_args():
    parser = argparse.ArgumentParser(description="send a source-routed UDP packet")
    subparsers = parser.add_subparsers(dest="operation", required=True)

    sender = subparsers.add_parser("send")
    sender.add_argument("path", choices=PATHS)
    sender.add_argument("token")
    sender.add_argument("--ttl", default=64, type=int)
    sender.add_argument("--interface")

    receiver = subparsers.add_parser("receive")
    receiver.add_argument("path", choices=PATHS)
    receiver.add_argument("token")
    receiver.add_argument("--timeout", default=2.0, type=float)
    receiver.add_argument("--quiet-time", default=0.2, type=float)
    return parser.parse_args()


def main():
    args = _parse_args()
    if args.operation == "send":
        interface = send_packet(args.path, args.token, args.ttl, args.interface)
        print(f"sent {args.path} token {args.token} on {interface}")
        return

    matches = receive_payloads(
        args.path,
        args.token,
        timeout=args.timeout,
        quiet_time=args.quiet_time,
    )
    for payload in matches:
        print(payload.hex())
    if not matches:
        raise SystemExit("no matching UDP payload received")


if __name__ == "__main__":
    main()
