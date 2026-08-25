import socket
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mininet"))

from topology import (  # noqa: E402
    HOSTS,
    LINKS,
    SWITCHES,
    DiamondTopology,
    _check_port_available,
    _configure_host,
    _run_node_command,
    _wait_for_ports,
    SourceRoutingNetwork,
    build_controller_command,
    build_switch_command,
    expected_interfaces,
)


EXPECTED_LINKS = (
    ("h1", 0, "s1", 1),
    ("s1", 2, "s2", 1),
    ("s1", 3, "s3", 1),
    ("s2", 2, "s4", 2),
    ("s3", 2, "s4", 3),
    ("s4", 1, "h2", 0),
)


class FakeProcess:
    def __init__(self, returncode=None):
        self.returncode = returncode

    def poll(self):
        return self.returncode


class FakeInterface:
    def __init__(self, name):
        self.name = name


class FakeNode:
    def __init__(self, name="h1", failure_index=None):
        self.name = name
        self.failure_index = failure_index
        self.commands = []

    def defaultIntf(self):
        return FakeInterface(f"{self.name}-eth0")

    def pexec(self, command):
        self.commands.append(command)
        if len(self.commands) - 1 == self.failure_index:
            return "", "injected failure", 1
        return "", "", 0


class FakeResource:
    def __init__(self, name):
        self.name = name
        self.stopped = 0
        self.terminated = 0

    def stop(self):
        self.stopped += 1

    def terminate(self):
        self.terminated += 1


class FakeSwitch(FakeResource):
    def __init__(self, name):
        super().__init__(name)
        self.process_stopped = 0

    def _stop_process(self):
        self.process_stopped += 1


class FailingStopNetwork:
    def __init__(self):
        self.links = [FakeResource("link")]
        self.switches = [FakeSwitch("s1"), FakeSwitch("s2")]
        self.hosts = [FakeResource("h1"), FakeResource("h2")]

    def stop(self):
        raise RuntimeError("injected Mininet stop failure")


class FakeTemporaryDirectory:
    def __init__(self):
        self.cleaned = False

    def cleanup(self):
        self.cleaned = True


class TopologyContractTest(unittest.TestCase):
    def test_inventory(self):
        self.assertEqual(
            HOSTS,
            {
                "h1": {
                    "address": "10.0.1.1/24",
                    "mac": "00:00:00:00:01:01",
                    "peer_address": "10.0.4.1",
                    "peer_prefix": "10.0.4.0/24",
                    "peer_mac": "00:00:00:00:04:01",
                },
                "h2": {
                    "address": "10.0.4.1/24",
                    "mac": "00:00:00:00:04:01",
                    "peer_address": "10.0.1.1",
                    "peer_prefix": "10.0.1.0/24",
                    "peer_mac": "00:00:00:00:01:01",
                },
            },
        )
        self.assertEqual(
            SWITCHES,
            {
                "s1": {
                    "device_id": 1,
                    "grpc_port": 50051,
                    "thrift_port": 9091,
                    "ports": (1, 2, 3),
                },
                "s2": {
                    "device_id": 2,
                    "grpc_port": 50052,
                    "thrift_port": 9092,
                    "ports": (1, 2),
                },
                "s3": {
                    "device_id": 3,
                    "grpc_port": 50053,
                    "thrift_port": 9093,
                    "ports": (1, 2),
                },
                "s4": {
                    "device_id": 4,
                    "grpc_port": 50054,
                    "thrift_port": 9094,
                    "ports": (1, 2, 3),
                },
            },
        )
        self.assertEqual(LINKS, EXPECTED_LINKS)

    def test_mininet_port_map(self):
        with tempfile.TemporaryDirectory() as runtime_dir:
            topology = DiamondTopology(runtime_dir=runtime_dir)
        self.assertEqual(set(topology.hosts()), {"h1", "h2"})
        self.assertEqual(set(topology.switches()), {"s1", "s2", "s3", "s4"})
        self.assertEqual(len(topology.links()), 6)
        for name, config in HOSTS.items():
            self.assertEqual(topology.nodeInfo(name)["ip"], config["address"])
            self.assertEqual(topology.nodeInfo(name)["mac"], config["mac"])
        for left, left_port, right, right_port in EXPECTED_LINKS:
            self.assertEqual(topology.port(left, right), (left_port, right_port))
            self.assertEqual(topology.port(right, left), (right_port, left_port))

    def test_expected_interface_names(self):
        self.assertEqual(
            expected_interfaces(),
            (
                "h1-eth0",
                "h2-eth0",
                "s1-eth1",
                "s1-eth2",
                "s1-eth3",
                "s2-eth1",
                "s2-eth2",
                "s3-eth1",
                "s3-eth2",
                "s4-eth1",
                "s4-eth2",
                "s4-eth3",
            ),
        )

    def test_switch_commands(self):
        with tempfile.TemporaryDirectory() as runtime_dir:
            notifications = []
            for name, spec in SWITCHES.items():
                switch_dir = Path(runtime_dir) / name
                interfaces = {port: f"{name}-eth{port}" for port in spec["ports"]}
                command = build_switch_command(
                    "/usr/local/bin/simple_switch_grpc",
                    spec,
                    interfaces,
                    switch_dir,
                )
                expected = [
                    "/usr/local/bin/simple_switch_grpc",
                    "--no-p4",
                    "--device-id",
                    str(spec["device_id"]),
                    "--thrift-port",
                    str(spec["thrift_port"]),
                    "--notifications-addr",
                    f"ipc://{switch_dir / 'notifications.ipc'}",
                    "--log-console",
                    "-L",
                    "warn",
                ]
                for port in spec["ports"]:
                    expected.extend(("-i", f"{port}@{name}-eth{port}"))
                expected.extend(
                    (
                        "--",
                        "--grpc-server-addr",
                        f"127.0.0.1:{spec['grpc_port']}",
                        "--drop-port",
                        "511",
                    )
                )
                self.assertEqual(command, expected)
                notifications.append(command[7])
            self.assertEqual(len(set(notifications)), 4)

    def test_switch_command_rejects_wrong_ports(self):
        with self.assertRaisesRegex(ValueError, "interface ports"):
            build_switch_command(
                "simple_switch_grpc", SWITCHES["s1"], {1: "s1-eth1"}, "/tmp/s1"
            )

    def test_controller_command(self):
        self.assertEqual(
            build_controller_command(
                "/repo/build/controller",
                "/repo/build/source_routing.p4info.txtpb",
                "/repo/build/source_routing.json",
                25.0,
                verify_only=True,
            ),
            [
                "/repo/build/controller",
                "--p4info",
                "/repo/build/source_routing.p4info.txtpb",
                "--device-config",
                "/repo/build/source_routing.json",
                "--timeout",
                "25s",
                "--verify-only",
            ],
        )

    def test_host_configuration(self):
        host = FakeNode()
        _configure_host(host, HOSTS["h1"])
        self.assertEqual(
            host.commands[0],
            ["ip", "-4", "address", "flush", "dev", "h1-eth0"],
        )
        self.assertEqual(
            host.commands[1],
            ["ip", "address", "add", "10.0.1.1/24", "dev", "h1-eth0"],
        )
        self.assertEqual(
            host.commands[2],
            ["ip", "link", "set", "dev", "h1-eth0", "up"],
        )
        self.assertEqual(
            host.commands[3],
            ["ip", "route", "replace", "10.0.4.0/24", "dev", "h1-eth0"],
        )
        self.assertEqual(
            host.commands[4],
            [
                "ip",
                "neighbor",
                "replace",
                "10.0.4.1",
                "lladdr",
                "00:00:00:00:04:01",
                "nud",
                "permanent",
                "dev",
                "h1-eth0",
            ],
        )
        self.assertEqual(
            host.commands[5:7],
            [
                ["sysctl", "-qw", "net.ipv6.conf.all.disable_ipv6=1"],
                ["sysctl", "-qw", "net.ipv6.conf.default.disable_ipv6=1"],
            ],
        )
        offload = host.commands[-1]
        self.assertEqual(offload[:3], ["ethtool", "--offload", "h1-eth0"])
        for feature in ("rx", "tx", "sg", "tso", "gso", "gro", "lro"):
            index = offload.index(feature)
            self.assertEqual(offload[index + 1], "off")

    def test_node_command_reports_failure(self):
        host = FakeNode(failure_index=0)
        with self.assertRaisesRegex(
            RuntimeError, "h1: ip link show failed: injected failure"
        ):
            _run_node_command(host, ["ip", "link", "show"])


class ReadinessTest(unittest.TestCase):
    def test_wait_for_listening_port(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            _wait_for_ports((listener.getsockname()[1],), FakeProcess(), 0.2)

    def test_wait_detects_exited_process(self):
        with self.assertRaisesRegex(RuntimeError, "exited with status 7"):
            _wait_for_ports((1,), FakeProcess(7), 0.2)

    def test_wait_times_out(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserved:
            reserved.bind(("127.0.0.1", 0))
            port = reserved.getsockname()[1]
            with self.assertRaisesRegex(TimeoutError, str(port)):
                _wait_for_ports((port,), FakeProcess(), 0.02)

    def test_port_preflight_detects_listener(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]
            with self.assertRaisesRegex(RuntimeError, f"TCP port {port}"):
                _check_port_available("127.0.0.1", port)


class CleanupTest(unittest.TestCase):
    def test_mininet_stop_failure_uses_owned_resource_fallback(self):
        runtime = SourceRoutingNetwork("controller", "p4info", "device-config")
        net = FailingStopNetwork()
        runtime_dir = FakeTemporaryDirectory()
        runtime.net = net
        runtime._runtime_dir = runtime_dir

        runtime.close()

        self.assertIsNone(runtime.net)
        self.assertIsNone(runtime._runtime_dir)
        self.assertTrue(runtime_dir.cleaned)
        self.assertEqual(net.links[0].stopped, 1)
        for switch in net.switches:
            self.assertEqual(switch.process_stopped, 2)
            self.assertEqual(switch.stopped, 1)
            self.assertEqual(switch.terminated, 1)
        for host in net.hosts:
            self.assertEqual(host.terminated, 1)
        runtime.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
