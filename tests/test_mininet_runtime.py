import os
import socket
import sys
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mininet"))

from topology import (  # noqa: E402
    HOSTS,
    SWITCHES,
    SourceRoutingNetwork,
    expected_interfaces,
)


class ConfigurationFailureNetwork(SourceRoutingNetwork):
    failure_message = "injected controller configuration failure"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.runtime_path = None
        self.switch_pids = ()
        self.host_pids = ()

    def _configure_pipeline(self):
        self.runtime_path = Path(self._runtime_dir.name)
        self.switch_pids = tuple(switch.process.pid for switch in self.net.switches)
        self.host_pids = tuple(host.pid for host in self.net.hosts)
        raise RuntimeError(self.failure_message)


def runtime_arguments():
    return {
        "controller": ROOT / "build" / "controller",
        "p4info": ROOT / "build" / "source_routing.p4info.txtpb",
        "device_config": ROOT / "build" / "source_routing.json",
    }


def wait_for_process_exit(pid, timeout=3.0):
    deadline = time.monotonic() + timeout
    while (Path("/proc") / str(pid)).exists():
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.02)
    return True


def assert_runtime_cleanup(test, runtime_path, switch_pids, host_pids):
    test.assertIsNotNone(runtime_path)
    test.assertFalse(runtime_path.exists())
    for pid in (*switch_pids, *host_pids):
        test.assertTrue(wait_for_process_exit(pid), f"process {pid} is still running")
    for interface in expected_interfaces():
        test.assertFalse(
            (Path("/sys/class/net") / interface).exists(),
            f"interface {interface} remains",
        )
    for spec in SWITCHES.values():
        for address, port in (
            ("127.0.0.1", spec["grpc_port"]),
            ("0.0.0.0", spec["thrift_port"]),
        ):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                probe.bind((address, port))


class MininetRuntimeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0:
            raise RuntimeError("Mininet runtime tests require root privileges")

    def test_start_configure_verify_and_cleanup(self):
        runtime = SourceRoutingNetwork(**runtime_arguments())
        runtime_path = None
        switch_pids = ()
        host_pids = ()
        try:
            runtime.start()
            runtime_path = Path(runtime._runtime_dir.name)
            switch_pids = tuple(switch.process.pid for switch in runtime.net.switches)
            host_pids = tuple(host.pid for host in runtime.net.hosts)

            self.assertEqual(set(runtime.net.keys()), {*HOSTS, *SWITCHES})
            self.assertEqual(len(runtime.net.links), 6)
            self.assertEqual(len(set(switch_pids)), 4)
            self.assertTrue(
                all(switch.process.poll() is None for switch in runtime.net.switches)
            )
            for name, spec in SWITCHES.items():
                switch = runtime.net.get(name)
                self.assertEqual(
                    tuple(sorted(port for port in switch.intfs if port > 0)),
                    spec["ports"],
                )
                for port in spec["ports"]:
                    self.assertEqual(switch.intfs[port].name, f"{name}-eth{port}")
                for port in (spec["grpc_port"], spec["thrift_port"]):
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        pass
            self.assertEqual(
                runtime.controller_output.count("configured and verified"), 4
            )
            self.assertEqual(runtime.verify().count("verified ports"), 4)

            for name, config in HOSTS.items():
                host = runtime.net.get(name)
                interface = host.defaultIntf().name
                self.assertEqual(host.MAC(interface), config["mac"])
                address = host.cmd("ip -4 -o address show dev", interface)
                self.assertIn(config["address"], address)
                route = host.cmd("ip -4 route show", config["peer_prefix"])
                self.assertIn(f"dev {interface}", route)
                neighbor = host.cmd(
                    "ip neighbor show", config["peer_address"], "dev", interface
                )
                self.assertIn(config["peer_mac"], neighbor)
                self.assertIn("PERMANENT", neighbor.upper())
                offloads = host.cmd("ethtool -k", interface)
                for feature in (
                    "rx-checksumming: off",
                    "tx-checksumming: off",
                    "scatter-gather: off",
                    "tcp-segmentation-offload: off",
                    "generic-segmentation-offload: off",
                    "generic-receive-offload: off",
                    "large-receive-offload: off",
                ):
                    self.assertIn(feature, offloads)
        finally:
            runtime.close()

        self.assertIsNone(runtime.net)
        self.assertIsNone(runtime._runtime_dir)
        assert_runtime_cleanup(self, runtime_path, switch_pids, host_pids)

    def test_configuration_failure_cleans_all_resources(self):
        runtime = ConfigurationFailureNetwork(**runtime_arguments())
        try:
            with self.assertRaisesRegex(RuntimeError, runtime.failure_message):
                runtime.start()
        finally:
            runtime.close()

        self.assertIsNone(runtime.net)
        self.assertIsNone(runtime._runtime_dir)
        self.assertEqual(len(runtime.switch_pids), 4)
        self.assertEqual(len(runtime.host_pids), 2)
        assert_runtime_cleanup(
            self,
            runtime.runtime_path,
            runtime.switch_pids,
            runtime.host_pids,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
