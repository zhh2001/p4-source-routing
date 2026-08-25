#!/usr/bin/env python3

import argparse
import os
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import Switch
from mininet.topo import Topo


HOSTS = {
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
}

SWITCHES = {
    "s1": {"device_id": 1, "grpc_port": 50051, "thrift_port": 9091, "ports": (1, 2, 3)},
    "s2": {"device_id": 2, "grpc_port": 50052, "thrift_port": 9092, "ports": (1, 2)},
    "s3": {"device_id": 3, "grpc_port": 50053, "thrift_port": 9093, "ports": (1, 2)},
    "s4": {"device_id": 4, "grpc_port": 50054, "thrift_port": 9094, "ports": (1, 2, 3)},
}

LINKS = (
    ("h1", 0, "s1", 1),
    ("s1", 2, "s2", 1),
    ("s1", 3, "s3", 1),
    ("s2", 2, "s4", 2),
    ("s3", 2, "s4", 3),
    ("s4", 1, "h2", 0),
)


def build_switch_command(executable, spec, interfaces, runtime_dir):
    expected_ports = tuple(spec["ports"])
    if tuple(sorted(interfaces)) != expected_ports:
        raise ValueError(
            f"interface ports {tuple(sorted(interfaces))} do not match {expected_ports}"
        )

    command = [
        executable,
        "--no-p4",
        "--device-id",
        str(spec["device_id"]),
        "--thrift-port",
        str(spec["thrift_port"]),
        "--notifications-addr",
        f"ipc://{Path(runtime_dir) / 'notifications.ipc'}",
        "--log-console",
        "-L",
        "warn",
    ]
    for port in expected_ports:
        command.extend(("-i", f"{port}@{interfaces[port]}"))
    command.extend(
        (
            "--",
            "--grpc-server-addr",
            f"127.0.0.1:{spec['grpc_port']}",
            "--drop-port",
            "511",
        )
    )
    return command


def build_controller_command(
    controller, p4info, device_config, timeout, verify_only=False
):
    command = [
        str(controller),
        "--p4info",
        str(p4info),
        "--device-config",
        str(device_config),
        "--timeout",
        f"{timeout:g}s",
    ]
    if verify_only:
        command.append("--verify-only")
    return command


def _wait_for_ports(ports, process, timeout):
    pending = set(ports)
    deadline = time.monotonic() + timeout
    while pending:
        if process.poll() is not None:
            raise RuntimeError(
                f"simple_switch_grpc exited with status {process.returncode}"
            )
        for port in tuple(pending):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    pending.remove(port)
            except OSError:
                pass
        if not pending:
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"timed out waiting for TCP ports {sorted(pending)}")
        time.sleep(min(0.05, remaining))


def _check_port_available(address, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind((address, port))
        except OSError as error:
            raise RuntimeError(f"TCP port {port} is already in use") from error


def expected_interfaces():
    interfaces = set()
    for left, left_port, right, right_port in LINKS:
        interfaces.add(f"{left}-eth{left_port}")
        interfaces.add(f"{right}-eth{right_port}")
    return tuple(sorted(interfaces))


def _check_interfaces_available():
    existing = [
        name
        for name in expected_interfaces()
        if (Path("/sys/class/net") / name).exists()
    ]
    if existing:
        raise RuntimeError(f"network interfaces already exist: {', '.join(existing)}")


class P4RuntimeSwitch(Switch):
    def __init__(
        self,
        name,
        spec,
        runtime_dir,
        executable="simple_switch_grpc",
        **params,
    ):
        super().__init__(name, **params)
        self.spec = spec
        self.runtime_dir = Path(runtime_dir)
        self.executable = executable
        self.process = None
        self._log_file = None

    def start(self, controllers):
        if self.process is not None and self.process.poll() is None:
            raise RuntimeError(f"{self.name} is already running")
        executable = shutil.which(self.executable)
        if executable is None:
            raise RuntimeError(f"{self.executable} is not installed")

        expected_ports = tuple(self.spec["ports"])
        actual_ports = tuple(sorted(port for port in self.intfs if port > 0))
        if actual_ports != expected_ports:
            raise RuntimeError(
                f"{self.name} has data ports {actual_ports}, want {expected_ports}"
            )
        interfaces = {}
        for port in expected_ports:
            interface = self.intfs.get(port)
            if interface is None:
                raise RuntimeError(f"{self.name} has no interface on port {port}")
            interfaces[port] = interface.name

        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        log_path = self.runtime_dir / "simple_switch_grpc.log"
        command = build_switch_command(
            executable, self.spec, interfaces, self.runtime_dir
        )
        self._log_file = log_path.open("w", encoding="utf-8")
        try:
            self.process = self.popen(
                command,
                stdout=self._log_file,
                stderr=subprocess.STDOUT,
                close_fds=True,
            )
            _wait_for_ports(
                (self.spec["grpc_port"], self.spec["thrift_port"]),
                self.process,
                timeout=5.0,
            )
        except Exception as error:
            self._stop_process()
            detail = log_path.read_text(encoding="utf-8", errors="replace").strip()
            if detail:
                raise RuntimeError(f"{self.name}: {error}:\n{detail}") from error
            raise

    def _stop_process(self):
        process = self.process
        try:
            if process is not None and process.poll() is None:
                try:
                    process.terminate()
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=3.0)
                except subprocess.TimeoutExpired:
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=1.0)
            self.process = None
        finally:
            if self._log_file is not None:
                self._log_file.close()
                self._log_file = None

    def stop(self, deleteIntfs=True):
        self._stop_process()
        super().stop(deleteIntfs=deleteIntfs)


class DiamondTopology(Topo):
    def build(self, runtime_dir, switch_executable="simple_switch_grpc"):
        for name, config in HOSTS.items():
            self.addHost(name, ip=config["address"], mac=config["mac"])
        for name, spec in SWITCHES.items():
            self.addSwitch(
                name,
                cls=P4RuntimeSwitch,
                spec=spec,
                runtime_dir=Path(runtime_dir) / name,
                executable=switch_executable,
            )
        for left, left_port, right, right_port in LINKS:
            self.addLink(left, right, port1=left_port, port2=right_port)


def _run_node_command(node, command):
    stdout, stderr, status = node.pexec(command)
    if status != 0:
        rendered = " ".join(command)
        detail = stderr.strip() or stdout.strip()
        raise RuntimeError(f"{node.name}: {rendered} failed: {detail}")


def _disable_offloads(node, interface):
    _run_node_command(
        node,
        [
            "ethtool",
            "--offload",
            interface,
            "rx",
            "off",
            "tx",
            "off",
            "sg",
            "off",
            "tso",
            "off",
            "gso",
            "off",
            "gro",
            "off",
            "lro",
            "off",
        ],
    )


def _configure_host(host, config):
    interface = host.defaultIntf().name
    _run_node_command(host, ["ip", "-4", "address", "flush", "dev", interface])
    _run_node_command(
        host, ["ip", "address", "add", config["address"], "dev", interface]
    )
    _run_node_command(host, ["ip", "link", "set", "dev", interface, "up"])
    _run_node_command(
        host,
        ["ip", "route", "replace", config["peer_prefix"], "dev", interface],
    )
    _run_node_command(
        host,
        [
            "ip",
            "neighbor",
            "replace",
            config["peer_address"],
            "lladdr",
            config["peer_mac"],
            "nud",
            "permanent",
            "dev",
            interface,
        ],
    )
    _run_node_command(host, ["sysctl", "-qw", "net.ipv6.conf.all.disable_ipv6=1"])
    _run_node_command(host, ["sysctl", "-qw", "net.ipv6.conf.default.disable_ipv6=1"])
    _disable_offloads(host, interface)


class SourceRoutingNetwork:
    def __init__(
        self,
        controller,
        p4info,
        device_config,
        switch_executable="simple_switch_grpc",
        controller_timeout=25.0,
    ):
        self.controller = Path(controller)
        self.p4info = Path(p4info)
        self.device_config = Path(device_config)
        self.switch_executable = switch_executable
        self.controller_timeout = float(controller_timeout)
        self.net = None
        self.controller_output = ""
        self._runtime_dir = None

    def start(self):
        if self.net is not None:
            raise RuntimeError("network is already running")
        if self.controller_timeout <= 0:
            raise ValueError("controller timeout must be positive")
        for path in (self.controller, self.p4info, self.device_config):
            if not path.is_file():
                raise FileNotFoundError(path)
        if not os.access(self.controller, os.X_OK):
            raise PermissionError(f"controller is not executable: {self.controller}")
        executable = shutil.which(self.switch_executable)
        if executable is None:
            raise RuntimeError(f"{self.switch_executable} is not installed")

        service_ports = set()
        for spec in SWITCHES.values():
            for address, port in (
                ("127.0.0.1", spec["grpc_port"]),
                ("0.0.0.0", spec["thrift_port"]),
            ):
                if port in service_ports:
                    raise ValueError(f"TCP port {port} is configured more than once")
                service_ports.add(port)
                _check_port_available(address, port)
        _check_interfaces_available()

        try:
            self._runtime_dir = tempfile.TemporaryDirectory(prefix="p4-source-routing-")
            topology = DiamondTopology(
                runtime_dir=self._runtime_dir.name,
                switch_executable=executable,
            )
            self.net = Mininet(
                topo=topology,
                controller=None,
                build=False,
                autoStaticArp=False,
                waitConnected=False,
            )
            self.net.build()
            self.net.start()
            self._configure_nodes()
            self._configure_pipeline()
        except BaseException:
            self.close()
            raise
        return self

    def _configure_nodes(self):
        for name, config in HOSTS.items():
            _configure_host(self.net.get(name), config)
        for name, spec in SWITCHES.items():
            switch = self.net.get(name)
            for port in spec["ports"]:
                _disable_offloads(switch, switch.intfs[port].name)

    def _run_controller(self, verify_only):
        command = build_controller_command(
            self.controller,
            self.p4info,
            self.device_config,
            self.controller_timeout,
            verify_only=verify_only,
        )
        try:
            result = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=self.controller_timeout + 5.0,
            )
        except subprocess.TimeoutExpired as error:
            raise RuntimeError("controller timed out") from error
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            raise RuntimeError(
                f"controller exited with status {result.returncode}: {detail}"
            )
        return result.stdout.strip()

    def _configure_pipeline(self):
        self.controller_output = self._run_controller(verify_only=False)

    def verify(self):
        if self.net is None:
            raise RuntimeError("network is not running")
        return self._run_controller(verify_only=True)

    def close(self):
        net = self.net
        self.net = None
        runtime_dir = self._runtime_dir
        self._runtime_dir = None
        try:
            if net is not None:
                for switch in net.switches:
                    try:
                        switch._stop_process()
                    except BaseException:
                        pass
                try:
                    net.stop()
                except BaseException as stop_error:
                    recovery_errors = []

                    def recover(description, operation):
                        try:
                            operation()
                        except BaseException as error:
                            recovery_errors.append(f"{description}: {error}")

                    for link in net.links:
                        recover("stop link", link.stop)
                    for switch in net.switches:
                        recover(f"stop {switch.name} process", switch._stop_process)
                        recover(f"stop {switch.name}", switch.stop)
                        recover(f"terminate {switch.name}", switch.terminate)
                    for host in net.hosts:
                        recover(f"terminate {host.name}", host.terminate)
                    if recovery_errors:
                        detail = "; ".join(recovery_errors)
                        raise RuntimeError(
                            f"Mininet cleanup failed after {stop_error}: {detail}"
                        ) from stop_error
        finally:
            if runtime_dir is not None:
                runtime_dir.cleanup()

    def __enter__(self):
        return self.start()

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False


def _parse_args():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="run the source-routing topology")
    parser.add_argument(
        "--controller", default=root / "build" / "controller", type=Path
    )
    parser.add_argument(
        "--p4info",
        default=root / "build" / "source_routing.p4info.txtpb",
        type=Path,
    )
    parser.add_argument(
        "--device-config",
        default=root / "build" / "source_routing.json",
        type=Path,
    )
    parser.add_argument("--switch", default="simple_switch_grpc")
    return parser.parse_args()


def _exit_on_signal(signum, frame):
    raise SystemExit(128 + signum)


def main():
    if os.geteuid() != 0:
        raise SystemExit("Mininet requires root privileges")

    args = _parse_args()
    signal.signal(signal.SIGTERM, _exit_on_signal)
    signal.signal(signal.SIGHUP, _exit_on_signal)
    with SourceRoutingNetwork(
        controller=args.controller,
        p4info=args.p4info,
        device_config=args.device_config,
        switch_executable=args.switch,
    ) as runtime:
        if runtime.controller_output:
            print(runtime.controller_output)
        CLI(runtime.net)


if __name__ == "__main__":
    main()
