import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
P4_SOURCE = ROOT / "p4" / "source_routing.p4"


def find_named(items, name):
    for item in items:
        if item.get("name") == name:
            return item
    raise AssertionError(f"missing {name!r}")


def contains_value(value, expected):
    if value == expected:
        return True
    if isinstance(value, dict):
        return any(contains_value(child, expected) for child in value.values())
    if isinstance(value, list):
        return any(contains_value(child, expected) for child in value)
    return False


def transition_destination(transitions, value):
    default = None
    for transition in transitions:
        if transition["type"] == "default":
            default = transition["next_state"]
            continue
        encoded = int(transition["value"], 16)
        mask = (
            int(transition["mask"], 16)
            if transition["mask"]
            else (1 << (4 * (len(transition["value"]) - 2))) - 1
        )
        if value & mask == encoded & mask:
            return transition["next_state"]
    return default


class P4StructureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("p4c-bm2-ss")
        if compiler is None:
            raise RuntimeError("p4c-bm2-ss is not installed")

        cls.tempdir = tempfile.TemporaryDirectory(prefix="p4-source-routing-")
        output_dir = Path(cls.tempdir.name)
        cls.json_path = output_dir / "source_routing.json"
        cls.p4info_path = output_dir / "source_routing.p4info.txtpb"

        result = subprocess.run(
            [
                compiler,
                "--std",
                "p4-16",
                "--Werror",
                "--p4runtime-files",
                str(cls.p4info_path),
                "-o",
                str(cls.json_path),
                str(P4_SOURCE),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"P4 compilation failed ({result.returncode}):\n"
                f"{result.stdout}{result.stderr}"
            )

        cls.compiler_output = result.stdout + result.stderr
        cls.bmv2 = json.loads(cls.json_path.read_text(encoding="utf-8"))
        cls.p4info = cls.p4info_path.read_text(encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        cls.tempdir.cleanup()

    def test_compiles_without_warnings(self):
        self.assertNotRegex(self.compiler_output.lower(), r"\bwarning:")

    def test_p4runtime_contract(self):
        self.assertEqual(self.p4info.count('name: "MyIngress.valid_egress_port"'), 1)
        self.assertRegex(
            self.p4info,
            r'name: "meta\.requested_port"\s+bitwidth: 8\s+match_type: EXACT',
        )
        self.assertRegex(
            self.p4info,
            r'(?s)name: "MyIngress\.set_egress".*?'
            r'name: "port"\s+bitwidth: 9',
        )
        self.assertEqual(self.p4info.count('name: "MyIngress.drop"'), 1)
        self.assertRegex(self.p4info, r'(?m)^  size: 8$')

    def test_header_stack_shape(self):
        stack = find_named(self.bmv2["header_stacks"], "route")
        self.assertEqual(stack["header_type"], "source_route_entry_t")
        self.assertEqual(stack["size"], 8)

        headers_by_id = {header["id"]: header for header in self.bmv2["headers"]}
        self.assertEqual(
            [headers_by_id[header_id]["name"] for header_id in stack["header_ids"]],
            [f"route[{index}]" for index in range(8)],
        )

        entry_type = find_named(self.bmv2["header_types"], "source_route_entry_t")
        self.assertEqual(entry_type["fields"], [["output_port", 8, False]])
        base_type = find_named(self.bmv2["header_types"], "source_route_base_t")
        self.assertEqual(
            base_type["fields"],
            [["next_header", 16, False], ["route_length", 8, False]],
        )

    def test_parser_bounds_and_stack_extraction(self):
        parser = find_named(self.bmv2["parsers"], "parser")
        states = {state["name"]: state for state in parser["parse_states"]}
        self.assertTrue(
            {
                "start",
                "parse_source_route_base",
                "reject_source_route",
                "parse_source_route_entry",
                "parse_ipv4",
            }.issubset(states)
        )

        self.assertEqual(
            transition_destination(states["start"]["transitions"], 0x88B5),
            "parse_source_route_base",
        )
        self.assertEqual(
            transition_destination(states["start"]["transitions"], 0x0800),
            "parse_ipv4",
        )

        base_operations = states["parse_source_route_base"]["parser_ops"]
        self.assertTrue(any(operation["op"] == "verify" for operation in base_operations))
        self.assertTrue(
            contains_value(
                base_operations,
                {"type": "field", "value": ["source_route", "next_header"]},
            )
        )
        self.assertTrue(
            contains_value(base_operations, {"type": "hexstr", "value": "0x0800"})
        )

        base_transitions = states["parse_source_route_base"]["transitions"]
        for route_length in range(256):
            expected = (
                "parse_source_route_entry"
                if 1 <= route_length <= 8
                else "reject_source_route"
            )
            self.assertEqual(
                transition_destination(base_transitions, route_length),
                expected,
                f"route length {route_length}",
            )

        route_state = states["parse_source_route_entry"]
        self.assertTrue(
            any(
                operation["op"] == "extract"
                and operation["parameters"] == [{"type": "stack", "value": "route"}]
                for operation in route_state["parser_ops"]
            )
        )
        self.assertEqual(transition_destination(route_state["transitions"], 0), "parse_ipv4")
        self.assertEqual(
            transition_destination(route_state["transitions"], 1),
            "parse_source_route_entry",
        )
        self.assertTrue(
            any(
                operation["op"] == "verify"
                and contains_value(operation, {"type": "bool", "value": False})
                for operation in states["reject_source_route"]["parser_ops"]
            )
        )

    def test_ingress_validation_and_route_consumption(self):
        ingress = find_named(self.bmv2["pipelines"], "ingress")
        table = find_named(ingress["tables"], "MyIngress.valid_egress_port")
        self.assertEqual(len(table["key"]), 1)
        self.assertEqual(table["key"][0]["name"], "meta.requested_port")
        self.assertEqual(table["key"][0]["match_type"], "exact")
        self.assertEqual(
            set(table["actions"]),
            {"MyIngress.set_egress", "MyIngress.drop"},
        )

        drop_action = find_named(self.bmv2["actions"], "MyIngress.drop")
        self.assertEqual(table["default_entry"]["action_id"], drop_action["id"])
        set_egress = find_named(self.bmv2["actions"], "MyIngress.set_egress")
        self.assertTrue(
            any(
                primitive["op"] == "assign"
                and primitive["parameters"][0]
                == {"type": "field", "value": ["standard_metadata", "egress_spec"]}
                and contains_value(primitive, {"type": "runtime_data", "value": 0})
                for primitive in set_egress["primitives"]
            )
        )

        primitives = [
            primitive
            for action in self.bmv2["actions"]
            for primitive in action["primitives"]
        ]
        self.assertTrue(
            any(
                primitive["op"] == "pop"
                and contains_value(primitive, {"type": "header_stack", "value": "route"})
                and contains_value(primitive, {"type": "hexstr", "value": "0x1"})
                for primitive in primitives
            )
        )
        self.assertTrue(
            any(
                primitive["op"] == "assign"
                and primitive["parameters"][0]
                == {"type": "field", "value": ["source_route", "route_length"]}
                for primitive in primitives
            )
        )
        self.assertTrue(
            any(
                primitive["op"] == "assign"
                and primitive["parameters"][0]
                == {"type": "field", "value": ["ipv4", "ttl"]}
                for primitive in primitives
            )
        )
        self.assertTrue(
            any(
                primitive["op"] == "assign"
                and primitive["parameters"][0]
                == {"type": "field", "value": ["ethernet", "ether_type"]}
                and contains_value(primitive, {"type": "hexstr", "value": "0x0800"})
                for primitive in primitives
            )
        )
        self.assertTrue(
            any(
                primitive["op"] == "remove_header"
                and primitive["parameters"]
                == [{"type": "header", "value": "source_route"}]
                for primitive in primitives
            )
        )

        conditionals = ingress["conditionals"]
        for field in (
            ["standard_metadata", "parser_error"],
            ["standard_metadata", "checksum_error"],
            ["standard_metadata", "packet_length"],
            ["ipv4", "version"],
            ["ipv4", "ihl"],
            ["ipv4", "total_len"],
            ["ipv4", "flags"],
            ["ipv4", "fragment_offset"],
            ["ipv4", "ttl"],
        ):
            self.assertTrue(
                contains_value(conditionals, {"type": "field", "value": field}),
                f"missing validation for {field}",
            )

    def test_checksum_and_deparser(self):
        checksums = self.bmv2["checksums"]
        self.assertEqual(len(checksums), 2)
        self.assertEqual(
            {(checksum["verify"], checksum["update"]) for checksum in checksums},
            {(True, False), (False, True)},
        )
        self.assertTrue(
            all(checksum["target"] == ["ipv4", "header_checksum"] for checksum in checksums)
        )

        calculations = {
            calculation["name"]: calculation for calculation in self.bmv2["calculations"]
        }
        for checksum in checksums:
            calculation = calculations[checksum["calculation"]]
            self.assertEqual(calculation["algo"], "csum16")
            self.assertIn(
                {"type": "field", "value": ["ipv4", "ttl"]},
                calculation["input"],
            )

        deparser = find_named(self.bmv2["deparsers"], "deparser")
        self.assertEqual(
            deparser["order"],
            [
                "ethernet",
                "source_route",
                *[f"route[{index}]" for index in range(8)],
                "ipv4",
            ],
        )


if __name__ == "__main__":
    unittest.main()
