# P4 source routing

This repository is a small P4_16 source-routing reference implementation for BMv2. Each packet carries a fixed-capacity stack of output ports. Every switch validates the first port, forwards through it, and removes exactly that entry. The switches do not compute routes, and the control plane does not install per-flow paths.

This is basic packet-carried source routing, not Segment Routing, SR-MPLS, or SRv6.

## Packet format

Source-routed frames use the IEEE local experimental EtherType `0x88b5`:

```text
Ethernet
  SourceRouteBase
    next_header   16 bits
    route_length   8 bits
  SourceRouteEntry[route_length]
    output_port    8 bits
  IPv4
  transport payload
```

The base header is three bytes. `next_header` must be the IPv4 EtherType `0x0800`, and `route_length` is the number of remaining entries serialized in the packet. The P4 program implements the entries as a stack of eight `source_route_entry_t` headers; valid encoded lengths are therefore 1 through 8, not arbitrary length.

For `[2,2,1]`, the packet changes as follows:

| Link | Encapsulation | IPv4 TTL |
| --- | --- | ---: |
| h1 to s1 | source route `[2,2,1]` | 64 |
| s1 to s2 | source route `[2,1]` | 63 |
| s2 to s4 | source route `[1]` | 62 |
| s4 to h2 | ordinary IPv4 | 61 |

On the final pop, the source-route base and entry stack are no longer emitted, and the Ethernet EtherType is restored to `0x0800`. The IPv4 source and destination remain unchanged.

## Topology and routes

```text
                    (1) s2 (2)
                      /     \
h1 -- (1) s1 (2) -----       ----- (2) s4 (1) -- h2
             (3) -----       ----- (3)
                      \     /
                    (1) s3 (2)
```

The hosts use deterministic addresses:

| Host | IPv4 address | MAC address |
| --- | --- | --- |
| h1 | `10.0.1.1/24` | `00:00:00:00:01:01` |
| h2 | `10.0.4.1/24` | `00:00:00:00:04:01` |

The packet-carried routes are:

| Name | Path | Entries |
| --- | --- | --- |
| upper | h1, s1, s2, s4, h2 | `[2,2,1]` |
| lower | h1, s1, s3, s4, h2 | `[3,2,1]` |
| reverse upper | h2, s4, s2, s1, h1 | `[2,1,1]` |
| reverse lower | h2, s4, s3, s1, h1 | `[3,1,1]` |

The upper and lower forward packets have the same IPv4 destination. Changing only the stack selects s2 or s3.

## Data-plane behavior

The parser extracts exactly `route_length` entries with the P4 header-stack `next` operation. In ingress, the first entry becomes the requested output port. A P4Runtime-populated exact-match table permits only ports physically present on that switch; its default action drops the packet.

| Switch | Valid ports |
| --- | --- |
| s1 | `1, 2, 3` |
| s2 | `1, 2` |
| s3 | `1, 2` |
| s4 | `1, 2, 3` |

After a successful lookup, ingress decrements IPv4 TTL once, calls `route.pop_front(1)`, and decrements `route_length`. Invalid ports are dropped before either change.

The data plane verifies the incoming IPv4 header checksum and recomputes it after changing TTL. It accepts IPv4 version 4 with IHL 5, a total length of at least 20 bytes that fits in the received frame, no MF flag, zero fragment offset, and TTL greater than 1. Exact equality between the IPv4 total length and the frame remainder is not required, so trailing Ethernet padding is allowed. P4 does not parse or rewrite TCP or UDP; their headers, checksums, and payloads pass through unchanged.

## Control plane

The Go controller uses the pinned [`p4runtime-go-controller`](https://github.com/zhh2001/p4runtime-go-controller) module. For each switch it establishes P4Runtime primary arbitration, installs the compiled pipeline, and writes that switch's valid-port entries. It then reads back and compares both the pipeline and the exact table-entry set. Its `--verify-only` option performs the same readback without writing.

Device IDs are 1 through 4 for s1 through s4. Their P4Runtime endpoints are `127.0.0.1:50051` through `127.0.0.1:50054`; their Thrift ports are 9091 through 9094.

## Prerequisites

The project expects an existing Linux P4 development environment with:

- `p4c-bm2-ss` and the v1model include files;
- BMv2 `simple_switch_grpc`;
- Mininet, `iproute2`, `procps`, and `ethtool`;
- Python 3 with Scapy;
- Go matching the version declared in `go.mod`;
- `make` and `sudo` access for Mininet integration tests.

No separate controller framework is required; Go resolves the controller module versions recorded in `go.mod` and `go.sum`.

## Build and run

Build the P4 pipeline and Go controller:

```sh
make build
```

Outputs are written under the ignored `build/` directory. Start all four BMv2 switches, configure them over P4Runtime, and enter the Mininet CLI with:

```sh
make run
```

The fixed interface names and TCP service ports must be free before starting the topology.

The packet utility provides the four deterministic route profiles. From the Mininet prompt, for example:

```text
mininet> net
mininet> h1 python3 tools/source_route.py send upper demo-upper
mininet> h1 python3 tools/source_route.py send lower demo-lower
mininet> h2 python3 tools/source_route.py send reverse-upper demo-reverse
mininet> h2 python3 tools/source_route.py send reverse-lower demo-reverse-lower
```

Exiting the CLI stops the owned switch processes, removes the Mininet links, and deletes the temporary runtime directory.

## Tests

Run the complete suite with:

```sh
make test
```

The unit portion compiles P4 with warnings treated as errors, checks the P4Info and BMv2 JSON structure, compiles the Python support code, and runs Go tests and `go vet`. The integration portion starts the real topology, verifies controller readback and failure-path cleanup, and captures all six links with raw sockets.

Packet tests cover both forward branches, both reverse branches, exact stack consumption, final decapsulation, per-hop TTL and IPv4 checksum, TCP and UDP transparency, multiplicity, invalid ports, empty and oversized stacks, malformed and truncated headers, route exhaustion, extra entries, TTL expiry, invalid IPv4 checksums and lengths, options, and fragments.

Use `make test-unit` for the unprivileged checks and `make test-integration` for the privileged Mininet tests. `make clean` removes only `./build`.

## Limitations

- Only source-route-encapsulated IPv4 is forwarded. An ordinary IPv4 packet arriving at a P4 switch is dropped; there is no IPv4-routing fallback.
- ARP is not implemented in P4, so the topology installs permanent neighbor entries. An ordinary `ping` does not inject a source route and is dropped.
- IPv4 options, fragments, IPv6, and non-IPv4 inner EtherTypes are unsupported.
- P4 verifies only the IPv4 checksum. It preserves TCP and UDP checksums but does not reject an invalid transport checksum.
- A short route `[2]` is consumed by s1 and emitted toward s2 as ordinary IPv4 with TTL 63. Because s2 has no source-route header to consume, s2 drops it.
- An extra route `[2,2,1,99]` remains authoritative. It reaches the h2-facing link as source route `[99]` with TTL 61, so h2 does not receive ordinary IPv4.
- Route injection is host-side. There is no route computation, routing protocol, failure rerouting, authentication, multicast, or per-packet controller involvement.
