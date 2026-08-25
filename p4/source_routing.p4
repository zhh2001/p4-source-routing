#include <core.p4>
#include <v1model.p4>

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_SOURCE_ROUTE = 0x88b5;
const bit<32> SOURCE_ROUTE_PREFIX_BYTES = 17;
const int MAX_ROUTE_HOPS = 8;

typedef bit<9> port_t;

header ethernet_t {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

header source_route_base_t {
    bit<16> next_header;
    bit<8> route_length;
}

header source_route_entry_t {
    bit<8> output_port;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragment_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> header_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

struct headers_t {
    ethernet_t ethernet;
    source_route_base_t source_route;
    source_route_entry_t[MAX_ROUTE_HOPS] route;
    ipv4_t ipv4;
}

struct metadata_t {
    bit<8> parse_hops_remaining;
    bit<8> requested_port;
}

error {
    MalformedSourceRoute,
    UnsupportedInnerEtherType
}

parser MyParser(
        packet_in packet,
        out headers_t hdr,
        inout metadata_t meta,
        inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_SOURCE_ROUTE: parse_source_route_base;
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_source_route_base {
        packet.extract(hdr.source_route);
        meta.parse_hops_remaining = hdr.source_route.route_length;
        verify(hdr.source_route.next_header == ETHERTYPE_IPV4,
               error.UnsupportedInnerEtherType);
        transition select(hdr.source_route.route_length) {
            1..MAX_ROUTE_HOPS: parse_source_route_entry;
            default: reject_source_route;
        }
    }

    state reject_source_route {
        verify(false, error.MalformedSourceRoute);
        transition accept;
    }

    state parse_source_route_entry {
        packet.extract(hdr.route.next);
        meta.parse_hops_remaining = meta.parse_hops_remaining - 1;
        transition select(meta.parse_hops_remaining) {
            0: parse_ipv4;
            default: parse_source_route_entry;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
        verify_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragment_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            },
            hdr.ipv4.header_checksum,
            HashAlgorithm.csum16);
    }
}

control MyIngress(
        inout headers_t hdr,
        inout metadata_t meta,
        inout standard_metadata_t standard_metadata) {
    action set_egress(port_t port) {
        standard_metadata.egress_spec = port;
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    table valid_egress_port {
        key = {
            meta.requested_port: exact;
        }
        actions = {
            set_egress;
            drop;
        }
        size = 8;
        default_action = drop();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError ||
            !hdr.source_route.isValid() ||
            !hdr.ipv4.isValid()) {
            mark_to_drop(standard_metadata);
        } else if (standard_metadata.checksum_error != 0 ||
                   hdr.ipv4.version != 4 ||
                   hdr.ipv4.ihl != 5 ||
                   hdr.ipv4.total_len < 20 ||
                   standard_metadata.packet_length <
                       SOURCE_ROUTE_PREFIX_BYTES +
                       (bit<32>)hdr.source_route.route_length +
                       (bit<32>)hdr.ipv4.total_len ||
                   (hdr.ipv4.flags & 3w1) != 0 ||
                   hdr.ipv4.fragment_offset != 0 ||
                   hdr.ipv4.ttl <= 1) {
            mark_to_drop(standard_metadata);
        } else {
            meta.requested_port = hdr.route[0].output_port;
            if (valid_egress_port.apply().hit) {
                hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
                hdr.route.pop_front(1);
                hdr.source_route.route_length =
                    hdr.source_route.route_length - 1;

                if (hdr.source_route.route_length == 0) {
                    hdr.source_route.setInvalid();
                    hdr.ethernet.ether_type = ETHERTYPE_IPV4;
                }
            }
        }
    }
}

control MyEgress(
        inout headers_t hdr,
        inout metadata_t meta,
        inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragment_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            },
            hdr.ipv4.header_checksum,
            HashAlgorithm.csum16);
    }
}

control MyDeparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.source_route);
        packet.emit(hdr.route);
        packet.emit(hdr.ipv4);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
