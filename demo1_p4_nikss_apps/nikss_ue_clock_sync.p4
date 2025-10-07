#include <core.p4>
#include <psa.p4>

typedef bit<48>  EthernetAddress;
typedef bit<32>  IPv4Address;


#define ETHERTYPE_VLAN 16w0x8100 // IEEE 802.1Q
#define ETHERTYPE_IPV4 16w0x0800
#define ETHERTYPE_IPV6 16w0x86DD
#define ETHERTYPE_D6G 16w0xD6D6
#define ETHERTYPE_D6GINT 16w0xDF01
#define ETHERTYPE_CLOCK_SYNC 16w0xDF02


struct empty_t {}

header ethernet_t {
    bit<48> dst_mac;
    bit<48> src_mac;
    bit<16> ether_type;
}


header clock_sync_h {
    bit<8> count;
    bit<32> t0;
    bit<32> t1;
    bit<32> t2;
    bit<32> t3;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdr_checksum;
    bit<32> src_ip;
    bit<32> dst_ip;
}

header d6gmain_t {
   bit<16> serviceId; 	// Network service or slice
   bit<16> locationId; 	// UE location if applicable
   bit<1>  hhFlag;
   bit<7>  _reserved;
   bit<16> nextNF;	// next network function in the service graph
   bit<16> nextHeader;	// identifier of the next header elements
}

header d6gint_t {
   bit<16> next_header;
   bit<32> t1; // timestamp 
   bit<32> t2; // timestamp
   bit<32> t3; // timestamp
}

struct metadata {
    bit<32>  global_tstamp;
    bit<32>  reference_tstamp;
}


struct headers {
    ethernet_t       ethernet;
    d6gmain_t        d6gmain;
    d6gint_t         d6gint;
    ipv4_t           ipv4;
}

parser IngressParserImpl(packet_in buffer,
                         out headers parsed_hdr,
                         inout metadata meta,
                         in psa_ingress_parser_input_metadata_t istd,
                         in empty_t resubmit_meta,
                         in empty_t recirculate_meta)
{
    state start {
        buffer.extract(parsed_hdr.ethernet);
        transition select(parsed_hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_D6G: parse_d6gmain;
            default: accept;
        }
    }

    state parse_ipv4 {
        buffer.extract(parsed_hdr.ipv4);
        transition accept;
    }

    state parse_d6gmain {
        buffer.extract(parsed_hdr.d6gmain);
        transition select(parsed_hdr.d6gmain.nextHeader){
            ETHERTYPE_D6GINT: parse_d6gint;
            default: accept;
        }
    }

    state parse_d6gint {
        buffer.extract(parsed_hdr.d6gint);
        transition accept;
    }
}

parser EgressParserImpl(packet_in buffer,
                        out headers parsed_hdr,
                        inout metadata meta,
                        in psa_egress_parser_input_metadata_t istd,
                        in empty_t normal_meta,
                        in empty_t clone_i2e_meta,
                        in empty_t clone_e2e_meta)
{
    state start {
        buffer.extract(parsed_hdr.ethernet);
        transition select(parsed_hdr.ethernet.ether_type) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        buffer.extract(parsed_hdr.ipv4);
        transition accept;
    }
}

control ingress(inout headers hdr,
                inout metadata meta,
                in    psa_ingress_input_metadata_t  istd,
                inout psa_ingress_output_metadata_t ostd)
{
    Register<bit<32>, bit<32>>(32w1) register_tstamp_ref;


    action do_forward_t1(PortId_t egress_port) {
        hdr.d6gint.setValid();
        hdr.d6gint.next_header = hdr.d6gmain.nextHeader;
        hdr.d6gmain.nextHeader = ETHERTYPE_D6GINT;
        hdr.d6gint.t1 = meta.global_tstamp - meta.reference_tstamp;
        send_to_port(ostd, egress_port);
    }
    
    action do_forward_t2(PortId_t egress_port) {
        hdr.d6gint.t2 = meta.global_tstamp - meta.reference_tstamp;
        send_to_port(ostd, egress_port);
    }

    action do_forward_t3(PortId_t egress_port) {
        hdr.d6gint.t3 = meta.global_tstamp - meta.reference_tstamp;
        send_to_port(ostd, egress_port);
    }

    action do_forward(PortId_t egress_port) {
        send_to_port(ostd, egress_port);
    }

    action do_add_d6g_header( 
                bit<16> serviceId, 
                bit<16> locationId, 
                bit<1> hhFlag,
                bit<16> nextNF
    ) {
        hdr.d6gmain.setValid();
        hdr.d6gmain.serviceId = serviceId;
        hdr.d6gmain.locationId = locationId;
        hdr.d6gmain.hhFlag = hhFlag;
        hdr.d6gmain._reserved = 0;
        hdr.d6gmain.nextNF = nextNF;
        hdr.d6gmain.nextHeader = hdr.ethernet.ether_type;
        hdr.ethernet.ether_type = ETHERTYPE_D6G;
    }

    action do_remove_d6g_header( 
                PortId_t egress_port
    ) {
        hdr.ethernet.ether_type = hdr.d6gmain.nextHeader;
        hdr.d6gmain.setInvalid();
        send_to_port(ostd, egress_port);
    }


    table tbl_d6g_fwd {
        key = {
            hdr.d6gmain.serviceId : exact;
            hdr.d6gmain.nextNF:     exact;
        }
        actions = { do_remove_d6g_header; 
                    do_forward; 
                    do_forward_t1; 
                    do_forward_t2; 
                    do_forward_t3; 
                    NoAction; }

        default_action = NoAction;
        size = 100;
    }

    table tbl_ipv4_fwd {
        key = {
            hdr.ipv4.dst_ip: lpm;
        }
        actions = { do_forward; do_add_d6g_header; NoAction; }
        default_action = NoAction;
        size = 100;
    }

    table tbl_d6g_int {
        key = {
            hdr.ipv4.dst_ip: lpm;
        }
        actions = { do_forward; do_add_d6g_header; NoAction; }
        default_action = NoAction;
        size = 100;
    }
    apply {
        bit<32> zero;
        zero = 0 ;
        meta.global_tstamp = ((bit<64>) istd.ingress_timestamp)[47:16];

        if(hdr.ethernet.ether_type == ETHERTYPE_CLOCK_SYNC) {
            register_tstamp_ref.write(zero, meta.global_tstamp);
            exit;
        } else {
            meta.reference_tstamp = register_tstamp_ref.read(zero);
        }
        if (hdr.ipv4.isValid()) tbl_ipv4_fwd.apply();
        if (hdr.d6gmain.isValid()) tbl_d6g_fwd.apply();
    }
}


control egress(inout headers hdr,
               inout metadata meta,
               in    psa_egress_input_metadata_t  istd,
               inout psa_egress_output_metadata_t ostd)
{
    apply { }
}

control CommonDeparserImpl(packet_out packet,
                           inout headers hdr)
{
    apply {
        packet.emit(hdr);
    }
}

control IngressDeparserImpl(packet_out buffer,
                            out empty_t clone_i2e_meta,
                            out empty_t resubmit_meta,
                            out empty_t normal_meta,
                            inout headers hdr,
                            in metadata meta,
                            in psa_ingress_output_metadata_t istd)
{
    CommonDeparserImpl() cp;
    apply {
        cp.apply(buffer, hdr);
    }
}

control EgressDeparserImpl(packet_out buffer,
                           out empty_t clone_e2e_meta,
                           out empty_t recirculate_meta,
                           inout headers hdr,
                           in metadata meta,
                           in psa_egress_output_metadata_t istd,
                           in psa_egress_deparser_input_metadata_t edstd)
{
    CommonDeparserImpl() cp;
    apply {
        cp.apply(buffer, hdr);
    }
}

IngressPipeline(IngressParserImpl(),
                ingress(),
                IngressDeparserImpl()) ip;

EgressPipeline(EgressParserImpl(),
               egress(),
               EgressDeparserImpl()) ep;

PSA_Switch(ip, PacketReplicationEngine(), ep, BufferingQueueingEngine()) main;