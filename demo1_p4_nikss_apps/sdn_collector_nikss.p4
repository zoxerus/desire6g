#include <core.p4>
#include <psa.p4>

typedef bit<48>  EthernetAddress;
typedef bit<32>  IPv4Address;


#define MAX_REPORTS 16
#define COLLECTOR_PORT 35000
#define IP_PROTOCOL_UDP 8w17
#define ETH_TYPE_IPV4 16w2048
#define DSCP_INT 8w32

// Constants for Ethernet types
const bit<16> ETHERTYPE_INT_MD = 0x88b5;        // reserved by IEEE for experimental protocols
const bit<16> ETHERTYPE_INT_CTRL = 0x88b6;      // reserved by IEEE for experimental protocols
const bit<16> ETHERTYPE_IPV4    = 0x800 ;       // IPv4 protocol

// Constants for L4 Protocols
const bit<8>  L4PROTO_UDP = 0x11  ;
const bit<8>  L4PROTO_TCP = 0x06  ;


const bit<32> zero = 0;
const bit<32> one = 1;
const bit<32> two = 2;
const bit<32> three = 3;
const bit<32> four = 4;
const bit<32> five = 5; 
const bit<32> six = 6; 
const bit<32> seven = 7;
const bit<32> eight = 8; 
const bit<32> nine = 9;
const bit<32> ten = 10;
const bit<32> eleven = 11;
const bit<32> twelve = 12;
const bit<32> thirteen = 13;
const bit<32> fourteen = 14; 
const bit<32> fifteen = 15;


struct empty_t {}

header ethernet_t {
    bit<48> dst_mac;
    bit<48> src_mac;
    bit<16>         ether_type;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> src_ip;
    bit<32> dst_ip;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length;
    bit<16> checksum;
}


header int_md_t {
    /* 
    int_label is used to identify the flow,
    also used to select the register index to read the egress port.
    */
    bit<16> int_label;

    /* a field to save the original EtherType field, 
        so it can be restored at the end of the SDN domain */
    bit<16> original_ether_type;

    bit<64> latency;
}

/*
Th INT control header that is sent back into the SDN domain for in-band control.
    this header is used by the active collector to send the egress port for the INT packet
    back to the ingress node, so it can be used to set the egress port in the register.
*/
header int_inc_t {
    /* 
    the label serves for forwarding the control message in the backwards directions
    */
    bit<16> int_label;
    /* 
    This is the index of the register that holds the egress port in the ingress node.
    */
    bit<32> register_index;
    /* 
    the value of the output port to be written in the register. 
    */
    bit<16> output_port;
}

header l4_ports_t {
    bit<16> src_port;
    bit<16> dst_port;
}

struct metadata {
    bit<64> int_threshold; // threshold for INT metadata
    CloneSessionId_t clone_session_id;
}

header int_agg_t {
    bit<80> one_field; // 16 bits for label, 64 bits for latency
}

struct headers {
    ethernet_t                  ethernet;
    ipv4_t                      ipv4;
    udp_t                       udp;
    int_md_t                    int_md;
    int_inc_t                   int_inc;
    l4_ports_t                  l4_ports;
    int_agg_t[MAX_REPORTS]      agg_reports;
}

/* The Ingress Parser */
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
            ETHERTYPE_INT_MD: parse_int_md;
            ETHERTYPE_INT_CTRL: parse_inc;
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_int_md {
        buffer.extract(parsed_hdr.int_md);
        transition accept;
    }

    state parse_inc {
        buffer.extract(parsed_hdr.int_inc);
        transition accept;

    }

    state parse_ipv4 {
        buffer.extract(parsed_hdr.ipv4);
        transition select(parsed_hdr.ipv4.protocol) {
            L4PROTO_UDP: parse_l4_ports;
            L4PROTO_TCP: parse_l4_ports;
            default: accept;
        }
    }

    state parse_l4_ports {
        buffer.extract(parsed_hdr.l4_ports);
        transition accept;
    }

    state parse_udp {
        /* extract UDP header */
        buffer.extract(parsed_hdr.udp);
        /* determine if this packet is carrying INT header from the DSCP field */
        transition select(parsed_hdr.ipv4.diffserv){
            DSCP_INT: parse_int;  // DSCP indicates if the packet is carrying INT
            default: accept;
        }
    }

    state parse_int {
        /* extract the shim header and INT metadata header */
        buffer.extract(parsed_hdr.int_md);
        transition accept;
    }
} // end of IngressParserImpl

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
            ETHERTYPE_INT_MD: parse_int_md;
            ETHERTYPE_INT_CTRL: parse_inc;
            default: accept;
        }
    }

    state parse_int_md {
        buffer.extract(parsed_hdr.int_md);
        transition accept;
    }

    state parse_inc {
        buffer.extract(parsed_hdr.int_inc);
        transition accept;

    }
}

control ingress(inout headers hdr,
                inout metadata meta,
                in    psa_ingress_input_metadata_t  istd,
                inout psa_ingress_output_metadata_t ostd)
{
    /* a register to hold reports*/
    Register<bit<80>, bit<32>>(32w16) reg_report_buffer;
    Register<bit<32>, bit<32>>(32w1) reg_report_counter;
    bit<32> pointer; 

    action do_forward(PortId_t egress_port) {
        send_to_port(ostd, egress_port);
    }

    table tbl_fwd {
        key = {
            hdr.ipv4.dst_ip : lpm;
        }
        actions = { do_forward; NoAction; }
        default_action = NoAction;
        size = 100;
    } 

    action ac_set_threshold(bit<64> threshold, 
                            CloneSessionId_t clone_session) {
        meta.int_threshold = threshold;
        meta.clone_session_id = clone_session; // Reset clone session ID
    }


    table tbl_set_latency_threshold {
        key = {
            hdr.int_md.int_label : exact;
        }
        actions = { ac_set_threshold; NoAction; }
        default_action = NoAction;
        size = 100;
    } 
 
    apply {
        if (hdr.int_md.isValid()){
            tbl_set_latency_threshold.apply();

            if (hdr.int_md.latency > meta.int_threshold) {
                ostd.clone = true;
                ostd.clone_session_id = (CloneSessionId_t) meta.clone_session_id; 
            }


            pointer = reg_report_counter.read(zero);
            
            
            bit<64> latency = hdr.int_md.latency;
            bit<16> int_label = hdr.int_md.int_label;
            bit<80> report_data =  int_label ++ latency;


            reg_report_buffer.write(pointer, report_data);
            if (pointer == fifteen ) {
                hdr.agg_reports[zero].setValid();
                hdr.agg_reports[one].setValid();
                hdr.agg_reports[two].setValid();
                hdr.agg_reports[three].setValid();
                hdr.agg_reports[four].setValid();
                hdr.agg_reports[five].setValid();
                hdr.agg_reports[six].setValid();
                hdr.agg_reports[seven].setValid();
                hdr.agg_reports[eight].setValid();
                hdr.agg_reports[nine].setValid();
                hdr.agg_reports[ten].setValid();
                hdr.agg_reports[eleven].setValid();
                hdr.agg_reports[twelve].setValid();
                hdr.agg_reports[thirteen].setValid();
                hdr.agg_reports[fourteen].setValid();
                hdr.agg_reports[fifteen].setValid();

                hdr.agg_reports[zero].one_field = reg_report_buffer.read(zero);
                hdr.agg_reports[one].one_field = reg_report_buffer.read(one);
                hdr.agg_reports[two].one_field = reg_report_buffer.read(two);
                hdr.agg_reports[three].one_field = reg_report_buffer.read(three);
                hdr.agg_reports[four].one_field = reg_report_buffer.read(four);
                hdr.agg_reports[five].one_field = reg_report_buffer.read(five);
                hdr.agg_reports[six].one_field = reg_report_buffer.read(six);
                hdr.agg_reports[seven].one_field = reg_report_buffer.read(seven);
                hdr.agg_reports[eight].one_field = reg_report_buffer.read(eight);
                hdr.agg_reports[nine].one_field = reg_report_buffer.read(nine);
                hdr.agg_reports[ten].one_field = reg_report_buffer.read(ten);
                hdr.agg_reports[eleven].one_field = reg_report_buffer.read(eleven);
                hdr.agg_reports[twelve].one_field = reg_report_buffer.read(twelve);
                hdr.agg_reports[thirteen].one_field = reg_report_buffer.read(thirteen);
                hdr.agg_reports[fourteen].one_field = reg_report_buffer.read(fourteen);
                hdr.agg_reports[fifteen].one_field = reg_report_buffer.read(fifteen);

                pointer = 0;
                reg_report_counter.write(zero, pointer);
            }
        }
    }
}


control egress(inout headers hdr,
               inout metadata meta,
               in    psa_egress_input_metadata_t  istd,
               inout psa_egress_output_metadata_t ostd)
{

    action ac_set_inband_control (bit<16> int_label, 
                                    bit<32> register_index, 
                                    bit<16> output_port) {
        hdr.int_inc.setValid();
        hdr.int_inc.int_label = int_label;
        hdr.int_inc.register_index = register_index;
        hdr.int_inc.output_port = output_port;

        // Set the original EtherType to the INT header
        hdr.ethernet.ether_type = ETHERTYPE_INT_CTRL;
        hdr.int_md.setInvalid();
    }

    // Table to forward packets based on the INT label
    // Matches the label to a register index that holds the egress port
    table tb_inband_control {
        key = {            
            hdr.int_md.int_label: exact;
        }
        actions = {
            ac_set_inband_control;
            NoAction;
        }
        default_action = NoAction;
        size = 1024;

    }


    apply { 

        if (istd.packet_path == PSA_PacketPath_t.CLONE_I2E ){
            tb_inband_control.apply();
        }
    }
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