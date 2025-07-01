#include <core.p4>
#include <psa.p4>


typedef bit<32> label_port_register_index_t;

// #define MAX_SWITCHES 5

// Constants for Ethernet types
const bit<16> ETHERTYPE_INT_MD = 0x88b5;        // reserved by IEEE for experimental protocols
const bit<16> ETHERTYPE_INT_CTRL = 0x88b5;      // reserved by IEEE for experimental protocols
const bit<16> ETHERTYPE_IPV4    = 0x800 ;       // IPv4 protocol

// Constants for L4 Protocols
const bit<8>  L4PROTO_UDP = 0x11  ;
const bit<8>  L4PROTO_TCP = 0x06  ;


const bit<32> MAX_SWITCHES = 5;

// compiler complains if numbers are used directly in the code,
// so we define them as constants.
const bit<32> zero  = 0;
const bit<32> one   = 1;
const bit<32> two   = 2;
const bit<32> three = 3;
const bit<32> four  = 4;
const bit<32> five  = 5;




struct empty_t {}

header ethernet_t {
    bit<48> dst_mac;
    bit<48> src_mac;
    bit<16> ether_type;
}





/*
This header is inserted by the ingress node and is  used as a shim header for INT (In-band Network Telemetry).
it is applied to data packets that are entering the INT SDN domain.
and is followed by a series of int_md_t headers that contain the timestamps
*/
header int_main_t {
    /* 
    int_label is used to identify the flow,
    also used to select the register index to read the egress port.
    */
    bit<16> int_label;

    /* a field to save the original EtherType field, 
        so it can be restored at the end of the SDN domain */
    bit<16> original_ether_type;
}

/* this header is inserted after by each node in the INT domeain,
    starting from the ingress node.
 */
header int_md_t {
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
    bit<16> hdr_checksum;
    bit<32> src_ip;
    bit<32> dst_ip;
}

header l4_ports_t {
    bit<16> src_port;
    bit<16> dst_port;
}

struct metadata {
    bit<8> remaining_switches; // Number of switches left to process
}


struct headers {
    ethernet_t                     ethernet;
    int_main_t                     int_main;
    int_md_t                       int_md;
    int_inc_t                      int_inc;
    ipv4_t                         ipv4;
    l4_ports_t                     l4_ports;
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
            ETHERTYPE_INT_MD: parse_int_main;
            ETHERTYPE_INT_CTRL: parse_inc;
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_int_main {
        buffer.extract(parsed_hdr.int_main);
        transition parse_int_md;
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
        transition accept;
        }

}

control ingress(inout headers hdr,
                inout metadata meta,
                in    psa_ingress_input_metadata_t  istd,
                inout psa_ingress_output_metadata_t ostd)
{
    // Declare a register to hold the output port for INT packets
    // This register will be indexed by the int_label in the INT header
    // and will store the egress port for each label.
    // The register size is 256 entries, each entry is a 9-bit port number
    // (assuming a maximum of 512 ports in the switch).
    // The register is initialized to 0, meaning no port is assigned by default.
    // If a packet with an int_label is received and the corresponding entry
    // in the register is 0, the packet will be dropped.
    


    // register to hold the output port for each label
    Register<bit<32>, bit<32>> (32w512) rg_output_port;


    //counters to count the number of packets processed
    DirectCounter<bit<64>>(PSA_CounterType_t.PACKETS) counter_label_handler;

    DirectCounter<bit<64>>(PSA_CounterType_t.PACKETS) counter_label_set;

    action ac_drop() {
        ostd.drop = true;
    }


    // When a label is match, this reads the relevant register index
    // and sets the egress port in the standard_metadata.
    action ac_label_forward_with_int(label_port_register_index_t register_index) {
        ostd.egress_port = (PortId_t) rg_output_port.read( register_index);
        hdr.int_md.setValid();
        hdr.int_md.latency = (bit<64>) istd.ingress_timestamp;
    }

    action ac_label_forward_without_int(label_port_register_index_t register_index) {
        ostd.egress_port = (PortId_t) rg_output_port.read( register_index);
    }

    // this action is used to change the egress port that is saved in the
    // register, this is applied for packets that are coming from 
    // dataplane active collector
    action ac_set_port() {
        bit<32> register_index = hdr.int_inc.register_index;
        bit<32> output_port = hdr.int_inc.output_port;
        rg_output_port.write( register_index, output_port );
    }

    action ac_label_pop(label_port_register_index_t register_index) {
        ostd.egress_port = (PortId_t) rg_output_port.read(register_index);
        hdr.ethernet.ether_type = hdr.int_main.original_ether_type;
        hdr.int_main.setInvalid();
        hdr.int_md.setInvalid();
    }

    // Table to forward packets based on the INT label
    // Matches the label to a register index that holds the egress port
    table tb_label_handler {
        key = {            
            hdr.int_main.int_label: exact;
        }
        actions = {
            ac_label_forward_with_int;
            ac_label_forward_without_int;
            ac_label_pop;
            ac_set_port;
            NoAction;
        }
        default_action = NoAction;
        psa_direct_counter = counter_label_handler;
        size = 1024;

    }
    
    action ac_label_push(bit<16> label) {
        /*
        add and activate the int_main header,
        */
        hdr.int_main.setValid();
        hdr.int_main.int_label = label;
        hdr.int_main.original_ether_type = hdr.ethernet.ether_type;
        hdr.ethernet.ether_type = ETHERTYPE_INT_MD;

        /* add the first timestamp */
        hdr.int_md.setValid();
        hdr.int_md.latency = (bit<64>) istd.ingress_timestamp;
    }

    // Table to set the label based on the destination IP and L4 port
    // This table is used to assign a label to packets that are entering the INT SDN
    table tb_label_set {
        key = {            
            hdr.ipv4.dst_ip: lpm;
            hdr.l4_ports.dst_port: ternary;
            
        }
        actions = {
            ac_label_push;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
        psa_direct_counter = counter_label_set;
    }

    apply {
        // Check if this is an ingress packet arriving at the INT SDN domain
        if (hdr.ipv4.isValid() && !hdr.int_main.isValid() ){
            // Packet is coming from outside the INT SDN domain
            // Set the label based on the destination IP address
            // and the L4 port number.
            tb_label_set.apply();
        } 
        
        // Check if this is an INT packet with a label
        if ( hdr.int_main.isValid() || hdr.int_inc.isValid() ) {
            tb_label_handler.apply();
        }

    }
}


control egress(inout headers hdr,
               inout metadata meta,
               in    psa_egress_input_metadata_t  istd,
               inout psa_egress_output_metadata_t ostd)
{
    apply { 

        if ( hdr.int_main.isValid() ){
            hdr.int_md.latency = (bit<64>) istd.egress_timestamp - hdr.int_md.latency;
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