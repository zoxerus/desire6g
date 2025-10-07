/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> ETHERTYPE_D6G_MAIN     =  0xd6d6;
const bit<16> ETHERTYPE_IPV4   = 0x0800;

const bit<8> L4PROTO_UDP = 0x11;
const bit<8> L4PROTO_TCP = 0x06;

const bit<16> ETHERTYPE_D6GINT = 0xDF01;
const bit<16> ETHERTYPE_D6GMAIN = 0xD6D6;



/* Type defines */
typedef bit<9> PortId_t;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_t {
    bit<48>   dst_mac;
    bit<48>   src_mac;
    bit<16>   ether_type;
}

header d6gint_t {
    bit<16> next_header;
    bit<48> t1;
    bit<48> t2;
    bit<48> t3;
}

header d6g_main_t {
   bit<16> serviceId; 	// Network service or slice
   bit<16> locationId; 	// UE location if applicable
   bit<1>  hhFlag;
   bit<7>  _reserved;
   bit<16> nextNF;	// next network function in the service graph
   bit<16> nextHeader;	// identifier of the next header elements
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    dscp;
    bit<2>    ecn;
    bit<16>   total_len;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   frag_offset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdr_checksum;
    bit<32>   src_ip;
    bit<32>   dst_ip;
}

header l4ports_t {
    bit<16> src_port;
    bit<16> dst_port;
}

struct metadata {
}

struct headers {
    ethernet_t         ethernet;
    d6g_main_t         d6g_main;
    d6gint_t           d6gint;
    ipv4_t             ipv4;
    l4ports_t          l4ports;
}


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_D6G_MAIN    : parse_d6g_main;
            ETHERTYPE_IPV4        : parse_ipv4;
            default: accept;
        }
    }

    state parse_d6g_main {
        packet.extract(hdr.d6g_main);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            L4PROTO_UDP   : parse_l4ports;
            L4PROTO_TCP   : parse_l4ports;
            default       : accept;
        }
    }

    state parse_l4ports {
        packet.extract(hdr.l4ports);
        transition accept;
    }

}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}





/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
        exit;
    }

    action push_d6g_headers(bit<9> port, bit<16> serviceId, bit<16> nextNF ) {
        hdr.d6g_main.setValid();
        hdr.d6g_main.nextHeader = ETHERTYPE_D6GINT;
        hdr.d6g_main.serviceId = serviceId;
        hdr.d6g_main.nextNF = nextNF;
        hdr.d6g_main.hhFlag = 0;
        hdr.d6g_main.locationId = 0;
        hdr.d6g_main._reserved = 0;
        hdr.d6gint.setValid();
        hdr.d6gint.next_header = hdr.ethernet.ether_type;
        hdr.d6gint.t1 = standard_metadata.ingress_global_timestamp;
        hdr.d6gint.t2 = 0;
        hdr.d6gint.t3 = 0;
        hdr.ethernet.ether_type = ETHERTYPE_D6GMAIN;
        standard_metadata.egress_spec = port;
    }

    action pop_d6g_headers(bit<9> port) {
        hdr.ethernet.ether_type = hdr.d6g_main.nextHeader;
        hdr.d6g_main.setInvalid();
        standard_metadata.egress_spec = port; 
    }


    table tb_handle_tha_packets {
        key = {            
            standard_metadata.ingress_port: exact;
        }

        actions = {
            push_d6g_headers;
            pop_d6g_headers;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
/****************************************************************/


    apply {
        tb_handle_tha_packets.apply();
    } // END OF APPLY BLOCK
    
} // END OF INGRESS BLOCK


/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
        apply {

        }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.dscp,
              hdr.ipv4.ecn,
              hdr.ipv4.total_len,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.frag_offset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.src_ip,
              hdr.ipv4.dst_ip },
            hdr.ipv4.hdr_checksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
