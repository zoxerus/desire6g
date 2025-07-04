/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2

const bit<8>  UDP_PROTOCOL = 0x11  ;
const bit<8>  TCP_PROTOCOL = 0x06  ;
const bit<8>  IPV4_PROTOCOL_INT = 253;
const bit<16> TYPE_IPV4    = 0x800 ;

const bit<32> REPORT_MIRROR_SESSION_ID = 500;
const bit<6> IPv4_DSCP_INT = 6w31;   // indicates an INT header in the packet


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_t {
    bit<48>   dst_mac;
    bit<48>   src_mac;
    bit<16>   ether_type;
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

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length_;
    bit<16> checksum;
}

header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_num;
    bit<32> ack_num;
    bit<4>  data_offset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header sw_int_t {
    bit<8>  int_type;
    bit<8>  original_protocol;
    bit<64> delay_us_ran;
    bit<64> delay_us_pdp;
    bit<32> path_id;
    bit<64> paddding;
}
const bit<16> int_length_bytes = 30;


struct metadata {
    @field_list(25)
    bool   isIntSink;

    @field_list(25)
    bit<32> clone_session;

    @field_list(25)
    bit<8>  clone_index;
}

struct headers {
    ethernet_t         ethernet;
    ipv4_t             ipv4;
    udp_t              udp;
    tcp_t              tcp;
    sw_int_t           sw_int;
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
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IPV4_PROTOCOL_INT    : parse_int;
            default              : accept;
        }
    }

    state parse_int {
        packet.extract(hdr.sw_int);
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
    
    register<bit<64>> (3) rg_ran_delay;

    register<bit<64>> (3) rg_pdp_delay;

    register<bit<32>>  (3)  rg_report_counter;

       
    bit<32> report_count;

    action drop() {
        mark_to_drop(standard_metadata);
        exit;
    }

    apply {
        if (hdr.ipv4.isValid() && hdr.ipv4.protocol == IPV4_PROTOCOL_INT){
            bit<32> register_location = hdr.sw_int.path_id - 1;
            rg_report_counter.read(report_count, register_location );
            report_count = report_count + 1;

            bit<64> ran_delay;
            bit<64> pdp_delay;

            rg_ran_delay.read(ran_delay, register_location );
            rg_pdp_delay.read(pdp_delay, register_location );
            
            ran_delay = ran_delay + hdr.sw_int.delay_us_ran;
            pdp_delay = pdp_delay + hdr.sw_int.delay_us_pdp;
        
            if (report_count == 16 ){
                hdr.sw_int.int_type = 1;
                // hdr.sw_int.path_id = hdr.sw_int.path_id;

                hdr.sw_int.delay_us_ran = ran_delay >> 4; // divide by 16                
                hdr.sw_int.delay_us_pdp = pdp_delay >> 4; // divide by 16               

                rg_pdp_delay.write(register_location, 0 );
                rg_ran_delay.write(register_location, 0 );
                rg_report_counter.write(register_location, 0);
                
                hdr.ipv4.src_ip = 0x0a0a0a0a;
                hdr.ipv4.dst_ip = 0x0b0b0b0b;
                standard_metadata.egress_spec = 9w110;
            } else {
                rg_pdp_delay.write(register_location, pdp_delay );
                rg_ran_delay.write(register_location, ran_delay );
                rg_report_counter.write(register_location, report_count);
                mark_to_drop(standard_metadata);
            }
            

        }
    } // END OF APPLY BLOCK
    
} // END OF INGRESS BLOCK


/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
        apply{

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
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.sw_int);
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
