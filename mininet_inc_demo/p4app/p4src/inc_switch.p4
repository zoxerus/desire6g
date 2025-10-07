/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/* Packet Instance Types */
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_NORMAL        = 0;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE = 1;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE  = 2;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_COALESCED     = 3;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_RECIRC        = 4;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_REPLICATION   = 5;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_RESUBMIT      = 6;

/* Macros for checking the instance type of the packets */
#define IS_NORMAL(smeta)(smeta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_NORMAL)
#define IS_RESUBMITTED(smeta)(smeta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_RESUBMIT)
#define IS_RECIRCULATED(smeta)(smeta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_RECIRC)
#define IS_I2E_CLONE(smeta) (smeta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE)
#define IS_E2E_CLONE(smeta) (smeta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE)
#define IS_REPLICATED(smeta)(smeta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_REPLICATION)

/* FieldLists */
#define FIELD_LIST_1 1

/* EtherType defines */
const bit<16> ETHERTYPE_IPV4    = 0x800 ;
const bit<16> ETHERTYPE_SDN_INT = 0x88b5;
const bit<16> ETHERTYPE_SDN_RPT = 0x88b7;
const bit<16> ETHERTYPE_SDN_INC = 0x88b6;
const bit<16> ETHERTYPE_D6G_MAIN     =  0xd6d6;


/* IP next protocol defines */
const bit<8>  IP_PROTO_UDP = 0x11  ;
const bit<8>  IP_PROTO_TCP = 0x06  ;

/* Other constants */
const bit<32> REPORT_MIRROR_SESSION_ID = 500;
const bit<32> REPORT_TRUNCATE_LENGTH = 24;

/* Constants for defining the egress processing */
const bit<8> EP_SKIP = 0;
const bit<8> EP_INT_NORMAL = 1;
const bit<8> EP_INT_CLONED = 2;

/********************************************************/
/* Macros for checking which egress processing to apply */
/********************************************************/

/* this skips the egress processing entirely */
#define APPLY_EP_SKIP(meta)(meta.egress_processing == EP_SKIP)

/* this applies to normal packets, where hop latency is inserted and packet is forwarded
    to the next SDN hop */
#define APPLY_EP_INT_NORMAL(meta)( meta.egress_processing == EP_INT_NORMAL)

/* this applies to INT packets at the end of the SDN INT domain, where at the egress there will be to packets,
    the cloned packet is the report and is sent to the DPAC after updating hop latency, while the second packets,
    is the normal packet, and the INT header needs to be removed before forwarding the packet outside the SDN INT domain */
#define APPLY_EP_INT_REPORT(meta, smeta)(meta.egress_processing == EP_INT_CLONED && IS_I2E_CLONE(smeta) )
#define APPLY_EP_INT_POP(meta, smeta)( meta.egress_processing == EP_INT_CLONED && IS_NORMAL(smeta) )

/****************************************************************/

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

header d6g_main_t {
   bit<16> serviceId; 	// Network service or slice
   bit<16> locationId; 	// UE location if applicable
   bit<1>  hhFlag;
   bit<7>  _reserved;
   bit<16> nextNF;	// next network function in the service graph
   bit<16> nextHeader;	// identifier of the next header elements
}

header sdn_int_t {
    /* the sdn_label is local to the sdn domain
     and is different from the d6g label */
    bit<16> sdn_label;
    bit<16> original_ether_type;
    /* this is combined hop latency fro the sdn domain,
     it is different from the timestamps taken for the d6g domain*/
    bit<48> sdn_latency;
}

/*  */
header sdn_inc_t {
    bit<16> sdn_label;
    bit<9> register_index;
    bit<3> _reserved1;
    bit<9> output_port;
    bit<3> _reserved2;
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



struct metadata {
    @field_list(FIELD_LIST_1)    
    bit<48> latency;

    @field_list(FIELD_LIST_1)
    bit<8>   egress_processing;
}

struct headers {
    ethernet_t         ethernet;
    sdn_int_t          sdn_int;
    sdn_inc_t          sdn_inc;
    d6g_main_t         d6g_main;
    ipv4_t             ipv4;
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
            ETHERTYPE_SDN_INT: parse_sdn_int;
            ETHERTYPE_SDN_INC: parse_sdn_inc;
            ETHERTYPE_D6G_MAIN    : parse_d6g_main;
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_sdn_int {
        packet.extract(hdr.sdn_int);
        transition select(hdr.sdn_int.original_ether_type) {
            ETHERTYPE_D6G_MAIN    : parse_d6g_main;
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_sdn_inc {
        packet.extract(hdr.sdn_inc);
        transition accept;
    }

    state parse_d6g_main {
        packet.extract(hdr.d6g_main);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
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

    // Declare a register to hold the output port for INT packets
    // This register will be indexed by the int_label in the INT header
    // and will store the egress port for each label.
    // The register size is 256 entries, each entry is a 9-bit port number
    // (assuming a maximum of 512 ports in the switch).
    // The register is initialized to 0, meaning no port is assigned by default.
    // If a packet with an int_label is received and the corresponding entry
    // in the register is 0, the packet will be dropped.

    /* register array used for selecting output port form sdn_int label */
    register<bit<9>> (512) rg_output_port;

    // a counter to count the number of packets processed
    direct_counter(CounterType.packets) ct_int_added_from_ipv4 ;
    direct_counter(CounterType.packets) ct_int_added_from_d6gmain ;
    direct_counter(CounterType.packets) ct_int_handled ;
    direct_counter(CounterType.packets) ct_inc_handled;

    action drop() {
        mark_to_drop(standard_metadata);
        exit;
    }

    action ac_send_to_port(bit<9> port_id){
        standard_metadata.egress_spec = port_id;
    }

/******************************************************************/
    action ac_sdn_int_push(bit<16> label) {
        hdr.sdn_int.setValid();
        hdr.sdn_int.sdn_label = label;
        hdr.sdn_int.original_ether_type = hdr.ethernet.ether_type;

        hdr.ethernet.ether_type = ETHERTYPE_SDN_INT;
    }

    table tb_add_sdn_int_from_ipv4 {
        key = {            
            hdr.ipv4.dst_ip: lpm;
        }
        actions = {
            ac_sdn_int_push;
            ac_send_to_port;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
        counters = ct_int_added_from_ipv4;
    }

    table tb_add_sdn_int_from_d6gmain {
        key = {            
            hdr.d6g_main.nextNF: exact;
        }
        actions = {
            ac_sdn_int_push;
            ac_send_to_port;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
        counters = ct_int_added_from_d6gmain;
    }


/**********************************************************************/
    action ac_sdn_int_handle (bit<32> register_index){
        hdr.sdn_int.sdn_latency = standard_metadata.ingress_global_timestamp - hdr.sdn_int.sdn_latency;
        rg_output_port.read(standard_metadata.egress_spec, register_index);
        meta.egress_processing = EP_INT_NORMAL;
    }


    action ac_sdn_int_pop( bit<32> clone_session, bit<32> register_index ) {
        hdr.sdn_int.sdn_latency = standard_metadata.ingress_global_timestamp - hdr.sdn_int.sdn_latency; 
        rg_output_port.read(standard_metadata.egress_spec, register_index);
        meta.egress_processing = EP_INT_CLONED;
        clone_preserving_field_list(CloneType.I2E, clone_session, FIELD_LIST_1);
    }

    table tb_sdn_int_handler {
        key = {            
            hdr.sdn_int.sdn_label: exact;
        }
        actions = {
            ac_sdn_int_handle;
            ac_sdn_int_pop;
            ac_send_to_port;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
        counters = ct_int_handled;
    }

/****************************************************************/
    action ac_sdn_inc_update_register( ){
        rg_output_port.write( (bit<32>) hdr.sdn_inc.register_index, hdr.sdn_inc.output_port);
    }

    action ac_sdn_inc_forward(bit<32> register_index){
        rg_output_port.read(standard_metadata.egress_spec, register_index);
    }


    table tb_handle_inc {
        key = {            
            hdr.sdn_inc.sdn_label: exact;
        }
        actions = {
            ac_sdn_inc_update_register;
            ac_sdn_inc_forward;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
        counters = ct_inc_handled;
    }
/****************************************************************/


    apply {
        /* If there is not an SDN_INT header theen Apply the SDN INT,
             either based on the serviceId of the d6g_main header,
                or based on the destination IP address;
         */
        if ( hdr.d6g_main.isValid() ){
            tb_add_sdn_int_from_d6gmain.apply();
        } else if ( hdr.ipv4.isValid() ){
            tb_add_sdn_int_from_ipv4.apply();
        } else if ( hdr.sdn_inc.isValid()  ){
            tb_handle_inc.apply();
        }
        
        /* if sdn_int header already exist or is inserted in steps above,
          then handle it! */
        if ( hdr.sdn_int.isValid() ) {
            tb_sdn_int_handler.apply();
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

            if ( APPLY_EP_SKIP(meta) ) exit; 

            else if (APPLY_EP_INT_NORMAL(meta) ){
                hdr.sdn_int.sdn_latency = 
                    standard_metadata.egress_global_timestamp - hdr.sdn_int.sdn_latency;
            } 
            
            else if ( APPLY_EP_INT_POP(meta, standard_metadata) ){
                hdr.ethernet.ether_type = hdr.sdn_int.original_ether_type;
                hdr.sdn_int.setInvalid();

                if ( hdr.d6g_main.isValid() ) {
                    hdr.d6g_main.nextNF = hdr.d6g_main.nextNF + 1 ; }
            } 
            
            else if ( APPLY_EP_INT_REPORT(meta, standard_metadata) ){
                hdr.sdn_int.sdn_latency = 
                    standard_metadata.egress_global_timestamp - hdr.sdn_int.sdn_latency;
                /* remove everything after the SDN INT header including payload */    
                truncate(REPORT_TRUNCATE_LENGTH);
            }
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
        packet.emit(hdr.sdn_int);
        packet.emit(hdr.sdn_inc);
        packet.emit(hdr.d6g_main);
        packet.emit(hdr.ipv4);
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
