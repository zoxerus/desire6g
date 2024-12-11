/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>


/*** PACKET INSTANCE DEFINITIONS ***/
#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_COALESCED 3
#define PKT_INSTANCE_TYPE_INGRESS_RECIRC 4
#define PKT_INSTANCE_TYPE_REPLICATION 5
#define PKT_INSTANCE_TYPE_RESUBMIT 6


/*** ETHERTYPE DEFINITIONS ***/
#define ETHER_TYPE_REPORT 1501
#define ETHER_TYPE_TRIGGER 1502
#define ETHER_TYPE_IPV4 0X0800

/*** IPV4 PROTOCOL IDENTIFIERS ***/
#define IP_PROTO_UDP 0X11
#define IP_PROTO_TCP 0X06


#define MAX_NODES 5

// Field_LISTS
#define FL_INT_TRIGGER 10

// Clone Sessions
#define CS_INT_TRIGGER 128

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<16> switchID_t;
typedef bit<8>  backupPort_t;
typedef bit<9>  egressSpec_t;
typedef bit<24> qLen_t;
typedef bit<32> qDelay_t;
typedef bit<16> reportCount_t;

header hdr_ethernet_t {
    bit<48>     dst_mac;
    bit<48>     src_mac;
    bit<16>     ether_type;
}

header hdr_ipv4_t {
    bit<4>      version;
    bit<4>      ihl;
    bit<8>      diffserv;
    bit<16>     total_len;
    bit<16>     identification;
    bit<3>      flags;
    bit<13>     frag_offset;
    bit<8>      ttl;
    bit<8>      protocol;
    bit<16>     hdr_checksum;
    bit<32>     src_ip;
    bit<32>     dst_ip;
}

header hdr_udp_t {
    bit<16>     src_port;
    bit<16>     dst_port;
    bit<16>     length;
    bit<16>     checksum;
}

/*
this is the report header, to be received from the sink node */
header hdr_int_report_t {
    bit<8>      init_ttl;
    switchID_t  switch_id;
    bit<8>      hop_num;
	/* 
    extra information for trust
	switch with lowest trust level */
	switchID_t  trust_swid;
	bit<4>      trust_level;
    
    /*** TBD ****/
    bit<16>      count;  
    bit<12>      padding;
}

/* the report header that is sent by the switches 
    in the network */
header hdr_q_report_t {
	switchID_t  congestion_swid;
    qLen_t      q_length;
    qDelay_t    q_delay;  
}

/* 
a header to send the trigger message back to the network,
for triggering the inband reroute at the congested switch. */
header hdr_int_trigger_t {
    switchID_t      switch_id;
    backupPort_t    bakup_port;
}

struct metadata {
    /* used in parser to keep track of parsed reports */
    reportCount_t           remaining_q_reports;

    /* used as a key for table inband_reroute */
    bit<MAX_NODES>          congestion_bitmap;

    /* Fields to be preserved when cloning */
    @field_list(FL_INT_TRIGGER)
    switchID_t      congested_swid;
    @field_list(FL_INT_TRIGGER)
    backupPort_t    backup_port;
}

/* includes all headers used by this program */
struct headers {
    hdr_ethernet_t              ethernet;
    hdr_int_report_t            int_report;
    hdr_q_report_t[MAX_NODES]   q_reports;
    hdr_int_trigger_t           int_trigger;
    hdr_ipv4_t                  ipv4;
}


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet_header;
    }

    state parse_ethernet_header {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHER_TYPE_IPV4   :     parse_ipv4_header;
            ETHER_TYPE_REPORT :     parse_int_report_header;
            default: accept;
        }
    }

    state parse_ipv4_header {
        packet.extract(hdr.ipv4);
        transition accept;
    }

    state parse_int_report_header {
        log_msg("parsed INT report");
        packet.extract(hdr.int_report);
        meta.remaining_q_reports = hdr.int_report.count;
        transition select(meta.remaining_q_reports){
            0: accept;
            default: parse_next_q_report;
        }
    }

    state parse_next_q_report {
        packet.extract(hdr.q_reports.next);
        meta.remaining_q_reports = meta.remaining_q_reports - 1;
        transition select(meta.remaining_q_reports){
            0: accept;
            default: parse_next_q_report;
        }
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  
        // empty, skip verification.
    }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    // a counter for counting how many trigers have been sent
    counter ( 1, CounterType.packets) trigger_counter;
    
    counter ( 1, CounterType.packets) normal_counter;

    // counter for total packets received
    direct_counter (CounterType.packets) total_counter; 

/********************* IPv4 Forwarding *********************
************************************************************/
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(bit<48> dst_mac, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.src_mac = hdr.ethernet.dst_mac;
        hdr.ethernet.dst_mac = dst_mac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dst_ip: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

/******************* INT Trigger Handling *******************
************************************************************/
    action trigger_reroute (egressSpec_t eif, bit<16> sw_id, backupPort_t bport) {
        trigger_counter.count(0);
        standard_metadata.egress_spec = eif;
        meta.congested_swid = sw_id;
        meta.backup_port = bport;        
        clone_preserving_field_list(CloneType.I2E, CS_INT_TRIGGER, FL_INT_TRIGGER);
    }

    action normal_forward(egressSpec_t eif){
        normal_counter.count(0);
        standard_metadata.egress_spec = eif;
    }

    table inband_reroute{
        key = {
            meta.congestion_bitmap: ternary;
        }
        actions = {
            trigger_reroute;
            normal_forward; 
        }
        counters = total_counter; 
    }

/******************* Detect Congestion *******************
************************************************************/
    action check_switch0( qLen_t t0 ){
        meta.congestion_bitmap[0:0] = (bit)(t0 < hdr.q_reports[0].q_length );
        reg_congestion_swid.write(0, hdr.q_reports[0].congestion_swid);
    }
    
    action check_switches0to1( qLen_t t0, qLen_t t1 ){
        check_switch0(t0);
        meta.congestion_bitmap[1:1] = (bit)(t1 < hdr.q_reports[1].q_length );
        reg_congestion_swid.write(1, hdr.q_reports[1].congestion_swid);       
    }

    action check_switches0to2( qLen_t t0, qLen_t t1, qLen_t t2 ){
        check_switches0to1(t0,t1);
        meta.congestion_bitmap[2:2] = (bit)(t2 < hdr.q_reports[2].q_length );
        reg_congestion_swid.write(2, hdr.q_reports[2].congestion_swid);        
    }

    action check_switches0to3( qLen_t t0, qLen_t t1, qLen_t t2, qLen_t t3 ){
        check_switches0to2(t0, t1, t2);
        meta.congestion_bitmap[3:3] = (bit)(t3 < hdr.q_reports[3].q_length );
        reg_congestion_swid.write(3, hdr.q_reports[3].congestion_swid);
    }

    action check_switches0to4( qLen_t t0, qLen_t t1, qLen_t t2, qLen_t t3, qLen_t t4){
        check_switches0to3(t0, t1, t2, t3);
        meta.congestion_bitmap[4:4] = (bit)(t4 < hdr.q_reports[4].q_length );
        reg_congestion_swid.write(4, hdr.q_reports[4].congestion_swid);

    }

    table congestion_detection{
        key = {
            hdr.int_report.count         :  exact;
        } 

        actions = {
            NoAction;
            check_switch0;
            check_switches0to1;
            check_switches0to2;
            check_switches0to3;
            check_switches0to4;
        }

        default_action = NoAction();
    }

    apply {

        if (hdr.int_report.isValid() ) {
            
            if ( congestion_detection.apply().hit){

                inband_reroute.apply();
            }
            
        }

        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}


/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {


    apply {

        if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_INGRESS_CLONE){
            hdr.int_trigger.setValid();
            hdr.ethernet.ether_type = ETHER_TYPE_TRIGGER;
            hdr.int_trigger.switch_id = meta.congested_swid;

            hdr.int_trigger.bakup_port = meta.backup_port;
            hdr.int_report.setInvalid();
            hdr.q_reports[0].setInvalid();
            hdr.q_reports[1].setInvalid();
            hdr.q_reports[2].setInvalid();
            hdr.q_reports[3].setInvalid();
            hdr.q_reports[4].setInvalid();
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
              hdr.ipv4.diffserv,
              hdr.ipv4.total_len,
              hdr.ipv4.identification,
              //hdr.ipv4.intflag,
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
        packet.emit(hdr.int_report);
        packet.emit(hdr.q_reports);
        packet.emit(hdr.int_trigger);
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
