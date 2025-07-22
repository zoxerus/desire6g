/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/
const bit<16> ETHERTYPE_TPID   = 0x8100;
const bit<16> ETHERTYPE_IPV4   = 0x0800;
const bit<16> ETHERTYPE_IPV6   = 0x86DD;
const bit<16> ETHERTYPE_TO_CPU = 0xBF01;
const bit<16> ETHERTYPE_D6GINT = 0xDF01;
const bit<16> ETHERTYPE_D6GMAIN = 0xD6D6;

/*
 * Portable Types for PortId and MirrorID that do not depend on the target
 */
typedef bit<16> P_PortId_t;
typedef bit<16> P_MirrorId_t;
typedef bit<8>  P_QueueId_t;
 
#if __TARGET_TOFINO__ == 1
typedef bit<7> PortId_Pad_t;
typedef bit<6> MirrorId_Pad_t;
typedef bit<3> QueueId_Pad_t;
#define MIRROR_DEST_TABLE_SIZE 256
#elif __TARGET_TOFINO__ == 2
typedef bit<7> PortId_Pad_t;
typedef bit<8> MirrorId_Pad_t;
typedef bit<1> QueueId_Pad_t;
#define MIRROR_DEST_TABLE_SIZE 256
#else
#error Unsupported Tofino target
#endif

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress can differ */

/* Standard ethernet header */
header ethernet_h {
    bit<48>   dst_addr;
    bit<48>   src_addr;
    bit<16>   ether_type;
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
    bit<48> t1;
    bit<48> t2;
    bit<48> t3;
}


/*** Internal Headers Used with Mirroring ***/
typedef bit<4> header_type_t;
typedef bit<4> header_info_t;

const header_type_t HEADER_TYPE_BRIDGE         = 0xB;
const header_type_t HEADER_TYPE_MIRROR_INGRESS = 0xC;
const header_type_t HEADER_TYPE_MIRROR_EGRESS  = 0xD;
const header_type_t HEADER_TYPE_RESUBMIT       = 0xA;

/*
 * This is a common "preamble" header that must be present in all internal
 * headers. The only time you do not need it is when you know that you are
 * not going to have more than one internal header type ever
 */

#define INTERNAL_HEADER         \
    header_type_t header_type;  \
    header_info_t header_info


header inthdr_h {
    INTERNAL_HEADER;
}

/* Bridged metadata */
header bridge_h {
    INTERNAL_HEADER;
#ifdef FLEXIBLE_HEADERS
    @flexible bit<4>    d6gint_count;
#else
    @padding bit<4> pad0;   bit<4>  d6gint_count;
#endif
}

/* mirroring types */
const MirrorType_t ING_PORT_MIRROR = 3;
const MirrorType_t EGR_PORT_MIRROR = 5;


/* Bridged metadata for ingress mirrored packets */
header ing_port_mirror_h {
    INTERNAL_HEADER;

#ifdef FLEXIBLE_HEADERS
    @flexible  MirrorId_t  mirror_session;

#else
    @padding MirrorId_Pad_t  pad0;  MirrorId_t  mirror_session;        /*  2 */
#endif
}


/* Bridged metadata for egress mirrored packets */
header egr_port_mirror_h {
    INTERNAL_HEADER;                                                  /* 1 */

#ifdef FLEXIBLE_HEADERS
    @flexible  MirrorId_t  mirror_session;
    @flexible bit<48> t1;
    @flexible bit<48> t2;
#else
    @padding MirrorId_Pad_t  pad0;  MirrorId_t  mirror_session;        /*  2 */
                                    bit<48>     t1;
                                    bit<48>     t2;

#endif
}



/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_ingress_headers_t {
    bridge_h           bridge;
    ethernet_h         ethernet;
    d6gmain_t          d6gmain;
    d6gint_t           d6gint;
}

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
    header_type_t  mirror_header_type;
    header_info_t  mirror_header_info;
    MirrorId_t     mirror_session;
}

    /***********************  P A R S E R  **************************/
parser IngressParser(packet_in        pkt,
    /* User */
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
     state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition init_bridge_and_meta;
    }

    state init_bridge_and_meta {
        meta = { 0, 0, 0 };

        hdr.bridge.setValid();
        hdr.bridge.header_type  = HEADER_TYPE_BRIDGE;
        hdr.bridge.header_info  = 0;
        
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_D6GMAIN: parse_d6gmain;
            default: accept;
        }
    }

    state parse_d6gmain{
        pkt.extract(hdr.d6gmain);
        transition select(hdr.d6gmain.nextHeader){
            ETHERTYPE_D6GINT: parse_d6gint;
            default: accept;
        }
    }

    state parse_d6gint{
        pkt.extract(hdr.d6gint);
        transition accept;
    }

}

    /***************** M A T C H - A C T I O N  *********************/

control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    /* d6gint_count: where to insert the timestamp, 
        either t1, t2, or t3.
        this is later  used in the egress for the insertion of the timestamp */
    action do_d6gint_instruct_and_forward(PortId_t port, bit<4> d6gint_count) {
        hdr.bridge.d6gint_count = d6gint_count;
        ig_tm_md.ucast_egress_port = port;
    }

    action do_d6g_forward(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }

    /* This table is used to check where to insert the timestamp */
    table tb_d6gint_handler {
        key = {
            hdr.d6gmain.serviceId : ternary;
            hdr.d6gmain.nextNF    : exact;
        }
        actions = {
            do_d6gint_instruct_and_forward; do_d6g_forward; drop; NoAction; 
        }
        size = 512;
        default_action = drop();
    }

    apply {
        /* Check if we need to insert d6g telemetry, and decide where to insert it 
            the insertion is done later in the egress pipeline */
        if (!tb_d6gint_handler.apply().hit ) { drop(); }
    }

}

   /*********************  D E P A R S E R  ************************/

#ifdef FLEXIBLE_HEADERS
#define PAD(field)  field
#else
#define PAD(field)  0, field
#endif


control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    apply {        
        /* Deparse the regular packet with bridge metadata header prepended */
        pkt.emit(hdr);
    }
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

/* need to parse the same headers for the insertion of the INT */
struct my_egress_headers_t {
    ethernet_h         ethernet;
    d6gmain_t          d6gmain;
    d6gint_t           d6gint;
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
    inthdr_h           inthdr;
    bridge_h           bridge;
    MirrorId_t         mirror_session;
    bool               ing_mirrored;
    bool               egr_mirrored;
    ing_port_mirror_h  ing_port_mirror;
    egr_port_mirror_h  egr_port_mirror;
    header_type_t      mirror_header_type;
    header_info_t      mirror_header_info;
    MirrorId_t         egr_mirror_session;
    bit<48>             t1;
    bit<48>             t2;
}

    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        meta.mirror_session        = 0;
        meta.ing_mirrored          = false;
        meta.egr_mirrored          = false;
        meta.mirror_header_type    = 0;
        meta.mirror_header_info    = 0;
        meta.egr_mirror_session    = 0;
        meta.t1                    = 0;
        meta.t2                    = 0;
 

        pkt.extract(eg_intr_md);
        meta.inthdr = pkt.lookahead<inthdr_h>();
           
        transition select(meta.inthdr.header_type, meta.inthdr.header_info) {
            ( HEADER_TYPE_BRIDGE,         _ ) :
                           parse_bridge;
            ( HEADER_TYPE_MIRROR_INGRESS, (header_info_t)ING_PORT_MIRROR ):
                           parse_ing_port_mirror;
            ( HEADER_TYPE_MIRROR_EGRESS,  (header_info_t)EGR_PORT_MIRROR ):
                           parse_egr_port_mirror;
            default : reject;
        }
    }

    state parse_bridge {
        pkt.extract(meta.bridge);
        transition parse_ethernet;
    }

    state parse_ing_port_mirror {
        pkt.extract(meta.ing_port_mirror);
        meta.ing_mirrored   = true;
        meta.mirror_session = meta.ing_port_mirror.mirror_session;
        transition parse_ethernet;
    }
    
    state parse_egr_port_mirror {
        pkt.extract(meta.egr_port_mirror);
        meta.egr_mirrored   = true;
        meta.mirror_session = meta.egr_port_mirror.mirror_session;
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_D6GMAIN: parse_d6gmain;
            default: accept;
        }
    }

    state parse_d6gmain{
        pkt.extract(hdr.d6gmain);
        transition select(hdr.d6gmain.nextHeader){
            ETHERTYPE_D6GINT: parse_d6gint;
            default: accept;
        }
    }

    state parse_d6gint{
        pkt.extract(hdr.d6gint);
        transition accept;
    }
}




    /***************** M A T C H - A C T I O N  *********************/
control Egress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    action do_d6gint_update_t2() {
        hdr.d6gint.t2 = (bit<48>) eg_prsr_md.global_tstamp;
    }

    action do_d6gint_update_t3_and_send_report(MirrorId_t mirror_session){
        hdr.d6gmain.nextHeader = hdr.d6gint.next_header;
        meta.t1 = hdr.d6gint.t1;
        meta.t2 = hdr.d6gint.t2;

        hdr.d6gint.setInvalid();
        
        eg_dprsr_md.mirror_type = EGR_PORT_MIRROR;

#ifndef P4C_3876_FIXED
        #if __TARGET_TOFINO__ > 1
        eg_dprsr_md.mirror_io_select = 1;
        #endif
#endif
        meta.mirror_header_type     = HEADER_TYPE_MIRROR_EGRESS;
        meta.mirror_header_info     = (header_info_t) EGR_PORT_MIRROR;
        meta.egr_mirror_session     = mirror_session;
    }
    
    table tb_d6gint_update {
        key = {
            meta.bridge.d6gint_count: exact;
        }

        actions = {
            do_d6gint_update_t2; do_d6gint_update_t3_and_send_report; NoAction;
        }
        default_action = NoAction;
        size = 1024;
    }


    action do_send_report_to_collector(bit<48> src_mac, bit<48> dst_mac){
        hdr.ethernet.src_addr = src_mac;
        hdr.ethernet.dst_addr = dst_mac;
        hdr.d6gint.setValid();
        hdr.d6gmain.nextHeader = ETHERTYPE_D6GINT;
        hdr.d6gint.next_header = 0;
        hdr.d6gint.t1 = meta.egr_port_mirror.t1;
        hdr.d6gint.t2 = meta.egr_port_mirror.t2;
        hdr.d6gint.t3 = eg_prsr_md.global_tstamp;
    }

    table tb_handle_mirrored_packets {
        key = {
            meta.mirror_session     : exact;
            }
        actions = { do_send_report_to_collector; NoAction ;}
        // counters = cn_mirrored_packets;
        default_action = NoAction;
        size = 1024;
    }


    apply {
        if (hdr.d6gint.isValid()) {
            tb_d6gint_update.apply();
        } else if (meta.ing_port_mirror.isValid() ||
                   meta.egr_port_mirror.isValid()) { 
            tb_handle_mirrored_packets.apply();
        }
    }
}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md,
    in    egress_intrinsic_metadata_t               eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t   eg_prsr_md)
{
    Mirror() egr_port_mirror;
    apply {
        /* 
         * If there is a mirror request, create a clone. 
         * Note: Mirror() externs emits the provided header, but also
         * appends the ORIGINAL ingress packet after those
         */
        if (eg_dprsr_md.mirror_type == EGR_PORT_MIRROR) {
            egr_port_mirror.emit<egr_port_mirror_h>(
                meta.egr_mirror_session,
                {
                    meta.mirror_header_type,
                    meta.mirror_header_info,
                    PAD(meta.egr_mirror_session),
                    meta.t1,
                    meta.t2
                });

        }
                
        pkt.emit(hdr);
    }
}


/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
