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
const bit<16> ETHERTYPE_CLOCK_SYNC = 0xBF02;
const bit<16> ETHERTYPE_CLOCK_UPDATE = 0xBF03;
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


typedef bit<48> D6G_Timestamp_t;


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
    D6G_Timestamp_t t1;
    D6G_Timestamp_t t2;
    D6G_Timestamp_t t3;
}

// header clock_update_h {
//     D6G_Timestamp_t propagation_delay;
// }

header clock_sync_h {
    bit<8> count;
    D6G_Timestamp_t t0;
    D6G_Timestamp_t t1;
    D6G_Timestamp_t t2;
    D6G_Timestamp_t t3;
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
    // @flexible bit<4>    d6gint_count;
#else
    // @padding bit<4> pad0;   bit<4>  d6gint_count;
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
    @flexible  D6G_Timestamp_t     t3;

#else
    @padding MirrorId_Pad_t  pad0;  MirrorId_t  mirror_session;        /*  2 */
                                    D6G_Timestamp_t     t3;
#endif
}


/* Bridged metadata for egress mirrored packets */
header egr_port_mirror_h {
    INTERNAL_HEADER;                                                  /* 1 */

#ifdef FLEXIBLE_HEADERS
    @flexible  MirrorId_t  mirror_session;
#else
    @padding MirrorId_Pad_t  pad0;  MirrorId_t  mirror_session;        /*  2 */

#endif
}



/************************************************************************* 
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/ 

    /***********************  H E A D E R S  ************************/ 

struct my_ingress_headers_t {
    bridge_h           bridge;
    ethernet_h         ethernet;
    // clock_update_h     clock_update;
    clock_sync_h       clock_sync;
    d6gmain_t          d6gmain;
    d6gint_t           d6gint;
}

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/ 

struct my_ingress_metadata_t {
    header_type_t  mirror_header_type;
    header_info_t  mirror_header_info;
    MirrorId_t     mirror_session;
    // D6G_Timestamp_t        reference_tstamp;
    // D6G_Timestamp_t        global_tstamp;
    // D6G_Timestamp_t        mac_tstamp;
    D6G_Timestamp_t        t3;
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
        meta = { 0, 0, 0, 0};

        hdr.bridge.setValid();
        hdr.bridge.header_type  = HEADER_TYPE_BRIDGE;
        hdr.bridge.header_info  = 0;
        
        // meta.mac_tstamp = ig_intr_md.ingress_mac_tstamp;

        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_D6GMAIN:          parse_d6gmain;
            ETHERTYPE_CLOCK_SYNC:       parse_clock_sync;
            // ETHERTYPE_CLOCK_UPDATE:     parse_clock_update;
            default:                    accept;
        }
    }

    state parse_clock_sync{
        pkt.extract(hdr.clock_sync);
        transition accept;
    }

    // state parse_clock_update{
    //     pkt.extract(hdr.clock_update);
    //     transition accept;
    // }


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



// #ifdef REG_READ_WRITE
// ssdf;

// #else /* Use RegisterAction */
// control GetRelativeTimestamp(
//     inout my_ingress_metadata_t meta,
//     inout my_ingress_headers_t  hdr
//     )()

// {
//     Register<D6G_Timestamp_t, bit<8>>(1) register_timestamp_reference;

//     RegisterAction<D6G_Timestamp_t, bit<8>, D6G_Timestamp_t>(register_timestamp_reference)
//     update_register = {
//         void apply(inout D6G_Timestamp_t register_data) {
//             {
//                 register_data = meta.reference_tstamp;
//             }
//         }
//     };
    
//     RegisterAction<D6G_Timestamp_t, bit<8>, D6G_Timestamp_t>(register_timestamp_reference)
//     read_register = {
//         void apply(inout D6G_Timestamp_t register_data, out D6G_Timestamp_t result) {
//             result = register_data;
//         }
//     };
        
//     apply {
//         if (hdr.clock_update.isValid()) {
//             meta.reference_tstamp = meta.mac_tstamp - hdr.clock_update.propagation_delay;
//             update_register.execute(8w0);
//             exit;
//         } else {
//             meta.reference_tstamp = read_register.execute(8w0);
//         }
//     }
// }
// #endif

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
    action skip_egress(){
        ig_tm_md.bypass_egress = 1;
        hdr.bridge.setInvalid();
    }


    action do_d6gint_update_t1(PortId_t port) {
        hdr.d6gint.t1 = ig_intr_md.ingress_mac_tstamp;
        ig_tm_md.ucast_egress_port = port;
        skip_egress();
    }
    action do_d6gint_update_t2(PortId_t port) {
        hdr.d6gint.t2 = ig_intr_md.ingress_mac_tstamp;
        ig_tm_md.ucast_egress_port = port;
        skip_egress();
    }

    action do_d6gint_update_t3_and_send_report(PortId_t port, MirrorId_t mirror_session){
        ig_tm_md.ucast_egress_port = port;
        meta.t3 = ig_intr_md.ingress_mac_tstamp;
        ig_dprsr_md.mirror_type = ING_PORT_MIRROR;
        hdr.d6gmain.nextHeader = hdr.d6gint.next_header;
        hdr.d6gint.setInvalid();

#ifndef P4C_3876_FIXED
        #if __TARGET_TOFINO__ > 1
        ig_dprsr_md.mirror_io_select = 1;
        #endif
#endif
        meta.mirror_header_type     = HEADER_TYPE_MIRROR_INGRESS;
        meta.mirror_header_info     = (header_info_t) ING_PORT_MIRROR;
        meta.mirror_session         = mirror_session;
    }
    
    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    action do_d6g_forward(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
        skip_egress();
    }

    /* This table is used to check where to insert the timestamp */
    table tb_d6gint_handler {
        key = {
            hdr.d6gmain.serviceId : ternary;
            hdr.d6gmain.nextNF    : exact;
        }
        actions = {
            do_d6gint_update_t1; do_d6gint_update_t2; do_d6gint_update_t3_and_send_report; do_d6g_forward; drop; NoAction; 
        }
        size = 512;
        default_action = drop();
    }

    action just_forward(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
        skip_egress();
    }

    action clock_sync_add_t0(PortId_t port){
        hdr.clock_sync.t0 = ig_intr_md.ingress_mac_tstamp;
        hdr.clock_sync.count = hdr.clock_sync.count + 1;
        just_forward(port);
    }

    action clock_sync_add_t1(PortId_t port){
        hdr.clock_sync.t1 = ig_intr_md.ingress_mac_tstamp;
        hdr.clock_sync.count = hdr.clock_sync.count + 1;
        just_forward(port);
    }

    action clock_sync_add_t2(PortId_t port){
        hdr.clock_sync.t2 = ig_intr_md.ingress_mac_tstamp;
        hdr.clock_sync.count = hdr.clock_sync.count + 1;
        just_forward(port);
    }

    action clock_sync_add_t3(PortId_t port){
        hdr.clock_sync.t3 = ig_intr_md.ingress_mac_tstamp;
        hdr.clock_sync.count = hdr.clock_sync.count + 1;
        just_forward(port);
    }

    table tb_clock_sync {
        key = {
            hdr.clock_sync.count: exact;
        }
        actions = {
            just_forward;
            clock_sync_add_t0; 
            clock_sync_add_t1; 
            clock_sync_add_t2; 
            clock_sync_add_t3; 
            NoAction;
            }

        default_action = NoAction;
        size = 32;
    }

    // GetRelativeTimestamp() grt;
    apply {
        if ( hdr.clock_sync.isValid() ) {
            tb_clock_sync.apply();
            exit;
        }

        // grt.apply(
        //     meta,
        //     hdr
        //     );
            
        // if (meta.reference_tstamp > meta.mac_tstamp) {
        //     meta.reference_tstamp = meta.reference_tstamp - 0xffff ;
        // }

        // meta.global_tstamp = meta.mac_tstamp - meta.reference_tstamp;

        if (hdr.d6gint.isValid() ){
            tb_d6gint_handler.apply();
        }
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
    Mirror() ing_port_mirror;
    apply {
        /* 
         * If there is a mirror request, create a clone. 
         * Note: Mirror() externs emits the provided header, but also
         * appends the ORIGINAL ingress packet after those
         */
        if (ig_dprsr_md.mirror_type == ING_PORT_MIRROR) {
            ing_port_mirror.emit<ing_port_mirror_h>(
                meta.mirror_session,
                {
                    meta.mirror_header_type,
                    meta.mirror_header_info,
                    PAD(meta.mirror_session),
                    meta.t3
                });

        } 
                
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
        transition accept;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_D6GMAIN: parse_d6gmain;
            default: accept;
        }
    }

    state parse_d6gmain {
        pkt.extract(hdr.d6gmain);
        transition select (hdr.d6gmain.nextHeader) {
            ETHERTYPE_D6GINT: parse_d6gint;
            default: accept;
        }
    }

    state parse_d6gint {
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

    // action remove_d6gint_and_forward(){
    //     hdr.d6gmain.nextHeader = hdr.d6gint.next_header;
    //     hdr.d6gint.setInvalid();
    // }

    
    // table tb_d6gint_remove {
    //     actions = {
    //         remove_d6gint_and_forward;
    //     }
    //     default_action = remove_d6gint_and_forward;
    //     size = 1024;
    // }

    action update_d6gint_t3(){
        hdr.d6gint.next_header = 0;
        hdr.d6gint.t3 = meta.ing_port_mirror.t3;
    }

    table tb_handle_mirrored_packets {
        key = {
            meta.mirror_session: exact;
            }
        actions = { 
            update_d6gint_t3; 
            NoAction ;}
        
        const entries = {
            10w100: update_d6gint_t3;
        }

        default_action = NoAction;
        size = 1024;
    }


    apply {
        if ( meta.ing_port_mirror.isValid() ) {
            tb_handle_mirrored_packets.apply();
        } 
        
        // else if ( hdr.d6gint.isValid() ) { 
        //     hdr.d6gmain.nextHeader = hdr.d6gint.next_header;
        //     hdr.d6gint.setInvalid();
        // }
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
    // Mirror() egr_port_mirror;
    apply {               
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
