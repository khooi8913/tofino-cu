#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

typedef bit<16> ether_type_t;
typedef bit<8> ip_protocol_t;

const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ip_protocol_t IP_PROTOCOLS_UDP = 0x11;

const bit<16> UDP_PORT_N3 = 0x0868; // from core-- 2152
const bit<16> UDP_PORT_F1 = 0x0869; // towards core-- 2153

const bit<32> IP_ADDR_CU = 0xc0a84690;      // 192.168.70.144
const bit<32> IP_ADDR_DU = 0xc0a84691;      // 192.168.70.145
const bit<32> IP_ADDR_UPF = 0xc0a84686;     // 192.168.70.134

#if __TARGET_TOFINO__ == 2
const bit<9> CPU_PORT = 0x05;
#else
const bit<9> CPU_PORT = 0x00;
#endif

header ethernet_h {
    bit<48>   dst_addr;
    bit<48>   src_addr;
    bit<16>   ether_type;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length;
    bit<16> checksum;
}

// GTPU v1
header gtpu_h {
    bit<3>  version;    /* version */
    bit<1>  pt;         /* protocol type */
    bit<1>  spare;      /* reserved */
    bit<1>  ex_flag;    /* next extension hdr present? */
    bit<1>  seq_flag;   /* sequence no. */
    bit<1>  npdu_flag;  /* n-pdn number present ? */
    bit<8>  msgtype;    /* message type */
    bit<16> msglen;     /* message length */
    bit<32>  teid;       /* tunnel endpoint id */
}

// Follows gtpu_h if any of ex_flag, seq_flag, or npdu_flag is 1.
header gtpu_options_h {
    bit<16> seq_num;   /* Sequence number */
    bit<8>  n_pdu_num; /* N-PDU number */
}

header gtpu_next_ext_h {
    bit<8>  next_ext;  /* Next extension header */
}

// GTPU extension: PDU Session Container (PSC) -- 3GPP TS 38.415 version 15.2.0
// https://www.etsi.org/deliver/etsi_ts/138400_138499/138415/15.02.00_60/ts_138415v150200p.pdf
header gtpu_ext_psc_h {
    bit<8> len;      /* Length in 4-octet units (common to all extensions) */
    bit<4> type;     /* Uplink or downlink */
    bit<4> spare0;   /* Reserved */
    bit<1> ppp;      /* Paging Policy Presence (UL only, not supported) */
    bit<1> rqi;      /* Reflective QoS Indicator (UL only) */
    bit<6>  qfi;      /* QoS Flow Identifier */
    bit<8> next_ext;
}

struct switch_headers_t {
    ethernet_h  ethernet;
    ipv4_h      ipv4;
    udp_h       udp;
    gtpu_h      gtpu;
    gtpu_options_h  gtpu_options;
    gtpu_next_ext_h gtpu_next_ex;
    gtpu_ext_psc_h  gtpu_ext_psc;
}

struct switch_metadata_t {
    bit<1>      is_f1;
    bit<1>      is_n3;
    bit<1>      from_du;
    bit<1>      from_cn;      
}

// ==================== INGRESS ====================
parser SwitchIngressParser(packet_in        pkt,
    out switch_headers_t          hdr,
    out switch_metadata_t         meta,
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
     state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_UDP : parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.dst_port) {
            UDP_PORT_N3 : parse_gtp_n3;     // towards core
            UDP_PORT_F1 : parse_gtp_f1;     // towards DU
        }
    }

    // currently have the same logic in both directions, can change here if required
    state parse_gtp_n3{
        pkt.extract(hdr.gtpu);
        pkt.extract(hdr.gtpu_options);

        transition select(hdr.gtpu.ex_flag, hdr.gtpu.seq_flag, hdr.gtpu.npdu_flag){
            (1, _, _)   :  parse_gtpu_ext;
            (0, 1, _)   :  parse_gtpu_ext;
            (0, 0, 1)   :  parse_gtpu_ext;
            default     :  accept;
        }
    }

    state parse_gtp_f1{
        pkt.extract(hdr.gtpu);
        pkt.extract(hdr.gtpu_options);

        transition select(hdr.gtpu.ex_flag, hdr.gtpu.seq_flag, hdr.gtpu.npdu_flag){
            (1, _, _)   :  parse_gtpu_ext;
            (0, 1, _)   :  parse_gtpu_ext;
            (0, 0, 1)   :  parse_gtpu_ext;
            default     :  accept;
        }
    }

    state parse_gtpu_ext{
        pkt.extract(hdr.gtpu_next_ex);
        pkt.extract(hdr.gtpu_ext_psc);
        transition accept;
    }
}

control SwitchIngress(
    inout switch_headers_t                       hdr,
    inout switch_metadata_t                      meta,
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    // First val in <,> is size and second is index
    Register<bit<8>,bit<8>>(10,0x0) npdu_reg;
    
    // Keep the npdu count based on the (16-bit) index of the register
    RegisterAction<bit<8>, bit<8>, bit<8>>(npdu_reg) fetch_npdu = {
        void apply(inout bit<8> np, out bit<8> rv) {
            np = np + 1;
            rv = np; 
        }
    };

    action drop() {
        ig_dprsr_md.drop_ctl = 0x01;
    }

    // IPv4 Forward --------------------------------------------------------------------
    action ipv4_forward_action(bit<9> port) {
        ig_tm_md.ucast_egress_port = port;
    }

    table ipv4_forward {
        key = {
            hdr.ipv4.dst_addr : exact;
        }
        actions = {
            ipv4_forward_action;
            NoAction;
        }
        default_action = NoAction();
    }

    action set_origin_f1() {
        meta.is_f1 = 1;
        meta.from_du = 1;
    }

    action set_origin_n3() {
        meta.is_n3 = 1;
        meta.from_cn = 1;
    }

    table get_origin {
        key = {
            hdr.ipv4.src_addr: exact;
        } 
        actions = {
            set_origin_f1;
            set_origin_n3;
            drop;
        }
        default_action = drop();
        const entries = {
            IP_ADDR_DU  : set_origin_f1();   // 192.168.70.145
            IP_ADDR_UPF : set_origin_n3();   // 192.168.70.134
        }
        size = 128;
    }

    // F1 to N3 --------------------------------------------------------------------
    action rewrite_f1_to_n3(bit<32> teid, bit<6> qfi) {
        hdr.gtpu.version = 3w0b001;    /* version */
        hdr.gtpu.pt = 1;         /* protocol type */
        hdr.gtpu.spare = 0;      /* reserved */
        hdr.gtpu.ex_flag = 1;    /* next extension hdr present? */

        hdr.gtpu_next_ex.setValid();
        hdr.gtpu_ext_psc.setValid();

        hdr.gtpu.seq_flag = 0;                      /* sequence no. */
        hdr.gtpu.npdu_flag = 0;                     /* n-pdn number present ? */
        hdr.gtpu.msgtype = 0xff;                    /* message type */
        hdr.gtpu.msglen = hdr.gtpu.msglen + 5;      /* message length */
        hdr.gtpu.teid=teid;                         /* tunnel endpoint id */ 
        hdr.gtpu_options.seq_num = 0;
        hdr.gtpu_options.n_pdu_num = 0;

        hdr.gtpu_next_ex.next_ext = 0x85;
        hdr.gtpu_ext_psc.len = 0x01 ;       /* Length in 4-octet units (common to all extensions) */
        hdr.gtpu_ext_psc.type = 0x1;        /* Uplink or downlink */
        hdr.gtpu_ext_psc.spare0 = 0x0;      /* Reserved */
        hdr.gtpu_ext_psc.ppp = 0;           /* Paging Policy Presence (UL only, not supported) */
        hdr.gtpu_ext_psc.rqi = 0;           /* Reflective QoS Indicator (UL only) */
        hdr.gtpu_ext_psc.qfi = qfi;         /* QoS Flow Identifier */
        hdr.gtpu_ext_psc.next_ext = 0x00;

        hdr.udp.src_port= UDP_PORT_N3;
        hdr.udp.dst_port= UDP_PORT_N3;
        hdr.ipv4.src_addr = IP_ADDR_CU;
        hdr.ipv4.dst_addr = IP_ADDR_UPF;

        // adjust packet length
        hdr.ipv4.total_len = hdr.ipv4.total_len + 5; 
        hdr.udp.length = hdr.udp.length + 5;
    }

    table fastpath_f1_to_n3 {
        key = {
            hdr.gtpu.teid : exact;
        }
        actions = {
            rewrite_f1_to_n3;
            NoAction;
        }
        default_action = NoAction;
    }

    // N3 to F1 --------------------------------------------------------------------
    action rewrite_n3_to_f1(bit<32> teid, bit<16> seq_num, bit<8> index) {
        hdr.gtpu.version = 3w0b001;     /* version */
        hdr.gtpu.pt = 1;                /* protocol type */
        hdr.gtpu.spare = 0;             /* reserved */
        hdr.gtpu.ex_flag = 0;           /* next extension hdr present? */

        hdr.gtpu_next_ex.setInvalid();
        hdr.gtpu_ext_psc.setInvalid();
        
        hdr.gtpu.seq_flag = 0;          /* sequence no. */
        hdr.gtpu.npdu_flag = 0;         /* n-pdn number present ? */
        hdr.gtpu.msgtype = 0xff;        /* message type */
        hdr.gtpu.msglen = hdr.gtpu.msglen - 5;     /* message length */
        hdr.gtpu.teid=teid;             /* tunnel endpoint id */ 

        hdr.gtpu_options.seq_num = seq_num;
        hdr.gtpu_options.n_pdu_num = fetch_npdu.execute(index);

        hdr.udp.src_port= UDP_PORT_F1;
        hdr.udp.dst_port= UDP_PORT_F1;
        hdr.ipv4.src_addr = IP_ADDR_CU;
        hdr.ipv4.dst_addr = IP_ADDR_DU;

        // adjust packet length
        hdr.ipv4.total_len = hdr.ipv4.total_len - 5; 
        hdr.udp.length = hdr.udp.length - 5;
    }

    table fastpath_n3_to_f1 {
        key = {
            hdr.gtpu.teid : exact;
        }
        actions = {
            rewrite_n3_to_f1;
            NoAction;
        }
        default_action = NoAction;
    }



    apply {
        if(hdr.ipv4.isValid()) { 
            
            ipv4_forward.apply();  

            if(ig_intr_md.ingress_port != CPU_PORT){ 
                if(hdr.gtpu.isValid()) {
                    get_origin.apply();

                    if(meta.from_du == 1) {
                        fastpath_f1_to_n3.apply();
                    } else if(meta.from_cn == 1) {
                        fastpath_n3_to_f1.apply();
                    }
                } else {
                    // SCTP -- F1-C or N2 
                    // from DU/ AMF
                }
            } else {
                // GTP or SCTP
                // from CPU port
            }
        }
    }
}

control SwitchIngressDeparser(packet_out pkt,
    inout switch_headers_t                       hdr,
    in    switch_metadata_t                      meta,
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    apply {
        // TODO: recompute UDP checksum
        pkt.emit(hdr);
    }
}

// ==================== EGRESS ====================
parser SwitchEgressParser(packet_in        pkt,
    out switch_headers_t          hdr,
    out switch_metadata_t         meta,
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

control SwitchEgress(
    inout switch_headers_t                          hdr,
    inout switch_metadata_t                         meta,
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    apply {
    }
}

control SwitchEgressDeparser(packet_out pkt,
    inout switch_headers_t                       hdr,
    in    switch_metadata_t                      meta,
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}


Pipeline(
    SwitchIngressParser(),
    SwitchIngress(),
    SwitchIngressDeparser(),
    SwitchEgressParser(),
    SwitchEgress(),
    SwitchEgressDeparser()
) pipe;

Switch(pipe) main;
