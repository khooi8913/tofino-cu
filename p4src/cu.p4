#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/
const int MCAST_GRP_ID = 1;

typedef bit<16> ether_type_t;
typedef bit<8> ip_protocol_t;

const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_ARP = 16w0x0806;

const ip_protocol_t IP_PROTOCOLS_UDP = 0x11;

const bit<16> UDP_PORT_N3 = 0x0868; // from core-- 2152
const bit<16> UDP_PORT_F1 = 0x0869; // towards core-- 2153
// const bit<16> UDP_PORT_N3 = 0x0868; // from core-- 2152
// const bit<16> UDP_PORT_F1 = 0x0868; // towards core-- 2152

// const bit<32> IP_ADDR_CU = 0xc0a84690;      // 192.168.70.144
// const bit<32> IP_ADDR_DU = 0xc0a84691;      // 192.168.70.145
// const bit<32> IP_ADDR_UPF = 0xc0a84586;     // 192.168.69.134
const bit<32> IP_ADDR_CU = 0xc0a80103;      // 192.168.1.3
const bit<32> IP_ADDR_DU = 0xc0a80106;      // 192.168.1.6
const bit<32> IP_ADDR_UPF = 0xc0a84686;     // 192.168.69.134
const bit<32> IP_ADDR_EXT = 0xc0a80105;     // 192.168.1.5

#if __TARGET_TOFINO__ == 2
const bit<9> CPU_PORT = 0x05;
#else
const bit<9> CPU_PORT = 0x00;
#endif

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

header ethernet_h {
    bit<48>   dst_addr;
    bit<48>   src_addr;
    bit<16>   ether_type;
}

header arp_h {
    bit<16> htype;
    bit<16> ptype;
    bit<8> hlen;
    bit<8> plen;
    bit<16> oper;
    bit<48> sender_hw_addr;
    bit<32> sender_ip_addr;
    bit<48> target_hw_addr;
    bit<32> target_ip_addr;
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
// header gtpu_h {
//     bit<1>  npdu_flag;  /* n-pdn number present ? */
//     bit<1>  seq_flag;   /* sequence no. */
//     bit<1>  spare;      /* reserved */
//     bit<1>  ex_flag;    /* next extension hdr present? */
//     bit<1>  pt;         /* protocol type */
//     bit<3>  version;    /* version */
//     bit<8>  msgtype;    /* message type */
//     bit<16> msglen;     /* message length */
//     bit<32>  teid;       /* tunnel endpoint id */
// }
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
    // bit<16> seq_num;   /* Sequence number */
    // bit<8>  n_pdu_num; /* N-PDU number */

    // OAI-specific
    bit<24> seq_num;   /* Alawys 0x000 N3, used in F1 to carry sequence numbers */
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
    arp_h       arp;
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

    bool        recompute_udp_csum;
    bit<16>     udp_csum;
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
            ETHERTYPE_ARP  : parse_arp;
            ETHERTYPE_IPV4 : parse_ipv4;
        }
    }

    state parse_arp {
        pkt.extract(hdr.arp);
		transition accept;
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
            UDP_PORT_N3 : parse_gtp;     // towards core
            UDP_PORT_F1 : parse_gtp;
            default : accept;
        }
    }

    state parse_gtp {
        pkt.extract(hdr.gtpu);
        pkt.extract(hdr.gtpu_options);  /* Remark: This is OAI-specific. Never used in N3, but F1. */
        transition select(hdr.gtpu.ex_flag, hdr.gtpu.seq_flag, hdr.gtpu.npdu_flag){
            (1, _, _)   :  parse_gtpu_ext;
            (_, 1, _)   :  parse_gtpu_ext;
            (_, _, 1)   :  parse_gtpu_ext;
            default     :  accept;
        }
    }

    state parse_gtpu_ext{
        pkt.extract(hdr.gtpu_next_ex);
        pkt.extract(hdr.gtpu_ext_psc);  /* Remark: This is OAI-specific. We assume only the PDU Session Container. */
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
    Register<bit<32>,bit<16>>(65536, 0x0) seq_num_reg;
    
    // Keep the npdu count based on the (16-bit) index of the register
    RegisterAction<bit<32>, bit<16>, bit<32>>(seq_num_reg) fetch_seq_num = {
        void apply(inout bit<32> val, out bit<32> rv) {
            if(val == 1 << 23) {
                val = 0;
            } else {
                val = val + 1;
            }
            rv = val;
        }
    };

    action drop() {
        ig_dprsr_md.drop_ctl = 0x01;
    }

    // IPv4 Forward --------------------------------------------------------------------
    action ipv4_forward_action(bit<9> port, bit<48> dest_mac) {
        // TODO: rewrite MAC address here
        ig_tm_md.ucast_egress_port = port;
        hdr.ethernet.dst_addr = dest_mac;
    }

    table ipv4_forward {
        key = {
            hdr.ipv4.dst_addr : ternary;
        }
        actions = {
            ipv4_forward_action;
            NoAction;
        }
        default_action = NoAction();
        const entries = {
            // (0xc0a84690 &&& 0xffffffff) : ipv4_forward_action(CPU_PORT, 0x0090fb770bac);       // CU(N3) - 192.168.70.144 @ tofino2b[enp4s0f0], 33/3
            // (0xc0a84692 &&& 0xffffffff) : ipv4_forward_action(CPU_PORT, 0x0090fb770bac);       // CU(F1) - 192.168.70.146 @ tofino2b[enp4s0f0], 33/3
            // (0xc0a84691 &&& 0xffffffff) : ipv4_forward_action(136, 0x649d99b1260e);     // DU - 192.168.70.145 @ aeon[enp179s0f0], 1/0
            // (0xc0a84684 &&& 0xffffffff) : ipv4_forward_action(152, 0x08c0ebd418a3);     // AMF - 192.168.70.132 mare[ens1f1np1], 3/0
            // (0xc0a84580 &&& 0xffffff00) : ipv4_forward_action(152, 0x08c0ebd418a3);     // AMF - 192.168.70.132 mare[ens1f1np1], 3/0
            (IP_ADDR_CU &&& 0xffffffff) : ipv4_forward_action(CPU_PORT, 0x0090fb770bac);        // CU - tofino2b[enp4s0f0], 33/3
            (IP_ADDR_DU &&& 0xffffffff) : ipv4_forward_action(176, 0x649d99b1b92d);             // DU - cir-zeus[enp179s0f0], 6/0
            (0xc0a84684 &&& 0xffffffff) : ipv4_forward_action(168, 0x08c0ebd418a2);             // AMF - 192.168.70.132 mare[ens1f0np0], 5/0
            (0xc0a84686 &&& 0xffffffff) : ipv4_forward_action(168, 0x08c0ebd418a2);             // UPF - 192.168.70.134 mare[ens1f0np0], 5/0
            (0xc0a80102 &&& 0xffffffff) : ipv4_forward_action(168, 0x08c0ebd418a2);             // 192.168.1.2 mare[ens1f0np0], 5/0
            (0xc0a80105 &&& 0xffffffff) : ipv4_forward_action(152, 0xe8ebd3aa7f92);             // 192.168.1.5 poseidon[ens1f0np0], 3/0
        }
        size = 64;
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
        hdr.gtpu.version = 3w0b001;     /* version */
        hdr.gtpu.pt = 1;                /* protocol type */
        hdr.gtpu.spare = 0;             /* reserved */
        hdr.gtpu.ex_flag = 1;           /* next extension hdr present? */

        hdr.gtpu_next_ex.setValid();
        hdr.gtpu_ext_psc.setValid();

        hdr.gtpu.seq_flag = 0;                      /* sequence no. */
        hdr.gtpu.npdu_flag = 0;                     /* n-pdn number present ? */
        hdr.gtpu.msgtype = 0xff;                    /* message type */
        hdr.gtpu.msglen = hdr.gtpu.msglen + 5;      /* message length */
        hdr.gtpu.teid=teid;                         /* tunnel endpoint id */ 
        hdr.gtpu_options.seq_num = 0;

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

        // update packet length
        hdr.ipv4.total_len = hdr.ipv4.total_len + 5; 
        hdr.udp.length = hdr.udp.length + 5;

        hdr.udp.checksum = 0;

        // TODO: merged this with IPv4 forward
        // hdr.ethernet.dst_addr = 0x08c0ebd418a3;
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
    action rewrite_n3_to_f1(bit<32> teid, bit<16> index) {
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

        hdr.gtpu_options.seq_num = (bit<24>) fetch_seq_num.execute(index);

        hdr.udp.src_port= UDP_PORT_F1;
        hdr.udp.dst_port= UDP_PORT_F1;
        hdr.ipv4.src_addr = IP_ADDR_CU;
        hdr.ipv4.dst_addr = IP_ADDR_DU;

        // adjust packet length
        hdr.ipv4.total_len = hdr.ipv4.total_len - 5; 
        hdr.udp.length = hdr.udp.length - 5;

        hdr.udp.checksum = 0;
        
        // TODO: merged this with IPv4 forward
        // hdr.ethernet.dst_addr = 0x649d99b1260e;
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
        if(hdr.ethernet.ether_type == ETHERTYPE_ARP){
			// do the broadcast to all involved ports
			ig_tm_md.mcast_grp_a = MCAST_GRP_ID;
			ig_tm_md.rid = 0;
		} else { 
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
                        
            ipv4_forward.apply();  
        }
    }
}

control SwitchIngressDeparser(packet_out pkt,
    inout switch_headers_t                       hdr,
    in    switch_metadata_t                      meta,
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    Checksum() ipv4_checksum;

    apply {
        hdr.ipv4.hdr_checksum = ipv4_checksum.update({
            hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.diffserv,
            hdr.ipv4.total_len,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.frag_offset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr
        });
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
