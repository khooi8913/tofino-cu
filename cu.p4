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
const bit<16> UDP_DOWN = 0x0868; // from core-- 2152
const bit<16> UDP_UP = 0x0869; // towards core-- 2153
const bit<9> CPU_PORT = 0x68;

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
    gtpu_options_h gtpu_options;
    gtpu_next_ext_h gtpu_next_ex;
    gtpu_ext_psc_h gtpu_ext_psc;
}

struct switch_metadata_t {

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
            UDP_UP : parse_gtp_1;   // towards core
            UDP_DOWN : parse_gtp_2; // towards DU
        }
    }
// currently have the same logic in both directions, can change here if required
    state parse_gtp_1{
        pkt.extract(hdr.gtpu);
        pkt.extract(gtpu_options);

        transition select(hdr.gtpu.ex_flag, hdr.gtpu.seq_flag, hdr.gtpu.npdu_flag){
            1, _, _ :  parse_gtpu_ext;
            0, 1, _ :  parse_gtpu_ext;
            0, 0, 1 :  parse_gtpu_ext;
            0, 0, 0 :  accept;
        }
    }

    state parse_gtp_2{
        pkt.extract(hdr.gtpu);
        pkt.extract(gtpu_options);

        transition select(hdr.gtpu.ex_flag, hdr.gtpu.seq_flag, hdr.gtpu.npdu_flag){
            1, _, _ :  parse_gtpu_ext;
            0, 1, _ :  parse_gtpu_ext;
            0, 0, 1 :  parse_gtpu_ext;
            0, 0, 0 :  accept;
        }
    }

    state parse_gtpu_ext{
        pkt.extract(gtpu_next_ext_h);
        pkt.extract(hdr.gtpu_ext_psc);
        transition accept;
    }

    // TODO:
    // parse GTP headers
    // F1 interface - port 2153
    // N3 interface - port 2152
    // refer to PCAP
}

control SwitchIngress(
    inout switch_headers_t                       hdr,
    inout switch_metadata_t                      meta,
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    // IPv4 Forward --------------------------------------------------------------------

    action ipv4_forward_action(bit<9> port) {
        ig_tm_md.ucast_egress_port = port;
    }

    action tunnel_seq_action(bit<32> tunnel_id, bit<16> seq_no) {
        hdr.gtpu.teid = tunnel_id;
        hdr.gtpu_options.seq_num = seq_no; // TODO
    
    }
    // can't maintain the entire rewrite as a table as one action can't apply a table
    table tunnel_seq {
        key = {
            hdr.gtpu.teid : lpm;
        }
        actions = {
            up_rewrite; down_rewrite; ipv4_forward_action;
            @defaultonly NoAction;
        }
        const entries = {
            0x301e8f18 : tunnel_seq_action(0x01, 0x0);
            0x01 : tunnel_seq_action(0x301e8f18, 0x0);
        }
        
        default_action = NoAction;

    }
// Src: 192.168.70.144(DU) or  Src: 192.168.70.134(Core)
    table ipv4_forward {
        key = {
            hdr.ipv4.dst_addr : exact;
            hdr.udp.dst_port : exact;
        }
        actions = {
            up_rewrite; down_rewrite; ipv4_forward_action;
            @defaultonly NoAction;
        }
        const entries = {
            ( 192.168.70.134, 2153) : up_rewrite();   // if I don't have the table mapping yet I need to send to CPU
            ( 192.168.70.144, 2152) : down_rewrite();   // 
            ( _, CPU_PORT)          : ipv4_forward_action();
        }
        
        default_action = NoAction;
    }


    // CU GTP Rewrite --------------------------------------------------------------------
    // TODO

    apply {

        if(!hdr.gtpu.isValid ){

            if(hdr.ipv4.dst_addr == 192.168.70.144){
                hdr.ipv4.dst_addr = 192.168.70.134;
            }
            if(hdr.ipv4.dst_addr == 192.168.70.134){
                hdr.ipv4.dst_addr = 192.168.70.144;
            }
        }
        else{

            if(ig_intr_md.ingress_port != CPU_PORT){ 
                
                if(hdr.udp.dst_port== UDP_UP){ // from F1 towards core
                
                    if(ipv4_forward_action.apply().hit){
                        // CU GTP rewrite
                        hdr.gtpu.version = 3w0b001;    /* version */
                        hdr.gtpu.pt = 1;         /* protocol type */
                        hdr.gtpu.spare = 0;      /* reserved */
                        hdr.gtpu.ex_flag = 1;    /* next extension hdr present? */
                        hdr.gtpu.seq_flag = 0;   /* sequence no. */
                        hdr.gtpu.npdu_flag = 0;  /* n-pdn number present ? */
                        hdr.gtpu.msgtype = 0xff;    /* message type */
                        hdr.gtpu.msglen = 0x5c;     /* message length */
                        // TODO FROM TABLE SEQ ID
                        tunnel_seq.apply();
                        // hdr.gtpu.teid=0x01;       /* tunnel endpoint id */ 

                        // The Extenstion Unit headers
                        hdr.gtpu_next_ex.next_ext = 0x85;
                        hdr.gtpu_ext_psc.len = 0x01 ;      /* Length in 4-octet units (common to all extensions) */
                        bit<4> type = 0x1;     /* Uplink or downlink */
                        bit<4> spare0 = 0x0;   /* Reserved */
                        bit<1> ppp = 0;      /* Paging Policy Presence (UL only, not supported) */
                        bit<1> rqi = 0;      /* Reflective QoS Indicator (UL only) */
                        bit<6>  qfi = 0x6;      /* QoS Flow Identifier */
                        bit<8> next_ext = 0x00;

                        hdr.udp.src_port= UDP_UP;
                        hdr.udp.dst_port= UDP_UP;
                        hdr.ipv4.src_addr = 192.168.70.144;
                        hdr.ipv4.dst_addr = 192.168.70.134;

                    }
                    else{
                        ig_tm_md.ucast_egress_port = CPU_PORT;
                    }
                }
                else{ // from N3 

                    if(ipv4_forward_action.apply().hit){
                        // F1 GTP rewrite
                        hdr.gtpu.version = 3w0b001;    /* version */
                        hdr.gtpu.pt = 1;         /* protocol type */
                        hdr.gtpu.spare = 0;      /* reserved */
                        hdr.gtpu.ex_flag = 0;    /* next extension hdr present? */
                        // EX FLAG SET TO 0
                        hdr.gtpu.seq_flag = 0;   /* sequence no. */
                        hdr.gtpu.npdu_flag = 0;  /* n-pdn number present ? */
                        hdr.gtpu.msgtype = 0xff;    /* message type */
                        // TODO FROM TABLE SEQ ID
                        tunnel_seq.apply();
                        hdr.gtpu.msglen = 0x57;     /* message length */
                        hdr.gtpu.teid=0x301e8f18;       /* tunnel endpoint id */ 

                        hdr.gtpu_ext_psc.setInvalid();

                        hdr.udp.src_port= UDP_DOWN;
                        hdr.udp.dst_port= UDP_DOWN;
                        hdr.ipv4.src_addr = 192.168.70.134;
                        hdr.ipv4.dst_addr = 192.168.70.144;

                    }
                    else{
                        ig_tm_md.ucast_egress_port = CPU_PORT;
                    }
                }

            }
            else{
                ipv4_forward_action.apply();
            }  
        }
        // TODO: 
        // 1. forward all SCTP packets to/fro CPU and DU
        // 2. if received from F1, is table hit, then do CU GTP Rewrite; if miss, send to CPU
        // 3. if received from N3, is table hit, then do F1 GTP Rewrite; if miss, send to CPU
        // 4. if received from CPU, do IPv4 forward directly
        // ipv4_forward.apply();
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
