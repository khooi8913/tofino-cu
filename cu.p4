#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
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

// Follows gtpu_t if any of ex_flag, seq_flag, or npdu_flag is 1.
header gtpu_options_h {
    bit<16> seq_num;   /* Sequence number */
    bit<8>  n_pdu_num; /* N-PDU number */
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
        transition accept;
    }

    // TODO:
    // parse GTP headers
    // F1 interface - port 2153
    // N3 interface - prot 2152
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
        
    table ipv4_forward {
        key = {
            local_md.dst_addr : lpm;
        }
        actions = {
            NoAction;
            ipv4_forward_action;
        }
        default_action = NoAction;
    }

    // CU GTP Rewrite --------------------------------------------------------------------
    // TODO

    apply {
        // TODO: 
        // 1. forward all SCTP packets to/fro CPU and DU
        // 2. if received from F1, is table hit, then do CU GTP Rewrite; if miss, send to CPU
        // 3. if received from N3, is table hit, then do F1 GTP Rewrite; if miss, send to CPU
        // 4. if received from CPU, do IPv4 forward directly
        ipv4_forward.apply();
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
