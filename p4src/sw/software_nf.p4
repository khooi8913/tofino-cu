#include <core.p4>
#include <psa.p4>

typedef bit<48>  EthernetAddress;
typedef bit<32>  IPv4Address;

const bit<16> F1_GTP_PORT = 2153;
const bit<16> N3_GTP_PORT = 2152;

struct empty_t{ }

header ethernet_h {
    EthernetAddress dstAddr;
    EthernetAddress srcAddr;
    bit<16>         etherType;
}

header ipv4_h {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header udp_h
{
    bit<16> srcPort;
    bit<16> dstPort;
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

// https://www.sharetechnote.com/html/5G/5G_PDCP.html
header pdcp_h {
    bit<1>  dcBit;
    bit<5>  r; 
    bit<18> seqNum;
}

struct headers {
    ethernet_h  ethernet;
    ipv4_h      ipv4;
    udp_h       udp;
    gtpu_h      gtpu;
    pdcp_h      pdcp;
}

struct metadata {
}

parser IngressParserImpl(packet_in buffer,
                         out headers parsed_hdr,
                         inout metadata user_meta,
                         in psa_ingress_parser_input_metadata_t istd,
                         in empty_t resubmit_meta,
                         in empty_t recirculate_meta)
{
    state start {
        transition accept;
    }
}

parser EgressParserImpl(packet_in buffer,
                        out headers parsed_hdr,
                        inout metadata user_meta,
                        in psa_egress_parser_input_metadata_t istd,
                        in empty_t normal_meta,
                        in empty_t clone_i2e_meta,
                        in empty_t clone_e2e_meta)
{
    state start {
        buffer.extract(parsed_hdr.ethernet);
        transition select(parsed_hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        buffer.extract(parsed_hdr.ipv4);
        transition select(parsed_hdr.ipv4.protocol) {
            0x11    : parse_udp;
            default : accept;
        }
    }

    state parse_udp {
        buffer.extract(parsed_hdr.udp);
        transition select(parsed_hdr.udp.srcPort, parsed_hdr.udp.dstPort) {
            (F1_GTP_PORT, F1_GTP_PORT) : parse_f1_gtpu_pdcp;
            default : accept;
        }
    }

    state parse_f1_gtpu_pdcp {
        buffer.extract(parsed_hdr.gtpu);
        buffer.extract(parsed_hdr.pdcp);
        transition accept;
    }
}

control ingress(inout headers hdr,
                inout metadata user_meta,
                in    psa_ingress_input_metadata_t  istd,
                inout psa_ingress_output_metadata_t ostd)
{

    apply { }
}

control egress(inout headers hdr,
               inout metadata user_meta,
               in    psa_egress_input_metadata_t  istd,
               inout psa_egress_output_metadata_t ostd)
               
{
    Register<bit<32>, bit<32>>(65536, 0) seq_num_reg;

    action rewrite_pdcp_seq_num (bit<32> index) {
        bit<32> currSeqNum = seq_num_reg.read(index);
        hdr.pdcp.seqNum = (bit<18>) currSeqNum;
        bit<32> nextSeqNum = currSeqNum + 1;
        seq_num_reg.write(index, nextSeqNum);
    }

    table f1_pdcp_seq_num_rewrite {
        key = {
            hdr.ipv4.dstAddr : exact;
            hdr.gtpu.teid : exact;
        }
        actions = {
            rewrite_pdcp_seq_num;
            NoAction;
        }
        default_action = NoAction();
    }

    apply { 
        if(hdr.gtpu.isValid()) {
            f1_pdcp_seq_num_rewrite.apply();
        }   
    }
}

control IngressDeparserImpl(packet_out packet,
                            out empty_t clone_i2e_meta,
                            out empty_t resubmit_meta,
                            out empty_t normal_meta,
                            inout headers hdr,
                            in metadata meta,
                            in psa_ingress_output_metadata_t istd)
{
    apply {
        packet.emit(hdr);
    }
}

control EgressDeparserImpl(packet_out packet,
                           out empty_t clone_e2e_meta,
                           out empty_t recirculate_meta,
                           inout headers hdr,
                           in metadata meta,
                           in psa_egress_output_metadata_t istd,
                           in psa_egress_deparser_input_metadata_t edstd)
{
    apply {
        packet.emit(hdr);
    }
}

IngressPipeline(IngressParserImpl(),
                ingress(),
                IngressDeparserImpl()) ip;

EgressPipeline(EgressParserImpl(),
               egress(),
               EgressDeparserImpl()) ep;

PSA_Switch(ip, PacketReplicationEngine(), ep, BufferingQueueingEngine()) main;
