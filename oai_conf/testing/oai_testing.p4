/* -*- P4_16 -*- */

#include <core.p4>
#include <t2na.p4>

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/
const int MCAST_GRP_ID = 1;

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress can differ */
typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<12> nexthop_id_t;
typedef bit<8> switch_id_t;

enum bit<16> ether_type_t {
    IPV4 = 0x0800,
    ARP  = 0x0806
}

/* Standard ethernet header */
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
    mac_addr_t sender_hw_addr;
    ipv4_addr_t sender_ip_addr;
    mac_addr_t target_hw_addr;
    ipv4_addr_t target_ip_addr;
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



/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_ingress_headers_t {
    ethernet_h   ethernet;
    ipv4_h       ipv4;
    arp_h arp;
}

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
}

    /***********************  P A R S E R  **************************/
parser MyIngressParser(packet_in        pkt,
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
        transition parse_ethernet;
    }

    state parse_ethernet {
		pkt.extract(hdr.ethernet);
		transition select(hdr.ethernet.ether_type){
			(bit<16>) ether_type_t.IPV4: parse_ipv4;
			(bit<16>) ether_type_t.ARP: parse_arp;
			default: accept;
		}
	}

	state parse_ipv4 {
		pkt.extract(hdr.ipv4);
		transition accept;
	}

	state parse_arp {
		pkt.extract(hdr.arp);
		transition accept;
	}
}

    /***************** M A T C H - A C T I O N  *********************/

control MyIngress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{

    // action forward(bit<48> dmac, bit<9> egress_port) {
    action forward(bit<9> egress_port) {
        // hdr.ethernet.dst_addr = dmac;
        ig_tm_md.ucast_egress_port = egress_port;
    }

    table tbl_forward {
        key = { 
            hdr.ipv4.dst_addr: exact; 
        }
        actions = { 
            forward; 
            NoAction; 
        }
        default_action = NoAction();
        const entries = {
            // 0xc0a84690 : forward(0x0090fb770bac, 5);     // CU - 192.168.70.144 @ tofino2b[enp4s0f0], 33/3
            // 0xc0a84691 : forward(0x649d99b1260e, 136);     // DU - 192.168.70.145 @ aeon[enp179s0f0], 1/0
            // 0xc0a84686 : forward(0x8aca58b8e852, 152);     // UPF - 192.168.70.134 mare[ens1f1np1], 3/0
            // 0xc0a84684 : forward(0x8aca58b9e951, 152);     // AMF - 192.168.70.132 mare[ens1f1np1], 3/0
            0xc0a84690 : forward(5);     // CU - 192.168.70.144 @ tofino2b[enp4s0f0], 33/3
            0xc0a84691 : forward(136);     // DU - 192.168.70.145 @ aeon[enp179s0f0], 1/0
            0xc0a84686 : forward(152);     // UPF - 192.168.70.134 mare[ens1f1np1], 3/0
            0xc0a84684 : forward(152);     // AMF - 192.168.70.132 mare[ens1f1np1], 3/0
        }
        size = 64;
    }
    apply {
        if(hdr.ethernet.ether_type == (bit<16>) ether_type_t.ARP){
			// do the broadcast to all involved ports
			ig_tm_md.mcast_grp_a = MCAST_GRP_ID;
			ig_tm_md.rid = 0;
		} else {
            tbl_forward.apply();
        }
    }
}

    /*********************  D E P A R S E R  ************************/

control MyIngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_egress_headers_t {
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
}

    /***********************  P A R S E R  **************************/

parser MyEgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control MyEgress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    apply {
    }
}

    /*********************  D E P A R S E R  ************************/

control MyEgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}


/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    MyIngressParser(),
    MyIngress(),
    MyIngressDeparser(),
    MyEgressParser(),
    MyEgress(),
    MyEgressDeparser()
) pipe;

Switch(pipe) main;