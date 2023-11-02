import sys
import ipaddress

from scapy.all import *

# ==============================
# CONSTANTS
# ==============================
IP_ADDR_CU = "192.168.1.3"
IP_ADDR_DU = "192.168.1.6"
IP_ADDR_UPF = "192.168.70.134"

UDP_PORT_F1 = 2153
UDP_PORT_N3 = 2152
# ==============================

# Usage (without debug): 
# 1. offline: python3 offload.py offline sample.pcap 0
# 2. online: sudo python3 offload.py online ens1 0
mode = sys.argv[1]
net_intf = sys.argv[2]

if mode == "offline":
    pass
elif mode == "online":
    sde_install = os.environ['SDE_INSTALL']
    sys.path.append('%s/lib/python2.7/site-packages/tofino'%(sde_install))
    sys.path.append('%s/lib/python2.7/site-packages/p4testutils'%(sde_install))
    sys.path.append('%s/lib/python2.7/site-packages'%(sde_install))

    # Assumes valid PYTHONPATH
    import grpc
    import bfrt_grpc.bfruntime_pb2 as bfrt_grpc
    import bfrt_grpc.client as gc

    # Connect to the BF Runtime server
    for bfrt_client_id in range(10):
        try:
            interface = gc.ClientInterface(
                grpc_addr="localhost:50052",
                client_id=bfrt_client_id,
                device_id=0,
                num_tries=1,
            )
            print("Connected to BF Runtime Server as client", bfrt_client_id)
            break
        except:
            print("Could not connect to BF Runtime Server")
            quit

    # Get information about the running program
    bfrt_info = interface.bfrt_info_get()
    print("The target is running the P4 program: {}".format(bfrt_info.p4_name_get()))

    # Establish that you are the "main" client
    if bfrt_client_id == 0:
        interface.bind_pipeline_config(bfrt_info.p4_name_get())

    # Get the target device, currently setup for all pipes
    target = gc.Target(device_id=0, pipe_id=0xffff)
else:
    print("invalid arguments!")
    exit(1)

def is_f1_gtp(pkt):
    return (pkt.getlayer("UDP").sport == UDP_PORT_F1 and pkt.getlayer("UDP").dport == UDP_PORT_F1)

def is_n3_gtp(pkt):
    return (pkt.getlayer("UDP").sport == UDP_PORT_N3 and pkt.getlayer("UDP").dport == UDP_PORT_N3)

def is_gtp(pkt):
    return is_f1_gtp(pkt) or is_n3_gtp(pkt)

def is_du_to_cu(pkt):
    return is_f1_gtp(pkt) and (pkt.getlayer("IP").dst == IP_ADDR_CU) and (pkt.getlayer("IP").src == IP_ADDR_DU)

def is_cu_to_cn(pkt):
    return is_n3_gtp(pkt) and (pkt.getlayer("IP").dst == IP_ADDR_UPF) and (pkt.getlayer("IP").src == IP_ADDR_CU)

def is_cn_to_cu(pkt):
    return is_n3_gtp(pkt) and (pkt.getlayer("IP").dst == IP_ADDR_CU) and (pkt.getlayer("IP").src == IP_ADDR_UPF)

def is_cu_to_du(pkt):
    return is_f1_gtp(pkt) and (pkt.getlayer("IP").dst == IP_ADDR_DU) and (pkt.getlayer("IP").src == IP_ADDR_CU)


def to_byte_array(pkt):
    return bytearray(bytes(pkt))

def to_hex_string(byte_array):
    return ''.join(format(x, '02x') for x in byte_array)

def parse_gtp(gtp_headers):
    teid = gtp_headers[4:8]
    # seq_num = gtp_headers[8:10]
    # npdu = gtp_headers[10:11]
    seq_num = gtp_headers[8:11]
    ext_hdr = gtp_headers[11:12] if len(gtp_headers) > 11 else None
    qfi = gtp_headers[14:15] if len(gtp_headers) > 11 else None
    
    print("TEID", to_hex_string(teid))
    print("Sequence Number", to_hex_string(seq_num))
    # print("N-PDU Number", to_hex_string(npdu))
    if len(gtp_headers) > 11:
        print("Extension Header", to_hex_string(ext_hdr))
        print("QFI", to_hex_string(qfi))
        # return int.from_bytes(teid, 'big'), int.from_bytes(seq_num, 'big'), int.from_bytes(npdu, 'big'), int.from_bytes(ext_hdr, 'big'), int.from_bytes(qfi, 'big')
        return int.from_bytes(teid, 'big'), int.from_bytes(seq_num, 'big'), int.from_bytes(ext_hdr, 'big'), int.from_bytes(qfi, 'big')
    else:
        # return int.from_bytes(teid, 'big'), int.from_bytes(seq_num, 'big'), int.from_bytes(npdu, 'big')
        return int.from_bytes(teid, 'big'), int.from_bytes(seq_num, 'big')


def is_UE_subnet(ip_addr):
    print(ip_addr)
    return ipaddress.ip_address(ip_addr) in ipaddress.ip_network("12.0.0.0/8")

du_to_cu = dict()
cu_to_cn = dict()
def learn_du_to_cu(pkt):
    udp_payload = pkt.getlayer("UDP").payload
    gtp_headers = to_byte_array(udp_payload)[:11]
    gtp_payload = to_byte_array(udp_payload)[11:]
    # hexdump(gtp_headers)
    # hexdump(gtp_payload)
    gtp_fields = parse_gtp(gtp_headers)
    
    ip_pkt = IP(bytes(gtp_payload))
    if ip_pkt.getlayer("IP").version == 4:
        ip_pair = ip_pkt.getlayer("IP").src, ip_pkt.getlayer("IP").dst
        if is_UE_subnet(ip_pkt.getlayer("IP").src) or is_UE_subnet(ip_pkt.getlayer("IP").dst):
            du_to_cu[ip_pair] = gtp_fields

def learn_cu_to_cn(pkt):
    udp_payload = pkt.getlayer("UDP").payload
    gtp_headers = to_byte_array(udp_payload)[:16]
    gtp_payload = to_byte_array(udp_payload)[16:]
    # hexdump(gtp_headers)
    # hexdump(gtp_payload)
    gtp_fields = parse_gtp(gtp_headers)

    ip_pkt = IP(bytes(gtp_payload))
    if ip_pkt.getlayer("IP").version == 4:
        ip_pair = ip_pkt.getlayer("IP").src, ip_pkt.getlayer("IP").dst
        if is_UE_subnet(ip_pkt.getlayer("IP").src) or is_UE_subnet(ip_pkt.getlayer("IP").dst):
            cu_to_cn[ip_pair] = gtp_fields

cn_to_cu = dict()
cu_to_du = dict()
def learn_cn_to_cu(pkt):
    udp_payload = pkt.getlayer("UDP").payload
    gtp_headers = to_byte_array(udp_payload)[:16]
    gtp_payload = to_byte_array(udp_payload)[16:]
    # hexdump(gtp_headers)
    # hexdump(gtp_payload)
    gtp_fields = parse_gtp(gtp_headers)
    
    ip_pkt = IP(bytes(gtp_payload))
    if ip_pkt.getlayer("IP").version == 4:
        ip_pair = ip_pkt.getlayer("IP").src, ip_pkt.getlayer("IP").dst
        if is_UE_subnet(ip_pkt.getlayer("IP").src) or is_UE_subnet(ip_pkt.getlayer("IP").dst):
            cn_to_cu[ip_pair] = gtp_fields

def learn_cu_to_du(pkt):
    udp_payload = pkt.getlayer("UDP").payload
    gtp_headers = to_byte_array(udp_payload)[:11]
    gtp_payload = to_byte_array(udp_payload)[11:]
    # hexdump(gtp_headers)
    # hexdump(gtp_payload)
    gtp_fields = parse_gtp(gtp_headers)
 
    ip_pkt = IP(bytes(gtp_payload))
    if ip_pkt.getlayer("IP").version == 4:
        ip_pair = ip_pkt.getlayer("IP").src, ip_pkt.getlayer("IP").dst
        if is_UE_subnet(ip_pkt.getlayer("IP").src) or is_UE_subnet(ip_pkt.getlayer("IP").dst):
            cu_to_du[ip_pair] = gtp_fields

is_pushed = dict()
assigned_user_idx = 0

def push_to_data_plane(ul_key, dl_key):
    global assigned_user_idx
    print(ul_key, dl_key)
    index = (ul_key, dl_key)
    if not index in is_pushed:
        # uplink direction
        # f1_ul_teid, f1_ul_seq_num, f1_ul_npdu = du_to_cu[ul_key]
        # n3_ul_teid, n3_ul_seq_num, n3_ul_npdu, n3_ul_ext_hdr, n3_ul_qfi = cu_to_cn[ul_key]
        # print(f1_ul_teid, f1_ul_seq_num, f1_ul_npdu)
        # print(n3_ul_teid, n3_ul_seq_num, n3_ul_npdu, n3_ul_ext_hdr, n3_ul_qfi)
        f1_ul_teid, f1_ul_seq_num = du_to_cu[ul_key]
        n3_ul_teid, n3_ul_seq_num, n3_ul_ext_hdr, n3_ul_qfi = cu_to_cn[ul_key]
        print(f1_ul_teid, f1_ul_seq_num)
        print(n3_ul_teid, n3_ul_seq_num, n3_ul_ext_hdr, n3_ul_qfi)

        print("UPLINK TEID (F1 to N3) MAPPING", f1_ul_teid, "TO", n3_ul_teid, "with QFI", n3_ul_qfi)

        # Calling the bfrt tables
        if mode == "online":
            fast_f1_to_n3 = bfrt_info.table_get('pipe.SwitchIngress.fastpath_f1_to_n3')
            fast_f1_to_n3_key = [fast_f1_to_n3.make_key([gc.KeyTuple("hdr.gtpu.teid", f1_ul_teid)])]
            fast_f1_to_n3_data = [fast_f1_to_n3.make_data([gc.DataTuple("teid", n3_ul_teid), 
                                                        gc.DataTuple("qfi", n3_ul_qfi)],'SwitchIngress.rewrite_f1_to_n3')]
            
            fast_f1_to_n3.entry_add(target, fast_f1_to_n3_key, fast_f1_to_n3_data)
 
        # p4.Ingress.ipv4_forward.entry_with_send(dst_addr=ipaddress.ip_address("192.168.70.132"), port=152).push()
        
        
        # -----Downlink direction    
        # n3_dl_teid, n3_dl_seq_num, n3_dl_npdu, n3_dl_ext_hdr, n3_dl_qfi = cn_to_cu[dl_key]
        # f1_dl_teid, f1_dl_seq_num, f1_dl_npdu = cu_to_du[dl_key]
        # print(n3_dl_teid, n3_dl_seq_num, n3_dl_npdu, n3_dl_ext_hdr, n3_dl_qfi)
        # print(f1_dl_teid, f1_dl_seq_num, f1_dl_npdu)
        n3_dl_teid, n3_dl_seq_num, n3_dl_ext_hdr, n3_dl_qfi = cn_to_cu[dl_key]
        f1_dl_teid, f1_dl_seq_num = cu_to_du[dl_key]
        print(n3_dl_teid, n3_dl_seq_num, n3_dl_ext_hdr, n3_dl_qfi)
        print(f1_dl_teid, f1_dl_seq_num)

        # print("DOWNLINK TEID (N3 to F1) MAPPING", n3_dl_teid, "TO", f1_dl_teid, "with SeqNumber", f1_dl_seq_num, "and NPDU", f1_dl_npdu)
        print("DOWNLINK TEID (N3 to F1) MAPPING", n3_dl_teid, "TO", f1_dl_teid, "with SeqNumber", f1_dl_seq_num)

        if mode == "online":
            fast_n3_to_f1 = bfrt_info.table_get('pipe.SwitchIngress.fastpath_n3_to_f1')
            fast_n3_to_f1_key = [fast_n3_to_f1.make_key([gc.KeyTuple("hdr.gtpu.teid", n3_dl_teid)])]
            fast_n3_to_f1_data = [fast_n3_to_f1.make_data([gc.DataTuple("teid", f1_dl_teid), 
                                                        # gc.DataTuple("seq_num", f1_dl_seq_num),
                                                        gc.DataTuple("index", assigned_user_idx)], 'SwitchIngress.rewrite_n3_to_f1')]
            
            fast_n3_to_f1.entry_add(target, fast_n3_to_f1_key, fast_n3_to_f1_data)

            # Initialize the register
            seq_num_reg = bfrt_info.table_get("pipe.SwitchIngress.seq_num_reg")
            seq_num_keys = [seq_num_reg.make_key([gc.KeyTuple('$REGISTER_INDEX', assigned_user_idx)])]
            seq_num_data = [seq_num_reg.make_data([gc.DataTuple('SwitchIngress.seq_num_reg.f1', f1_dl_seq_num)])]
            seq_num_reg.entry_mod(target, seq_num_keys, seq_num_data)
            assigned_user_idx += 1

        print("offloaded!")
        is_pushed[index] = True
    print("already offloaded!")
    

def offload_gtp_flow():
    # print("========== UPLINK ")
    # print(du_to_cu)
    # print(cu_to_cn)
    du_to_cu_keyset = set(du_to_cu.keys())
    cu_to_cn_keyset = set(cu_to_cn.keys())
    intersect_ul = du_to_cu_keyset.intersection(cu_to_cn_keyset)

    # print("========== DOWNLINK ")
    # print(cn_to_cu)
    # print(cu_to_du)
    cn_to_cu_keyset = set(cn_to_cu.keys())
    cu_to_du_keyset = set(cu_to_du.keys())
    intersect_dl = cn_to_cu_keyset.intersection(cu_to_du_keyset)
    # dl_keys = cn_to_cu.keys() + cu_to_du.keys()
    # dl_keys = list(set(dl_keys))

    print("========== PREPARING TO OFFLOAD ")
    # print(intersect_ul)
    # print(intersect_dl)
    intersect_ul = list(intersect_ul)
    intersect_dl = list(intersect_dl)
    for ul_key in intersect_ul:
        dl_key = ul_key[1], ul_key[0]
        if dl_key in intersect_dl:
            push_to_data_plane(ul_key, dl_key)

def cu_offload_callback(pkt):
    if is_gtp(pkt):
        if is_du_to_cu(pkt):
            print("========== FI-U UL ========== ")
            learn_du_to_cu(pkt)
        elif is_cu_to_cn(pkt):
            print("========== N3 UL ==========")
            learn_cu_to_cn(pkt)
        elif is_cn_to_cu(pkt):
            print("========== N3 DL ==========")
            learn_cn_to_cu(pkt)
        elif is_cu_to_du(pkt):
            print("========== F1-U DL ==========")
            learn_cu_to_du(pkt)
        else:
            print("Invalid")
        offload_gtp_flow()


if mode == "online":
    sniff(iface=net_intf, prn=cu_offload_callback, filter="udp", store=0)
elif mode == "offline":
    sniff(offline=net_intf, prn=cu_offload_callback, filter="udp", store=0)
