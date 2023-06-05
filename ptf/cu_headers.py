from scapy.all import *

class gtp(Packet):
    name = "GTP header"
    fields_desc = [
       ShortField("hdr_total_len", 0),
       ShortField("pkt_length", 0),
   ]