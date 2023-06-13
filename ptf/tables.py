#!/usr/bin/env python3
import sys
import os
import argparse
import time
import scapy
from scapy.all import *

sde_install = os.environ['SDE_INSTALL']
sys.path.append('%s/lib/python2.7/site-packages/tofino'%(sde_install))
sys.path.append('%s/lib/python2.7/site-packages/p4testutils'%(sde_install))
sys.path.append('%s/lib/python2.7/site-packages'%(sde_install))


# Assumes valid PYTHONPATH
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

# For getting the dev_ports from the front panel ports itself
def get_devport(frontpanel, lane):
    port_hdl_info = bfrt_info.table_get("$PORT_HDL_INFO")
    key = port_hdl_info.make_key(
        [gc.KeyTuple("$CONN_ID", frontpanel), gc.KeyTuple("$CHNL_ID", lane)]
    )
    for data, _ in port_hdl_info.entry_get(target, [key], {"from_hw": False}):
        devport = data.to_dict()["$DEV_PORT"]
        if devport:
            return devport
        
# TODO: Need to modify the port logic here
port15 = get_devport(15, 0)
port16 = get_devport(16, 0)
print(port15)
print(port16)

port_tbl = bfrt_info.table_get("$PORT")

port_tbl_keys = [
    port_tbl.make_key([gc.KeyTuple("$DEV_PORT", port15)]),
    port_tbl.make_key([gc.KeyTuple("$DEV_PORT", port16)]),
]
port_tbl_data = [
    port_tbl.make_data(
        [
            gc.DataTuple("$SPEED", str_val="BF_SPEED_100G"),
            gc.DataTuple("$FEC", str_val="BF_FEC_TYP_NONE"),
            gc.DataTuple("$AUTO_NEGOTIATION", str_val="PM_AN_FORCE_DISABLE"),
            gc.DataTuple("$PORT_DIR", str_val="PM_PORT_DIR_DEFAULT"),
            gc.DataTuple("$PORT_ENABLE", bool_val=True),
        ]
    ),
    port_tbl.make_data(
        [
            gc.DataTuple("$SPEED", str_val="BF_SPEED_100G"),
            gc.DataTuple("$FEC", str_val="BF_FEC_TYP_NONE"),
            gc.DataTuple("$AUTO_NEGOTIATION", str_val="PM_AN_FORCE_DISABLE"),
            gc.DataTuple("$PORT_DIR", str_val="PM_PORT_DIR_DEFAULT"),
            gc.DataTuple("$PORT_ENABLE", bool_val=True),
        ]
    ),
]
port_tbl.entry_add(target, port_tbl_keys, port_tbl_data)
print("Added Ports")

forward = bfrt_info.table_get('pipe.Ingress.ipv4_forward')

# Add key fields
forward.info.key_field_annotation_add('hdr.ipv4.dst_addr','hdr.udp.dst_port')

# Create key
key = [forward.make_key([gc.KeyTuple("hdr.ipv4.dst_addr", "192.168.70.134"),gc.KeyTuple("hdr.udp.dst_port", 2153)])]


