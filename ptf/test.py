# TODO
######### STANDARD MODULE IMPORTS ########
from __future__ import print_function
import unittest
import logging 
import grpc   
import pdb
from scapy.all import *

######### PTF modules for BFRuntime Client Library APIs #######
import importlib
import ptf
from ptf.testutils import *
from ptf.mask import *
from bfruntime_client_base_tests import BfRuntimeTest
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import bfrt_grpc.client as gc

####################### PTF modules for Fixed APIs (Thrift) #######################
import pd_base_tests
from ptf.thriftutils        import *
from res_pd_rpc.ttypes      import *   # Common data types
from mirror_pd_rpc.ttypes   import *   # Mirror-specific data types

########## Basic Initialization ############
class P4ProgramTest(BfRuntimeTest):
    # Establish connection to gRPC Bfrt server
    def setUp(self):
        self.client_id = 0
        self.p4_name   = test_param_get("cu", "")
        self.dev       = 0
        self.dev_tgt   = gc.Target(self.dev, pipe_id=0xFFFF)
        
        print(" n")
        print("Test Setup")
        print("==========")

        BfRuntimeTest.setUp(self, self.client_id, self.p4_name)
        
        self.bfrt_info = self.interface.bfrt_info_get()
        
        print("    Connected to Device: {}, Program: {}, ClientId: {}".format(
            self.dev, self.p4_name, self.client_id))

        # Create a list of all ports available on the device
        self.swports = []
        for (device, port, ifname) in ptf.config['interfaces']:
            self.swports.append(port)
        self.swports.sort()
        # print("Interfaces:", ptf.config['interfaces'])
        print("    SWPorts:", self.swports)

        # Understand what are we running on
        self.arch   = test_param_get('arch')
        self.target = test_param_get('target')

        if self.arch == 'tofino':
            self.dev_prefix = 'tf1'
            self.dev_config = {
                'num_pipes'         : 4,
                'eth_cpu_port_list' : [64, 65, 66, 67],
                'pcie_cpu_port'     : 320
            }
        elif self.arch == 'tofino2':
            self.dev_prefix = 'tf2'
            self.dev_config = {
                'num_pipes'         : 4,
                'eth_cpu_port_list' : [2, 3, 4, 5],  # TODO: Modify these
                'pcie_cpu_port'     : 0
            }
        
        # Not necessary just SDE and table checks
        try:
            self.dev_conf_tbl = self.bfrt_info.table_get('device_configuration')
            conf_tbl_prefix = self.dev_conf_tbl.info.name.split('.')[0]

            # Check that there is no mismatch
            if conf_tbl_prefix != self.dev_prefix:
                print("""
                      ERROR: You requested to run the test on '{}',
                             but the device {} only has '{}' tables in it.

                             Add '--arch {}' parameter to the command line.
                      """.format(self.dev_prefix,
                                 self.dev,
                                 conf_tbl_prefix,
                                 {'tf1':'tofino', 'tf2':'tofino2'}[
                                     conf_tbl_prefix]))
                self.assertTrue(False)
                quit()

            # Get the device configuration (default entry)
            resp = self.dev_conf_tbl.default_entry_get(self.dev_tgt)
            for data, _ in resp:
                self.dev_config = data.to_dict()
                break
        except KeyError:
            # Older SDE (before 9.5.0)
            pass
        
        # Get tables ready
        self.forward = self.bfrt_info.table_get("SwitchIngress.ipv4_forward")
        self.forward.info.key_field_annotation_add(
            "hdr.ipv4.dst_addr", "ipv4")
           
        self.uplink =  self.bfrt_info.table_get("SwitchIngress.fastpath_f1_to_n3")
        # self.downlink =  self.bfrt_info.table_get("Ingress.fastpath_n3_to_f1")

        self.tables = [self.forward, self.uplink 
                       #, self.downlink
                       ]
        
        # Optional, but highly recommended
        self.cleanUp()
        
        
    def tearDown(self):
        print("\n")
        print("Test TearDown:")
        print("==============")

        self.cleanUp()
        
        # Call the Parent tearDown
        BfRuntimeTest.tearDown(self)

    # Use Cleanup Method to clear the tables before and after the test starts
    # (the latter is done as a part of tearDown()
    def cleanUp(self):
        print("\n")
        print("Table Cleanup:")
        print("==============")

        try:
            for t in self.tables:
                print("  Clearing Table {}".format(t.info.name_get()))
                keys = []
                for (d, k) in t.entry_get(self.dev_tgt, [], {"from_hw": False}):
                    if k is not None:
                        keys.append(k)
                t.entry_del(self.dev_tgt, keys)
                # Not all tables support default entry
                try:
                    t.default_entry_reset(self.dev_tgt)
                except:
                    pass
        except Exception as e:
            print("Error cleaning up: {}".format(e))

#-------Table Programming----------
# Each entry is a tuple, consisting of 3 elements:
#  key         -- a list of tuples for each element of the key
#  action_name -- the action to use. Must use full name of the action
#  data        -- a list (may be empty) of the tuples for each action
#                 parameter
def programTable(table, entries, target, verbose=False):
        key_list=[]
        data_list=[]
        for k, a, d in entries:
            key_list.append(table.make_key([gc.KeyTuple(*f)   for f in k]))
            data_list.append(table.make_data([gc.DataTuple(*p) for p in d], a))
            if verbose:
                print("    Adding an entry to table {}: {} --> {}({})".format(
                    table.info.name_get(), k, a, d
                ))
        table.entry_add(target, key_list, data_list)
        if verbose:
            print("  Table programming completed for {}".format(table.info.name_get()))


#-------The main test----------
class CU(P4ProgramTest):
    def runTest(self):
        pcap_flow = rdpcap("../sample/study.pcap")

        # TODO change the ports
        ingress_port = 8
        egress_port  = 9
        cpu_port = 5
        
        print("\n")
        print("Adding table rules")
        print("========")
        
        programTable(self.forward, [
                    ([("hdr.ipv4.dst_addr", 0xc0a84690)],
                    "SwitchIngress.ipv4_forward_action", [("port", egress_port)]),
                    ([("hdr.ipv4.dst_addr", 0xc0a84686)],
                    "SwitchIngress.ipv4_forward_action", [("port", egress_port)])
                    ]        
                     , self.dev_tgt)

        programTable(self.uplink, [
                    ([("hdr.gtpu.teid", 0x301e8f18)],
                    "SwitchIngress.rewrite_f1_to_n3", [("teid", 0x01), 
                    ("qfi", 0x06)])]         
                     , self.dev_tgt)
        
        print("\n")
        print("Testing for DU to CU")
        print("========")
        
        # pkt = simple_udp_packet()
        send_pkt = pcap_flow[0]
    
        send_packet(self,ingress_port,send_pkt)

        expt_pkt = pcap_flow[1]
      
        print("Expected packet is: \n")
        hexdump(expt_pkt)
                # print("\n")
        # print("Adding table rules")
        # print("========")
        
        # programTable(self.forward, [
        #             ([("hdr.ipv4.dst_addr", "192.168.70.144")],
        #             "Ingress.ipv4_forward_action", [("port", egress_port)])]         
        #              , self.dev_tgt)

        # programTable(self.uplink, [
        #             ([("hdr.gtpu.teid", "0x301e8f18")],
        #             "Ingress.rewrite_f1_to_n3", [("teid", "0x01")], 
        #             [("qfi", "0x06")])]         
        #              , self.dev_tgt)
        
        # print("\n")
        # print("Testing for DU to CU")
        # print("========")
        
        expt_pkt = Mask(expt_pkt)
        
        expt_pkt.set_do_not_care_scapy(Ether, "dst")
        expt_pkt.set_do_not_care_scapy(Ether, "src")

        verify_packet(self, expt_pkt, egress_port)
        print("\nVerified Packet received on port %d" % egress_port)

        # Hard coded backup packets
        # send_pkt =  Ether(dst='02:42:C0:A8:46:90',
            #                  src='02:42:C0:A8:46:91')/ \
            #             IP(src='192.168.70.145',
            #               dst='192.168.70.144', ttl=64, ihl = 5)/ \
            #             UDP(sport=2153, dport=2153, len =103)/ \
            #             (0x30ff0057301e8f18816301450000549d404000400189360c010102c0a846870800f616000c000133fb626400000000a3a9090000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637)
                        
            # can compute the checksum using scapy
            # packet = IP(raw(packet))  # Build packet (automatically done when sending)
            # checksum_scapy = packet[UDP].chksum
        
        # expt_pkt = Ether(dst='02:42:C0:A8:46:86',
            #                  src='02:42:C0:A8:46:90')/ \
            #             IP(src='192.168.70.144',
            #               dst='192.168.70.134', ttl=64, ihl = 5)/ \
            #             UDP(sport=2152, dport=2152, len =108)/ \
            #             (0x34ff005c000000010000008501100600_450000549d404000400189360c010102c0a84687_0800f616000c000133fb626400000000a3a9090000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637)    
            
                        