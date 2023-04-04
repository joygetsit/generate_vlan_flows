#!/usr/bin/env python3

# Date: Oct 2022
# Author: Deepak Choudhary and Joydeep Pal
# Description: This script creates a custom IP packet with VLAN tags.
# You can fill in VLAN IDs, PCP (Priority Code Point), 
# and maybe add seqeunce numbers to a particular header field.
# Modified Date: Dec 2022
# Modified Date: Feb 2023

import argparse
import sys
import socket
import random
import struct

from scapy.sendrecv import sendp, send
from scapy.all import get_if_list, get_if_hwaddr
from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.inet import IP, UDP, TCP
from scapy.packet import Raw
from scapy.utils import PcapWriter
# from scapy.all import *
import time

# DataSize = 935 + 38 headers + 27 data = 1000 bytes
# Command to run: "./vlan_tagged_packets_create.py"

# To see fields,layers and fieldsizes, run scapy in terminal and
# call ls(IP()) for example
# 'ff:ff:ff:ff:ff:ff'

dstmac='00:1b:21:c2:54:42'
def get_if(interface):
    iface = None
    for i in get_if_list():
        if interface in i:
            iface = i
            break
    if not iface:
        print("Cannot find interface ", interface)
        exit(1)
    return iface


def main():
    #if len(sys.argv) < 2:
    #if len(sys.argv) < 4:
        #print('pass 3 arguments: <destination> <message> <Number of packets>')
        #print('pass 1 argument: <destination>')
        #exit(1)
    iface = get_if('enp1s0f0')

    writetoPcap = PcapWriter('Mixed_VLAN_pkts2.pcap')  # opened file to write
    
    # Can be used to change the size of the packet
    payload_size=935
    payload=""
    while len(payload) < payload_size:
        payload += "test "
        
    for PktIP_lastoctet in range(200):
        # for pktnum in range(int(sys.argv[3])):
        for PktSeqNo in range(65536):
            
            # Content_data = sys.argv[2] + "; Packet Number " + str(pktnum + 1) + payload
            # Content_data = 'Packet Number ' + str(pktnum + 1) + ' ' + payload
            Content_data = 'Packet_Number_' + f'{PktSeqNo:012d}' + '_' + payload
            # Change the vlan tag to generate desired vlan tagged packet
            IPsrc_as_pktsequencenumber = '15.15.15.' + str(PktIP_lastoctet)
            # pktsequencenumber = pktnum
            pkt_vlan2 = Ether(src=get_if_hwaddr(iface), dst=dstmac) / Dot1Q(vlan=2) / IP(src=IPsrc_as_pktsequencenumber, id=PktSeqNo, proto=253)
            pkt_vlan3 = Ether(src=get_if_hwaddr(iface), dst=dstmac) / Dot1Q(vlan=3) / IP(src=IPsrc_as_pktsequencenumber, id=PktSeqNo, proto=253)
            # Can append id to Source IP address field of IP header also #IP(src=pktsequencenumber)
            pkt_vlan2 = pkt_vlan2 / Raw(load=Content_data)
            pkt_vlan3 = pkt_vlan3 / Raw(load=Content_data)
            if (PktSeqNo in {0,1}) and (PktIP_lastoctet in {0,1}):
                pkt_vlan2.show2()
                pkt_vlan3.show2()
            # Write the packets to a pcap file, can be used with tcpreplay later
            writetoPcap.write(pkt_vlan2)
            writetoPcap.write(pkt_vlan3)


if __name__ == '__main__':
    main()
