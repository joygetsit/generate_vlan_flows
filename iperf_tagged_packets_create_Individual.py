#!./venv/bin/python3

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

dstmac = '00:1b:21:c2:54:42'
Interface = 'enp1s0f0'

# PcapFileName='iperf_2_packets_Size_1000bytes_test2.pcap'

# Current Command to run: "./vlan_tagged_packets_create.py"

# To see fields,layers and fieldsizes, run scapy in terminal and
# call ls(IP()) for example
# 'ff:ff:ff:ff:ff:ff'


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


def make(PacketLength, VLAN_ID, Priority, UDPdstport, PcapFileName):
    iface = get_if(Interface)

    writetoPcap = PcapWriter(PcapFileName)  # opened file to write
    # PacketLength = 935 + 46 headers + 24 data = 1000 bytes
    payload_size = PacketLength - 73
    payload = ""
    while len(payload) < payload_size:
        payload += "test "

    for PacketIP_lastoctet in range(10, 20):
        for PacketSequenceNo in range(65536):

            # Content_data = sys.argv[2] + "; Packet Number " + str(pktnum + 1) + payload
            # Content_data = 'Packet Number ' + str(pktnum + 1) + ' ' + payload
            Packet_Content = 'Packet_Num_' + f'{PacketSequenceNo:012d}' + '_' + payload

            IP_src = '100.1.10.' + str(PacketIP_lastoctet)
            Packet = Ether(src=get_if_hwaddr(iface), dst=dstmac) / Dot1Q(prio=Priority, vlan=VLAN_ID) / IP(
                src=IP_src, id=PacketSequenceNo, proto=17) / UDP(sport=44444, dport=UDPdstport)
            # Can append id to Source IP address field of IP header also #IP(src=pktsequencenumber)
            Packet = Packet / Raw(load=Packet_Content)
            if (PacketSequenceNo in {0, 1}) and (PacketIP_lastoctet in {0, 1}):
                Packet.show2()

            # Write the packets to a pcap file, can be used with tcpreplay later
            writetoPcap.write(Packet)


def main():

    # Change the vlan tag to generate desired vlan tagged packet
    # Change the udp destination port to generate desired udp packet

    # PacketLength=1000
    Priority = 0
    VLAN_ID = 2
    UDPdstport = 3002
    for PacketLength in {1000}:
        PcapFileName='iperf_' + str(UDPdstport) + 'VLAN_' + str(VLAN_ID) + '_packets_Size_' + str(PacketLength) + 'B_test6.pcap'
        make(PacketLength, VLAN_ID, Priority, UDPdstport, PcapFileName)


    Priority = 1
    VLAN_ID = 3
    UDPdstport = 3003
    for PacketLength in {1000}:
        PcapFileName='iperf_' + str(UDPdstport) + 'VLAN_' + str(VLAN_ID) + '_packets_Size_' + str(PacketLength) + 'B_test6.pcap'
        make(PacketLength, VLAN_ID, Priority, UDPdstport, PcapFileName)


if __name__ == '__main__':
    main()
