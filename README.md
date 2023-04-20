# Description
A CLI-based packet flow generator written in Python using the Scapy module. Generate multiple distinct traffic flows with uniquely identifiable packets. Uses VLAN IDs, priority (PCP field of VLAN header) and UDP destination ports for identification. Uses multiple CPU cores to generate flows parallely.

![License](https://img.shields.io/badge/License-BSD_3--Clause-blue.svg)

# Installation
Step 1: Modify python script and provide a list of vlan ID, packet size
Step 2: Run with ./'filename'.py

Separate PCAP files are generated for each combination. These pcap files can be used with network tools like tcpreplay to transmit packet flows.
