Basic Network Sniffer
 	Overview
•	This code is a basic network packet sniffer written in Python using the Scapy library. It captures and analyzes network packets, printing out relevant
information about each packet. This can be helpful for understanding network traffic, troubleshooting network issues, or developing network-based
applications.

 	“Scapy” Features
1.Packet capturing: sniff() function
2.Packet dissection: Accessing packet layers (e.g., packet[Ether])
3.Layer identification: Checking for specific layers (e.g., if Ether in packet)
4.Accessing packet fields: Extracting information from packet layers (e.g., eth_layer.src, ip_layer.dst)

 	Installation
•	Install the required dependencies: pip install scapy
•	Install Npcap: Visit Npcap website and download an appropriate installer for your system. Run the installer and follows the given instructions.

 	Usage
•	Run the Basic Network Sniffer script: BasicNetworkSniffer.py

This script will start captures and analyzes network packets, printing out information about each packet's layers (Ethernet, IP, TCP, and UDP).





