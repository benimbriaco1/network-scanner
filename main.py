# Packet manipulation
from scapy.all import ARP, Ether, srp

# Our target IP address, mask of /24
target_ip = "192.168.1.1/24"
# Create an ARP packet
arp = ARP(pdst=target_ip)

