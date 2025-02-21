# packet manipulation
from scapy.all import ARP, Ether, srp

# our target IP address, mask of /24
target_ip = "192.168.1.1/24"

# create an ARP packet
arp = ARP(pdst=target_ip)

# creating the ethernet broadcast packet
ether = Ether(dst="ff:ff:ff:ff:ff:ff")

# stacking the two packets using /
packet = ether/arp

# srp() is used to send and receive packets at layer 2 
# timeout of 3 seconds to avoid getting stuck
# srp() returns a tuple of (ans, unans), answered and unanswered packets
# using [0] to only retreieve unanswered packets
# ans and unans are lists of pairs in the format (sent_packet, received_packet)
result=srp(packet,timeout=3)[0]

# list of our clients
clients = []
# iteration to fill the above list
for sent, received in result:
    # appending our recived values
    # .psrc is the source IP of the response
    # .hwsrc is source MAC of response
    # using a dictionary with key value pairs to add
    clients.append({'ip': received.psrc, 'mac': received.hwsrc})

print(clients)