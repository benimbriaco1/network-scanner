# packet manipulation
from scapy.all import ARP, Ether, srp

# function for scanning IP and MAC given target IP and subnet
def network_scan():
    target_ip = input("Enter the network to scan: xxx.xxx.xxx.xxx/xx\n")

    # create an ARP packet
    # pdst = protocol destination address
    arp = ARP(pdst=target_ip)

    # creating the ethernet broadcast packet
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    # stacking the two packets using /
    # here we are encapsulating arp packet within ethernet frame
    packet = ether/arp

    # srp() is used to send and receive packets at layer 2 
    # timeout of 3 seconds to avoid getting stuck
    # srp() returns a tuple of (ans, unans), answered and unanswered packets
    # using [0] to only retreieve unanswered packets
    # ans and unans are lists of pairs in the format (sent_packet, received_packet)
    result=srp(packet,timeout=0.5)[0]

    # list of our clients
    clients = []
    # iteration to fill the above list
    for sent, received in result:
        # appending our recived values
        # .psrc is the source IP of the response
        # .hwsrc is source MAC of response
        # using a dictionary with key value pairs to add
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

    # formatting
    print("Available devices on the network:")
    # " "*24 adds 24 spaces
    print("IP" + " "*18+"MAC")
    # iterate through to print
    for client in clients:
        # ensures client['ip'] is left aligned and takes up 16 characters
        print("{:16}    {}".format(client['ip'], client['mac']))

# checking for a specific ip
def ip_match():
    pass

def user_choice():
    # user options
    choice = input('''What functionality would you like to use? \n -n to scan a network for IPs and MAC \n -s to 
    scan a network for a single match''')

    # network
    if choice.lower() == "n":
        # call to function
        network_scan()
    elif choice.lower() == "s":
        # call to function
        ip_match()


if __name__ == "__main__":
    user_choice()
