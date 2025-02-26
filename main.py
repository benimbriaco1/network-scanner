# packet manipulation
from scapy.all import ARP, Ether, srp
# ip address validation
import ipaddress


# function for scanning IP and MAC given target IP and subnet
def network_scan(target_ip, choice):

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
    if choice.lower() == "n":
        print("Available devices on the network:")
        # " "*24 adds 24 spaces
        print("IP" + " "*18+"MAC")
        # iterate through to print
        for client in clients:
            # ensures client['ip'] is left aligned and takes up 16 characters
            print("{:16}    {}".format(client['ip'], client['mac']))
    elif choice.lower() =="s":
        print("Network searched")
        for client in clients:
            if client['ip'] == target_ip:
                # indicate success
                print("Match found.")
                print("{:16}    {}".format(client['ip'], client['mac']))
                return
        print("No matches found.")
        

def user_choice():
    # user options
    print("What functionality would you like to use? \n -n to scan a network for IPs and MAC \n -s to ", end ="")
    choice = input("scan a network for a single IP\n:").lower()

    # network
    if choice == "n":
        # call to function
        target_ip = input("Enter the network to scan: xxx.xxx.xxx.xxx/xx\n")
        if check_valid(target_ip, choice):
            # if valid, proceed
            network_scan(target_ip, choice)
        else:
            # error message
            print("Invalid input.")
    elif choice == "s":
        # same code, different prompt
        target_ip = input("Enter the network to scan: xxx.xxx.xxx.xxx/xx\n")
        if check_valid(target_ip, choice):
            # if valid, proceed
            network_scan(target_ip, choice)
        else:
            # error message
            print("Invalid input.")
    # wrong input
    else:
        print(f"argument not recognized: {choice}")

# make sure the user enters a valid IP address 
def check_valid(ip, choice):
    # using the ipaddress library to check if given address is valid
    if choice == "n":
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    elif choice == "s":
        try: 
            ipaddress.network(ip)
            return True
        except ValueError:
            return False

if __name__ == "__main__":
    user_choice()