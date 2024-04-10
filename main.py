#!/usr/bin/python3
#import necessary module
import socket
import scapy.all as scapy
import prettytable
from mac_vendor_lookup import MacLookup
from argparse import ArgumentParser
import sys
import struct

#class for network scanning
class Networkscanner:
    def __init__(self,host):
        #store the host to scan
        self.host=host
        #initialize an empty dictionary to store alive hosts
        self.alive={}
        #create an ARP packet for scanning
        self.create_packet()
        #send ARP packet to the host
        self.sendpacket()
        #get the alive hosts from the received responses
        self.getalive()
        #print the alive host
        self.printalive()
    #Method for creating APR packet
    def create_packet(self):
        #creating layer 1 (ethernet) and layer 2 (ARP)
        layer1 =scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
        layer2=scapy.ARP(pdst=self.host)
        #combine both the layers and store in self.packet
        self.packet=layer1 / layer2
    #Method to send the ARP packet and receive responses
    def sendpacket(self):
        #send the ARP packet and store the results in self.ans
        ans , unans = scapy.srp(self.packet,timeout=1,verbose=False)
        if ans:
            #set self.ans to the received responses if any
            self.ans=ans
        else:
            #print an error message and exit the program if no hosts are alive
            print("No Host Is Alive")
            sys.exit(1)
    #Method to get the alive hosts from the received responses
    def getalive(self):
        #iterate through the received responses
        for send , received in self.ans:
            #store mac address of the alive host in self.alive
            self.alive[received.psrc]=received.hwsrc
    #Method to print the alive hosts
    def printalive(self):
        #create a prettytbale object to store and display the results
        table = prettytable.PrettyTable(['IP','MAC','VENDOR'])
        #iterate through the alive hosts
        for ip , mac in self.alive.items():
            #try to lookup the mac address
            try:  
                #add the mac address and vendor to the prettytable  
                table.add_row([ip , mac , MacLookup.lookup(mac)])
            #catch any exception that may occur during the lookup
            except Exception as e:
                #print an error message and add the mac address and " unknown_vendor " to the prettytable
                print(f"Error looking up MAC {mac} : {e}")
                table.add_row([ip , mac , "Unknown Vendor"])
        #print the prettytable 
        print(table)
#Function for getting arguments form the command line         
def get_args():
    #create an ArgumentParser object
    parser = ArgumentParser(description='Network Scanner')
    #Add argument for start and end ip addresses
    parser.add_argument('--s',dest='start_ip',help='start Ip address in the format x.x.x.x')
    parser.add_argument('--e',dest='end_ip',help='End ip address in the formate x.x.x.x')
    #parse the arguments 
    args = parser.parse_args()
    #check if the start_ip address and end_ip address are provided 
    if not args.start_ip or not args.end_ip:
        #print help message and exit the program if start_ip or end_ip are not provided
        parser.print_help(sys.stderr)
        sys.exit(1)
    
    #convert start_ip and end_ip to long integers
    start_ip=socket.inet_aton(args.start_ip)
    end_ip = socket.inet_aton(args.end_ip)

    #unpack start_ip and end_ip as unsigned 32-bit
    start_ip_long = struct.unpack("!I",start_ip)[0]
    end_ip_long = struct.unpack("!I",end_ip)[0]

    #range(start_ip_long, end_ip_long + 1): This generates a sequence of numbers from start_ip_long to end_ip_long (inclusive).

    #struct.pack("!I", ip_long): This converts the integer ip_long to a 4-byte binary string, which represents the IP address in network byte order.

    #socket.inet_ntoa(binary_string): This converts the binary string to a dotted-decimal string, which represents the IP address in human-readable format.

    #[expression for variable in sequence]: This is a list comprehension, which generates a list of values by applying the expression to each variable in the sequence.
    hosts=[socket.inet_ntoa(struct.pack("!I",ip_long))for ip_long in range(start_ip_long, end_ip_long +1)]

    #So, the line hosts = [socket.inet_ntoa(struct.pack("!I", ip_long)) for ip_long in range(start_ip_long, end_ip_long + 1)] generates a list of IP addresses in the range from start_ip_long to end_ip_long (inclusive).
    
    return hosts

#calling the get_args()
hosts = get_args()
#creating object for class and providing the value as hosts
Networkscanner(hosts)




        
    
    



