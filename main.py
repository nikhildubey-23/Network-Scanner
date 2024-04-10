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
        for send , received in slef.ans:
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

        
    
    



