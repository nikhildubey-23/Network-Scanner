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



