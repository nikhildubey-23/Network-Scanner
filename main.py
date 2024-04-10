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

