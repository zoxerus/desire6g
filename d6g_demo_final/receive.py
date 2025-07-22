#!/usr/bin/env python3
import argparse
import sys
import socket
import os
import random
import struct
import time

from scapy.all import sendp, get_if_list, bind_layers
from scapy.all import Packet, BitField
from scapy.all import Ether, IP, UDP, TCP, Raw, PacketListField
from scapy.all import sniff, bind_layers, Ether


if len(sys.argv) < 2:
    print(f"usage: {sys.argv[0]} interface_name")
    exit()    

iface = sys.argv[1]

class D6G_MAIN(Packet):
    name = "D6G_MAIN"
    fields_desc = [
        BitField(name='serviceId', default= 0, size = 16),
        BitField(name='locationId', default= 0, size=16),
        BitField(name='hhFlag', default= 0, size = 1),
        BitField(name='_reserved', default= 0, size = 7),
        BitField(name='nextNF', default= 0, size = 16),
        BitField(name='nextHeader', default= 0, size=16)
    ]

#    def extract_padding(self, s):
#        return '', s

class D6G_INT(Packet):
    name= "D6G_INT"
    fields_desc = [
        BitField(name='nextHeader', default= 0, size=16),
        BitField(name='t1', default= 0, size=48),
        BitField(name='t2', default= 0, size=48),
        BitField(name='t3', default= 0, size=48)
    ]
#    def extract_padding(self, s):
#        return '', s

ETHERTYPE_D6GMAIN = 0xD6D6
ETHERTYPE_D6GINT = 0xDF01

bind_layers(Ether, D6G_MAIN, type= ETHERTYPE_D6GMAIN)
bind_layers(D6G_MAIN, D6G_INT, nextHeader = ETHERTYPE_D6GINT)
bind_layers(D6G_INT, IP, nextHeader = 0x0800)
bind_layers(D6G_MAIN, IP, nextHeader = 0x0800)



def handle_pkt(pkt):
    if(D6G_MAIN in pkt):
        pkt.show2()

    sys.stdout.flush()
    
def main():
    print(("sniffing on %s" % iface))
    sys.stdout.flush()
    sniff(iface = iface,
        prn = lambda x: handle_pkt(x), filter='')
    print('sniffin started')


if __name__ == '__main__':
    main()
