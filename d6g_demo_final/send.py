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


if len(sys.argv) < 4:
    print(f"usage: {sys.argv[0]} interface_name serviceId nextNF")
    exit()    


IFACE = sys.argv[1]
SERVICE_ID = int(sys.argv[2])
NEXT_NF = int(sys.argv[3])


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



def main():
    eth = Ether(src='00:00:00:00:11:11', dst='00:00:00:00:22:22', type = ETHERTYPE_D6GMAIN)
    d6g = D6G_MAIN(serviceId= SERVICE_ID, nextNF= NEXT_NF, nextHeader=ETHERTYPE_D6GINT)
    d6gint = D6G_INT(nextHeader=0x0800, t2=55, t1=99)
    ip = IP(src='10.0.0.1', dst='10.0.0.2', proto=17)
    udp = UDP(sport = 50001, dport= 50004)
    payload = 'Hello H4 from H1'
    pkt = eth/d6g/d6gint/ip/udp/payload


    sendp(pkt, iface=IFACE, verbose=False)
    print("\n\nsent\n\n")
    pkt.show2()


if __name__ == '__main__':
    main()
