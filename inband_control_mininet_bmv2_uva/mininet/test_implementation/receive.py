#!/usr/bin/env python3
import sys
import struct
import os

from socket import *
from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Raw, Ether, PacketListField
from scapy.layers.inet import _IPOption_HDR


class INT_REPORT(Packet):
    name = 'INT_REPORT'
    fields_desc = [
        # BitField(name='kind', default=1, size=8),
        # BitField(name='length', default=2, size=8),
        
        BitField(name='init_ttl', default=3, size=8),
        BitField(name='switch_id', default=5, size=16),
        BitField(name='hop_num', default=7, size=8),
        BitField(name='trust_swid', default=11, size=16),
        BitField(name='trust_level', default=13, size=4),
        BitField(name='count', default=5, size=16),
        BitField(name='padding', default=0, size=12),
    ]    
    

class Q_REPORT(Packet):
    name = 'Q_REPORT'
    fields_desc = [
        BitField(name='switch____id', default=5, size=16),
        BitField(name='queue_length', default=7, size=24),
        BitField(name='queue__delay', default=11, size=32)
    ]    
    
    def extract_padding(self, s):
        return '', s



class INT_AGG(Packet):
    name = "INT_AGG"
    fields_desc = [
        PacketListField('aggregated_reports', None, Q_REPORT, count_from= lambda x: 5)
    ]


class INT_TRIGGER(Packet):
    name = 'INT_TRIGGER'
    fields_desc = [
        BitField(name='Switch_ID', default=1, size=16),
        BitField(name='Backup_Port', default=1, size=8)
    ]

pkt_in = 0

def handle_pkt(pkt):
    if (INT_REPORT in pkt):
        global pkt_in
        pkt_in = pkt_in + 1
        print('Packet in: {}'.format(pkt_in))
        print("-------------- New Packet --------------")
        pkt.show2()
        
        # get int data from received packet.
        data = pkt[INT_AGG]

        # print the int data
        data.show2()

        for congestion_report in data.aggregated_reports:
            print("report")
            congestion_report.show2()

        print('-------------- end --------------\n')
    elif INT_TRIGGER in pkt:
        pkt.show2()
        
        
    sys.stdout.flush()



def main():
    bind_layers(Ether, INT_REPORT, type=1501)
    bind_layers(INT_REPORT, INT_AGG, padding=0)
    bind_layers(Ether, INT_TRIGGER, type=1502)
    
    iface = "eth0"
    print(("sniffing on %s" % iface))
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))
if __name__ == '__main__':
    main()
