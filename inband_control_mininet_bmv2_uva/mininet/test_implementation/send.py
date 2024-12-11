#!/usr/bin/env python3
import argparse
import sys
import socket
import random
import struct
import time

from scapy.all import sendp, get_if_list, bind_layers
from scapy.all import Packet, BitField
from scapy.all import Ether, IP, UDP, TCP, PacketListField

class INT_REPORT(Packet):
    name = 'int_report'
    fields_desc = [
        # BitField(name='kind', default=1, size=8),
        # BitField(name='length', default=2, size=8),
        
        BitField(name='init_ttl', default=3, size=8),
        BitField(name='switch_id', default=5, size=16),
        BitField(name='hop_num', default=7, size=8),
        BitField(name='trust_swid', default=11, size=16),
        BitField(name='trust_level', default=13, size=4),
        BitField(name='count', default=5, size=16),
        BitField(name='Pudding', default=0, size=12),
    ]    
    
    def extract_padding(self, s):
        return '', s

class Q_REPORT(Packet):
    name = 'q_report'
    fields_desc = [
        BitField(name='switch____id', default=5, size=16),
        BitField(name='queue_length', default=7, size=24),
        BitField(name='queue__delay', default=11, size=32)
    ]    
    
    def extract_padding(self, s):
        return '', s



class INT_AGG(Packet):
    name = "q_reports"
    fields_desc = [
        PacketListField('aggregated_reports', None, Q_REPORT, count_from= lambda x: 5)
    ]


class INT_TRIGGER(Packet):
    name = 'INT_TRIGGER'
    fields_desc = [
        BitField(name='Switch_ID', default=1, size=16),
        BitField(name='Backup_Port', default=1, size=8)
    ]




pkt =  Ether(src='00:00:00:00:00:11', dst='00:00:00:00:00:12', type=1501)
report= INT_REPORT()
q_report1 = Q_REPORT(switch____id=100, queue_length=20)
q_report2 = Q_REPORT(switch____id=200, queue_length=20)
q_report3 = Q_REPORT(switch____id=300, queue_length=100)
q_report4 = Q_REPORT(switch____id=400, queue_length=20)
q_report5 = Q_REPORT(switch____id=500, queue_length=20)
pkt = pkt/report/q_report1/q_report2/q_report3/q_report4/q_report5


def get_if():
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def main():
    bind_layers(Ether, INT_REPORT, type=1501)
    bind_layers(Ether, INT_TRIGGER, type=1502)
    iface = get_if()
    print(("sending on interface %s" % (iface)))
    sendp(pkt, iface=iface, verbose=False)
    print("\rSent 1 Packets")
    print("")


if __name__ == '__main__':
    main()
