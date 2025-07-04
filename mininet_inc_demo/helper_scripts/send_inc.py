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


ETHERTYPE_INT = 1550
ETHERTYPE_INC = 1551

# class INT_MD(Packet):
#     name = 'INT_MD'
#     fields_desc = [
#         BitField(name='Label',              default=0, size=16),
#         BitField(name='Original_EtherType', default=0, size=16),
#         BitField(name='Latency',            default=0, size=48)
#     ]    

#     # def extract_padding(self, s):
#     #     return '', s



# class INT_CTRL(Packet):
#     name = 'INT_CTRL'
#     fields_desc = [
#         BitField(name='Label',                       default=0, size=16),
#         BitField(name='Register_index',              default=0, size=32),
#         BitField(name='Output_Port',                 default=0, size=16),
#     ]    

#     # def extract_padding(self, s):
#     #     return '', s






# class Q_REPORT(Packet):
#     name = 'q_report'
#     fields_desc = [
#         BitField(name='switch____id', default=5, size=16),
#         BitField(name='queue_length', default=7, size=24),
#         BitField(name='queue__delay', default=11, size=32)
#     ]    
    
#     def extract_padding(self, s):
#         return '', s



# class INT_AGG(Packet):
#     name = "q_reports"
#     fields_desc = [
#         PacketListField('aggregated_reports', None, Q_REPORT, count_from= lambda x: 5)
#     ]


# class INT_TRIGGER(Packet):
#     name = 'INT_TRIGGER'
#     fields_desc = [
#         BitField(name='Switch_ID', default=1, size=16),
#         BitField(name='Backup_Port', default=1, size=8)
#     ]




# pkt =  Ether(src='00:00:00:00:00:11', dst='00:00:00:00:00:12', type=1501)
# report= INT_REPORT()
# q_report1 = Q_REPORT(switch____id=100, queue_length=20)
# q_report2 = Q_REPORT(switch____id=200, queue_length=20)
# q_report3 = Q_REPORT(switch____id=300, queue_length=100)
# q_report4 = Q_REPORT(switch____id=400, queue_length=20)
# q_report5 = Q_REPORT(switch____id=500, queue_length=20)
# pkt = pkt/report/q_report1/q_report2/q_report3/q_report4/q_report5

# bind_layers(IP, UDP)

# bind_layers(INT_MD, IP, Original_EtherType=2048)


# bind_layers(Ether, INT_MD, type=ETHERTYPE_INT)

# bind_layers(Ether, INT_CTRL, type=ETHERTYPE_INC)

# bind_layers(INT_MD, IP)


# with open("delay.txt", "r") as file:
#     numbers = [int(line.strip()) for line in file]  # Convert to integers


# latency = 3*(921 + random.randint(0,241) ) + numbers[0]

# ether_inc = Ether(src='00:00:00:00:00:11', 
#              dst='00:00:00:00:00:22', 
#              type=ETHERTYPE_INT)

# ether_nml = Ether(src='00:00:00:00:00:11', 
#              dst='00:00:00:00:00:22', 
#              type=2048)

# int_md = INT_MD(Label=1, Original_EtherType=2048, Latency=latency)


# ipv4 = IP(src='10.0.0.1', dst='10.0.0.2', proto=17, len=54)
# udp = UDP(sport= 50001, dport=50002, len=34)

# payload = Raw(load="Hello There You Other Host")



# pkt =  ether_inc/int_md/ipv4/udp/payload

# pkt2 =  ether_nml/ipv4/udp/payload


# ether_nml.show2()
# ipv4.show2()
# udp.show2()
# payload.show2()




def get_if():
    ifaces = os.listdir('/sys/class/net/')
    iface = ''
    for i in ifaces:
        if 'eth0' in i:
            iface = i
    return iface

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

class SDN_INT(Packet):
    name= "SDN_INT"
    fields_desc = [
        BitField(name='sdn_label', default= 0, size=16),
        BitField(name='original_ether_type', default= 0, size=16),
        BitField(name='sdn_latency', default= 0, size=48)
    ]

"""
/*  */
header sdn_inc_t {
    bit<16> sdn_label;
    bit<9> register_index;
    bit<3> _reserved1;
    bit<9> output_port;
    bit<3> _reserved2;
}

"""


class SDN_INC(Packet):
    name= "SDN_INC"
    fields_desc = [
        BitField(name='sdn_label', default= 0, size=16),
        BitField(name='register_index', default= 0, size=9),
        BitField(name='_reserved1', default= 0, size=3),
        BitField(name='output_port', default= 0, size=9),
        BitField(name='_reserved2', default= 0, size=3)
    ]
    
    
    
    
def main():
    eth = Ether(src='00:00:00:00:00:01', dst='00:00:00:00:00:04', type = 0x88b6)
    inc = SDN_INC(sdn_label= 1100, register_index=1, output_port=3)
    # d6g = D6G_MAIN(serviceId=10, nextHeader=0x0800)
    # ip = IP(src='10.0.0.1', dst='10.0.0.4', proto=17)
    # udp = UDP(sport = 50001, dport= 50004)
    # payload = 'Hello H4 from H1'    
    pkt = eth/inc
    

    sendp(pkt, iface='eth0', verbose=False)
    print("\n\nsent\n\n")


if __name__ == '__main__':
    main()
