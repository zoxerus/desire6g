from scapy.fields import BitField
from scapy.packet import Packet
from scapy.all import sniff, bind_layers, Ether

import sys
import os

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
    
bind_layers(Ether, SDN_INT, type=0x88b7)

def handle_pkt(pkt):
    pkt.show2()

    sys.stdout.flush()




if __name__ == '__main__':
    print(("sniffing on %s" % 'eth0'))
    sys.stdout.flush()
    # corr_thread = Thread(target=correlate_on_thread)
    # corr_thread.start()
    sniff(iface = 'eth0',
        prn = lambda x: handle_pkt(x), filter='')
    print('sniffin started')
