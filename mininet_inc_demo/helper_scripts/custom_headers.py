from scapy.fields import BitField
from scapy.packet import Packet

class D6G_MAIN(Packet):
    name = "D6G_MAIN"
    field_desc = [
        BitField(name='serviceId', size = 16),
        BitField(name='locationId', size=16),
        BitField(name='hhFlag', size = 1),
        BitField(name='_reserved', size = 7),
        BitField(name='nextNF', size = 16),
        BitField(name='nextHeader', size=16)
    ]   

class SDN_INT(Packet):
    name= "SDN_INT"
    field_desc = [
        BitField(name='sdn_label', size=16),
        BitField(name='original_ether_type', size=16),
        BitField(name='sdn_latency', size=48)
    ]