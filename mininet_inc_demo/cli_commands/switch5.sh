# This is the first switch in the SDN domain,
# we attach the input physical interface to it to process incoming packets
port_add eth0 1
port_add eth1 4
table_add  MyIngress.tb_forward_packets MyIngress.ac_set_output_port 1 192.168.60.40/32 => 4
table_add  MyIngress.tb_forward_packets MyIngress.ac_set_output_port 1 192.168.70.40/32 => 4

table_add  MyIngress.tb_forward_packets MyIngress.ac_set_output_port 4 192.168.60.10/32 => 1
table_add  MyIngress.tb_forward_packets MyIngress.ac_set_output_port 4 192.168.70.10/32 => 1


      




