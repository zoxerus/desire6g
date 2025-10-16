port_add eth0 1
port_add eth1 4
table_add  MyIngress.tb_forward_packets MyIngress.ac_set_output_port 1 50:7c:6f:57:6c:b0&&&FFFFFFFFFFFF => 4 100
table_add  MyIngress.tb_forward_packets MyIngress.ac_set_output_port 1 d2:f3:57:16:2d:08&&&FFFFFFFFFFFF => 2 100
table_add  MyIngress.tb_forward_packets MyIngress.ac_set_output_port 3 d2:f3:57:16:2d:08&&&FFFFFFFFFFFF => 4 100

table_add  MyIngress.tb_forward_packets MyIngress.ac_set_output_port 4 00:00:00:00:00:00&&&000000000000 => 1 100



      




