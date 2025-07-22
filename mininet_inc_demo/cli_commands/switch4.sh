port_add em1 100
register_write MyIngress.rg_output_port 1 100
register_write MyIngress.rg_output_port 2 2
table_add MyIngress.tb_add_sdn_int_from_ipv4 MyIngress.ac_sdn_int_push 10.45.0.2/32 => 101
table_add MyIngress.tb_sdn_int_handler MyIngress.ac_sdn_int_handle 101 => 2
table_add MyIngress.tb_sdn_int_handler MyIngress.ac_sdn_int_pop 100 => 500 1
table_add MyIngress.tb_handle_inc MyIngress.ac_sdn_inc_forward 1100 => 2