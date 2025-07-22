register_write MyIngress.rg_output_port 1 4
register_write MyIngress.rg_output_port 2 1
table_add MyIngress.tb_sdn_int_handler MyIngress.ac_sdn_int_handle 100 => 1
table_add MyIngress.tb_sdn_int_handler MyIngress.ac_sdn_int_handle 101 => 2
table_add MyIngress.tb_handle_inc MyIngress.ac_sdn_inc_forward 1100 => 2