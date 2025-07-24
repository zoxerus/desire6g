port_add em0 100
register_write MyIngress.rg_output_port     1        100
register_write MyIngress.rg_output_port     2         2
table_add   MyIngress.tb_add_sdn_int_from_ipv4    MyIngress.ac_sdn_int_push   10.30.7.213/32 =>   100
table_add   MyIngress.tb_add_sdn_int_from_d6gmain   MyIngress.ac_sdn_int_push          10      =>  100
table_add   MyIngress.tb_add_sdn_int_from_d6gmain   MyIngress.ac_sdn_int_push          20      =>  200
table_add   MyIngress.tb_sdn_int_handler      MyIngress.ac_sdn_int_handle     100     =>      2
table_add   MyIngress.tb_sdn_int_handler            MyIngress.ac_sdn_int_pop        101     =>  500             1
table_add   MyIngress.tb_handle_inc                 MyIngress.ac_sdn_inc_update_register    1100    =>
