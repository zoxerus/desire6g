# This is the first switch in the SDN domain,
# we attach the input physical interface to it to process incoming packets
port_add em0 100

# Here we write the port numbers in the registers in order to
# Associate the labels to output ports through the table MyIngress.tb_sdn_int_handler
#                   Register Name         index  Output Port
register_write MyIngress.rg_output_port     1        100
register_write MyIngress.rg_output_port     2         2


# This Table is used to insert SDN label (if does not exist) based on teh ipv4 destination address
#                   Table Name                     Action Name              dest IPv4 LPM   Assigned label
table_add MyIngress.tb_add_sdn_int_from_ipv4    MyIngress.ac_sdn_int_push   10.30.7.213/32 =>   100



# This table handles the current packet using the SDN label and assigs it a register index to read from it the output port
#               Table Name                      Action Name              SDN Label    Register index
table_add MyIngress.tb_sdn_int_handler      MyIngress.ac_sdn_int_handle     100     =>      2


table_add MyIngress.tb_sdn_int_handler MyIngress.ac_sdn_int_pop 101 => 500 1
table_add MyIngress.tb_handle_inc MyIngress.ac_sdn_inc_update_register 1100 =>
table_add MyIngress.tb_add_sdn_int_from_d6gmain MyIngress.ac_sdn_int_push 10 => 100
table_add MyIngress.tb_add_sdn_int_from_d6gmain MyIngress.ac_sdn_int_push 20 => 200
