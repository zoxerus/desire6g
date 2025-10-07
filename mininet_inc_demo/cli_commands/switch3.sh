# Here we write the port numbers in the registers in order to
# Associate the labels to output ports through the table MyIngress.tb_sdn_int_handler
#                   Register Name         index  Output Port
register_write MyIngress.rg_output_port     1       4
register_write MyIngress.rg_output_port     2       1


# This table handles the current packet using the SDN label, ac_sdn_int_handle assigs it a register index to read from it the output port
#               Table Name                      Action Name              SDN Label    Register index
table_add MyIngress.tb_sdn_int_handler  MyIngress.ac_sdn_int_handle         100         => 1
table_add MyIngress.tb_sdn_int_handler  MyIngress.ac_sdn_int_handle         200         => 2