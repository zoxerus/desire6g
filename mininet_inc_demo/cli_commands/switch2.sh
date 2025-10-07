# Here we write the port numbers in the registers in order to
# Associate the labels to output ports through the table MyIngress.tb_sdn_int_handler
#                   Register Name         index  Output Port
register_write MyIngress.rg_output_port     1       4
register_write MyIngress.rg_output_port     2       1


# This table handles the current packet using the SDN label, ac_sdn_int_handle assigs it a register index to read from it the output port
#               Table Name                      Action Name              SDN Label    Register index
table_add MyIngress.tb_sdn_int_handler MyIngress.ac_sdn_int_handle          100         => 1
table_add MyIngress.tb_sdn_int_handler MyIngress.ac_sdn_int_handle          200         => 2


# tb_handle_inc matches the label of the incoming inband control packet,
# ac_sdn_forward: takes a register index and reads the output port from it 
#               Table Name                 Action Name            SDN Label  Registter Index
table_add MyIngress.tb_handle_inc   MyIngress.ac_sdn_inc_forward    200        => 2