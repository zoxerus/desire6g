# we attach the input physical interface to it to process incoming and outgoing packets
# to the SDN domain
port_add em1 100



# Here we write the port numbers in the registers in order to
# Associate the labels to output ports through the table MyIngress.tb_sdn_int_handler
#                   Register Name         index  Output Port
register_write MyIngress.rg_output_port     1       100
register_write MyIngress.rg_output_port     2       2








# This Table is used to insert SDN label (if does not exist) based on teh ipv4 destination address
#                   Table Name                     Action Name              dest IPv4 LPM   Assigned label
table_add MyIngress.tb_add_sdn_int_from_ipv4    MyIngress.ac_sdn_int_push   10.45.0.2/32        => 101


# This table handles the current packet using the SDN label, ac_sdn_int_handle assigs it a register index to read from it the output port
#               Table Name                      Action Name              SDN Label    Register index
table_add MyIngress.tb_sdn_int_handler  MyIngress.ac_sdn_int_handle         101             => 2



# This table # This table handles the current packet using the SDN label, ac_sdn_int pop: removes the SDN label and sends the report
# to the collector using the clone session, while reading the output port of the original packet form the Register indicated by the index
#               Table Name                     Action Name         SDN Label   Clone Session  Register index
table_add MyIngress.tb_sdn_int_handler  MyIngress.ac_sdn_int_pop      100       => 500              1


# tb_handle_inc matches the label of the incoming inband control packet,
# ac_sdn_forward: takes a register index and reads the output port from it 
#               Table Name                 Action Name            SDN Label  Registter Index
table_add MyIngress.tb_handle_inc MyIngress.ac_sdn_inc_forward      1100        => 2