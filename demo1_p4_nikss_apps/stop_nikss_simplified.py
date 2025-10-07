import subprocess
import os
import json
import re

def run_cmd(cmd):
    print(f"\n--Running Command:\n{cmd}")
    process = subprocess.run(cmd.split(), text= True, stdout=subprocess.PIPE, stderr= subprocess.PIPE)
    if (process.returncode == 0):
        print('---Success\n')
        return process.returncode, process.stdout
    else:
        print(f'---Faild: {process.stderr}\n')
        return process.returncode, process.stderr

def del_ports(port_list):
    for port in port_list:
        cmd_add_port = f"nikss-ctl del-port pipe {NIKSS_PIPE_ID} dev {port}"
        res = run_cmd(cmd_add_port)
        print(res[1])

NIKSS_FILE_O = 'o_nikss_ue.o'
NIKSS_PIPE_ID = 0

PORTS = {
    'vx11_orin': None,
    'vx10_ran': None 
    }

delete_entries_tb1_command = 'nikss-ctl table delete pipe 0 ingress_tbl_ipv4_fwd'
delete_entries_tb2_command = 'nikss-ctl table delete pipe 0 ingress_tbl_d6g_fwd'
delete_entries_tb3_command = 'nikss-ctl table delete pipe 0 ingress_tbl_clock_sync'
delete_entries_tb4_command = 'nikss-ctl table delete pipe 0 ingress_tbl_clock_update'

stop_nikss_command = 'nikss-ctl pipeline unload id 0'

def main():
    result = run_cmd(delete_entries_tb1_command)
    result = run_cmd(delete_entries_tb2_command)
    result = run_cmd(delete_entries_tb3_command)
    result = run_cmd(delete_entries_tb4_command)
    
    del_ports(PORTS.keys())
    
    result = run_cmd(stop_nikss_command)
    
if __name__ == '__main__':
    main()