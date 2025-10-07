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

def add_ports(port_list) -> dict:
    returned_port_dict = {}
    for port in port_list:
        cmd_add_port = f"nikss-ctl add-port pipe {NIKSS_PIPE_ID} dev {port}"
        res = run_cmd(cmd_add_port)
        if res[0] == 0:
            try:
                json_str = re.search(r'\{.*\}', res[1], re.DOTALL).group()
                cmd_output_json = json.loads(json_str)
            except Exception as e:
                print(f"Error: {e}, Because of Result: {res}")
                cmd_del_port = f"nikss-ctl del-port pipe {NIKSS_PIPE_ID} dev {port}"
                run_cmd(cmd_del_port)
                exit()
            returned_port_dict[cmd_output_json['name']] = cmd_output_json['port_id']
        else:
            print(res[1])
            exit()
    return returned_port_dict

NIKSS_FILE_O = 'o_nikss_ue.o'
NIKSS_PIPE_ID = 0

PORTS = {
    'vx11_orin': None,
    'vx10_ran': None 
    }

ENTRIES = []

def generate_entrie():
    global ENTRIES
    ENTRIES = [
         "nikss-ctl table add pipe 0 ingress_tbl_ipv4_fwd action name ingress_do_add_d6g_header key 10.30.7.213/32 data 1000 0 0 1",
        f"nikss-ctl table add pipe 0 ingress_tbl_d6g_fwd action name ingress_do_forward_t1 key 1000 1 data {PORTS['vx10_ran']}",
        f"nikss-ctl table add pipe 0 ingress_tbl_d6g_fwd action name ingress_do_remove_d6g_header key 2000 2 data {PORTS['vx11_orin']}"
    ]

run_nikss_command = f'nikss-ctl pipeline load id 0 {NIKSS_FILE_O}'

def main():
    global PORTS, ENTRIES
    
    result = run_cmd(run_nikss_command)
    print(result[1])
    
    PORTS = add_ports(PORTS.keys())
    print(PORTS)
    
    generate_entrie()
    
    for entry in ENTRIES:
        result = run_cmd(entry)
        print(result[1])
    
if __name__ == '__main__':
    main()