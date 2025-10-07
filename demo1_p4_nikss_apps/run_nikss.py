import subprocess
import os
import json
import re


NIKSS_FILE_O = 'o_nikss_ue.o'
NIKSS_PIPE_ID = 0
NIKSS_PORT_NAMES = ['vxlan11', 'vxlan_to_ran']

def generate_nikss_table_entries(nikss_port_details: dict):
    entries = [
        {
            'ingress_tbl_ipv4_fwd': {
                'ingress_do_add_d6g_header' : [
                    {
                    'match_key': '10.30.7.213/32',
                    'action_data': f'{nikss_port_details[NIKSS_PORT_NAMES[1]]} 1000 0 0 1'
                    },
                    {
                    'match_key': '192.168.1.4/32',
                    'action_data': f'{nikss_port_details[NIKSS_PORT_NAMES[0]]} 2000 0 0 2'
                    }
                ]
            }
        }
    ]
    return entries


def check_if_running_as_sudo():
    if os.geteuid() == 0:
        pass
    else:
        print('This script must be run as sudo')
        exit()

def run_cmd(cmd):
    print(f"\n--Running Command:\n{cmd}\n")
    process = subprocess.Popen(cmd.split(), text= True, stdout=subprocess.PIPE, stderr= subprocess.PIPE)
    output, error = process.communicate()
    if (process.returncode == 0):
        return process.returncode, output
    else:
        return process.returncode, error
            
            
def load_nikss_pipeline_if_not_exists(pipe_id, nikss_file):
    cmd_load_pipe = f"nikss-ctl pipeline load id {pipe_id} {nikss_file}"
    res = run_cmd(cmd_load_pipe)
    if res[0] != 0:
        print(res[1])
        exit()
        
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

def add_table_entries(pipe_id, entry_list):
    for table_entry in entry_list:
        for table_name in table_entry.keys():
            for action_name in table_entry[table_name]:
                for entry in table_entry[table_name][action_name]:
                    add_entry_command = (
                        f"""nikss-ctl table add pipe {pipe_id} """
                        f"""{table_name} action name {action_name} """
                        f"""key {entry['match_key']} data {entry['action_data']}"""
                    )
                    res = run_cmd(add_entry_command)
                    if res[0] != 0:
                        print(res[1])
                        exit()
            

def main():
    check_if_running_as_sudo()
    load_nikss_pipeline_if_not_exists(pipe_id= NIKSS_PIPE_ID, nikss_file= NIKSS_FILE_O)
    ports_dict = add_ports(NIKSS_PORT_NAMES)
    table_entries = generate_nikss_table_entries(ports_dict)
    add_table_entries(pipe_id= NIKSS_PIPE_ID, entry_list= table_entries)
    pass



if __name__ == '__main__':
    main()