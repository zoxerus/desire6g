#!/usr/bin/env python3
# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.link import TCLink

from p4_mininet import P4Switch, P4Host

import argparse
from time import sleep


parser = argparse.ArgumentParser(description='Mininet demo')
parser.add_argument('--behavioral-exe', help='Path to behavioral executable',
                    type=str, action="store", required = True)
parser.add_argument('--thrift-port', help='Thrift server port for table updates',
                    type=int, action="store", default=9090)

parser.add_argument('--json-collector', help='Path to JSON config file',
                    type=str, action="store", required=True)

parser.add_argument('--json-bmv2-cudu', help='Path to JSON config file',
                    type=str, action="store", required=True)

parser.add_argument('--json-netswitch', help='Path to JSON config file',
                    type=str, action="store", required=True)
parser.add_argument('--pcap-dump', help='Dump packets on interfaces to pcap files',
                    type=str, action="store", required=False, default=False)
parser.add_argument('--debugger', help='Enable Debugger',
                    type=str, action="store", required=False, default=False)
parser.add_argument('--log-level', help="Set log level, vales are:'trace','debug',                      +\
                                    'info', 'warn', 'error', 'off', default is 'info' ",
                                    type = str,action='store', required=False, default='info')
args = parser.parse_args()


class MyTopo(Topo):
    "Single switch connected to n (< 256) hosts."
    def __init__(self, sw_path, 
                 json_collector,
                 json_netswitch,
                 json_bmv2_cudu, 
                 thrift_port, pcap_dump, enable_debugger, **opts):
        # Initialize topology and  default options
        Topo.__init__(self, **opts)
        
        
        s100 = self.addSwitch('s100',
                                sw_path = sw_path,
                                json_path = json_bmv2_cudu,
                                thrift_port = 59100,
                                pcap_dump = pcap_dump,
                                enable_debugger = enable_debugger
                                )
        
        s101 = self.addSwitch('s101',
                                sw_path = sw_path,
                                json_path = json_bmv2_cudu,
                                thrift_port = 59101,
                                pcap_dump = pcap_dump,
                                enable_debugger = enable_debugger
                                )

        s1 = self.addSwitch('s1',
                                sw_path = sw_path,
                                json_path = json_netswitch,
                                thrift_port = 59001,
                                pcap_dump = pcap_dump,
                                enable_debugger = enable_debugger
                                )
        
        
        s2 = self.addSwitch('s2',
                                sw_path = sw_path,
                                json_path = json_netswitch,
                                thrift_port = 59002,
                                pcap_dump = pcap_dump,
                                enable_debugger = enable_debugger
                                )

        s3 = self.addSwitch('s3',
                            sw_path = sw_path,
                            json_path = json_netswitch,
                            thrift_port = 59003,
                            pcap_dump = pcap_dump,
                            enable_debugger = enable_debugger
                            )
        
        s4 = self.addSwitch('s4',
                            sw_path = sw_path,
                            json_path = json_netswitch,
                            thrift_port = 59004,
                            pcap_dump = pcap_dump,
                            enable_debugger = enable_debugger
                            )


        # h1 = self.addHost('h1',
        #                     ip = "10.0.0.1/24",
        #                     mac = '00:00:00:00:00:01')
        
        
        # h4 = self.addHost('h4',
        #                     ip = "10.0.0.4/24",
        #                     mac = '00:00:00:00:00:04')
        
        
        # h5 = self.addHost('h5',
        #             ip = "10.0.0.5/24",
        #             mac = '00:00:00:00:00:05')

        # self.addLink(s1, h1, 1, 0)
        # self.addLink(s4, h4, 4, 0)
        # self.addLink(s4, h5, 5, 0)
        
        # TOPOLOGY
        #     [S3]
        #     /  \
        #  [S1]  [S4]
        #     \  /
        #     [S2]

        self.addLink(s100, s101, 2, 1)
        self.addLink(s100, s101, 3, 2)
        self.addLink(s101, s3, 33, 33)
        
        self.addLink(s1, s2, 2, 1)
        self.addLink(s2, s4, 4, 2)
        self.addLink(s1, s3, 3, 1)
        self.addLink(s3, s4, 4, 3)
        
def main():

    topo = MyTopo( sw_path         = args.behavioral_exe,
                   json_collector  = args.json_collector,
                   json_netswitch  = args.json_netswitch,
                   json_bmv2_cudu  = args.json_bmv2_cudu,
                   thrift_port     = args.thrift_port,
                   pcap_dump       = args.pcap_dump,
                   enable_debugger = args.debugger
                   )
    
    net = Mininet(topo = topo,
                  host = P4Host,
                  switch = P4Switch,
                  link=TCLink,
                  controller = None)
    net.staticArp()

    print('Starting Mininet')
    net.start()

    # h1 = net.get('h1')
    # h1.setDefaultRoute("dev eth0")
    # h1.describe()

    # h4 = net.get('h4')
    # h4.setDefaultRoute("dev eth0 ")
    # h4.describe()    
    
    
    print('\n')

    print("Ready !")

    CLI( net )
    net.stop()


print(__name__)

if __name__ == '__main__':
    print('STARTING')
    print(__name__)
    setLogLevel( 'info' )
    main()
else:
    print('__name__ is not main')
