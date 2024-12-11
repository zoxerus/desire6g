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
# parser.add_argument('--num-hosts', help='Number of hosts to connect to switch',
#                     type=int, action="store", default=2)
# parser.add_argument('--mode', choices=['l2', 'l3'], type=str, default='l3')
# parser.add_argument('--json-collector', help='Path to JSON config file',
#                     type=str, action="store", required=True)
parser.add_argument('--json-netswitch', help='Path to JSON config file',
                    type=str, action="store", required=True)
parser.add_argument('--pcap-dump', help='Dump packets on interfaces to pcap files',
                    type=str, action="store", required=False, default=False)
parser.add_argument('--debugger', help='Enable Debugger',
                    type=str, action="store", required=False, default=False)
parser.add_argument('--log-level', help="Set log level, values are:'trace','debug',                      +\
                                    'info', 'warn', 'error', 'off', default is 'info' ",
                                    type = str,action='store', required=False, default='info')
args = parser.parse_args()


class MyTopo(Topo):
    "Single switch connected to n (< 256) hosts."
    def __init__(self, sw_path, 
                #  json_collector,
                 json_netswitch, thrift_port, pcap_dump, enable_debugger, **opts):
        # Initialize topology and  default options
        Topo.__init__(self, **opts)

        s1 = self.addSwitch('s1',
                                sw_path = sw_path,
                                json_path = json_netswitch,
                                thrift_port = 9091,
                                pcap_dump = pcap_dump,
                                enable_debugger = enable_debugger
                                )
        

        # s2 = self.addSwitch('s2',
        #                         sw_path = sw_path,
        #                         json_path = json_netswitch,
        #                         thrift_port = 9092,
        #                         pcap_dump = pcap_dump,
        #                         enable_debugger = enable_debugger
        #                         )
        


        # s2 = self.addSwitch('s2',
        #                         sw_path = sw_path,
        #                         json_path = json_netswitch,
        #                         thrift_port = 9092,
        #                         pcap_dump = pcap_dump,
        #                         enable_debugger = enable_debugger
        #                         )
        # s3 = self.addSwitch('s3',
        #                         sw_path = sw_path,
        #                         json_path = json_netswitch,
        #                         thrift_port = 9093,
        #                         pcap_dump = pcap_dump,
        #                         enable_debugger = enable_debugger
        #                         )

        h11 = self.addHost('h11',
                            ip = "10.0.0.11/24",
                            # mac = '9e:81:b6:de:5e:a9',
                            mac = '00:00:00:00:00:11',
                            commands = ["route add default gw 10.0.0.1 dev eth0",
                            "arp -i eth0 -s 10.0.0.1 00:00:00:00:00:01"])
        

        h12 = self.addHost('h12',
                            ip = '10.0.0.12/24',
                            # mac = 'ce:e4:06:07:7e:fb',
                            mac = '00:00:00:00:00:12',
                            commands = ["route add default gw 10.0.0.2 dev eth0",
                            "arp -i eth0 -s 10.0.0.2 00:00:00:00:00:02"])
        

        # h21 = self.addHost('h21',
        #             ip = '10.0.10.21/24',
        #             # mac = 'ce:e4:06:07:7e:fb',
        #             mac = '56:1E:10:00:20:21',
        #             commands = ["route add default gw 10.0.10.1 dev eth0",
        #             "arp -i eth0 -s 10.0.10.1 56:1E:10:00:20:01"])
        
        # h22 = self.addHost('h22',
        #             ip = '10.0.10.22/24',
        #             # mac = 'ce:e4:06:07:7e:fb',
        #             mac = '56:1E:10:00:20:22',
        #             commands = ["route add default gw 10.0.10.1 dev eth0",
        #             "arp -i eth0 -s 10.0.10.1 56:1E:10:00:20:02"])
        

        # h3 = self.addHost('h3',
        #                     ip = "10.0.31.10/24",
        #                     mac = '56:1E:10:00:31:10',
        #                     commands = ["route add default gw 10.0.31.1 dev eth0",
        #                     "arp -i eth0 -s 10.0.31.1 56:1E:10:00:31:01"])


        # self.addLink(s0, s1, 1, 1)
        # self.addLink(s0, s2, 2, 1)
        # self.addLink(s0, s3, 3, 1)
        # self.addLink(s1, s2, 2, 2)
        # self.addLink(s2, s3, 3, 2)

        self.addLink(s1, h11, 1, 0)
        self.addLink(s1, h12, 2, 0)

        # self.addLink(s2, h21, 1, 0)
        # self.addLink(s2, h22, 2, 0)

        # self.addLink(s1, s2 , 3, 3)




def main():
    # num_hosts = args.num_hosts
    # mode = args.mode

    topo = MyTopo(args.behavioral_exe,
                            # args.json_collector,
                            args.json_netswitch,
                            args.thrift_port,
                            args.pcap_dump,
                            args.debugger
                            )
    
    net = Mininet(topo = topo,
                  host = P4Host,
                  switch = P4Switch,
                  link=TCLink,
                  controller = None)

    #net.addNAT().configDefault()
    net.start()

    # s0 = net.get('s0')
    # s0.setMAC('56:1E:10:10:00:01', intf = 's0-eth1')
    # s0.setMAC('56:1E:10:20:00:01', intf = 's0-eth2')
    # s0.setMAC('56:1E:10:30:00:01', intf = 's0-eth3')
    #s0.setMAC('20:1a:06:4e:99:fb', intf = 'enp1s0f0')

    # s0.setIP('10.10.0.1/30', intf='s0-eth1')
    # s0.setIP('10.20.0.1/30', intf='s0-eth2')
    # s0.setIP('10.30.0.1/30', intf='s0-eth3')
    #s0.setIP('10.30.2.173/32', intf='enp1s0f0')

    s1 = net.get('s1')
    # s1.setMAC('56:1E:10:00:10:01', intf = 's1-eth1')
    # s1.setMAC('56:1E:10:00:10:02', intf = 's1-eth2')
    # s1.setMAC('5e:e6:73:dc:b3:67', intf = 's1-eth1')
    # s1.setMAC('d2:3d:00:2a:d2:02', intf = 's1-eth2')

    # s1.setIP('10.0.10.1/30', intf = 's1-eth1')
    # s1.setIP('10.0.10.1/30', intf = 's1-eth2')
    # s1.setIP('10.0.11.1/24', intf = 's1-eth1')
    # s1.setIP('10.0.12.1/24', intf = 's1-eth2')




    # s2 = net.get('s2')
    # s2.setMAC('56:1E:10:20:00:02', intf = 's2-eth1')
    # s2.setMAC('56:1E:10:12:00:02', intf = 's2-eth2')
    # s2.setMAC('56:1E:10:23:00:01', intf = 's2-eth3')

    # s2.setIP('10.20.0.2/30', intf = 's2-eth1')
    # s2.setIP('10.12.0.2/30', intf = 's2-eth2')
    # s2.setIP('10.23.0.1/30', intf = 's2-eth3')

    # s3 = net.get('s3')
    # s3.setMAC('56:1E:10:30:00:02', intf = 's3-eth1')
    # s3.setMAC('56:1E:10:23:00:02', intf = 's3-eth2')
    # s3.setMAC('56:1E:10:00:31:01', intf = 's3-eth3')

    # s3.setIP('10.30.0.2/30', intf = 's3-eth1')
    # s3.setIP('10.23.0.2/30', intf = 's3-eth2')
    # s3.setIP('10.0.31.1/24', intf = 's3-eth3')

    print('\n')

    h11 = net.get('h11')
    h11.setARP('10.0.0.1', '00:00:00:00:00:01')
    h11.setDefaultRoute("dev eth0 via %s" % '10.0.0.1')
    h11.describe()


    h12 = net.get('h12')
    h12.setARP('10.0.0.2', '00:00:00:00:00:02')
    h12.setDefaultRoute("dev eth0 via %s" % '10.0.0.2')
    h12.describe()

    # h21 = net.get('h21')
    # h21.setARP('10.0.10.1', '56:1E:10:00:20:01')
    # h21.setDefaultRoute("dev eth0 via %s" % '10.0.10.1')
    # h21.describe()


    # h22 = net.get('h22')
    # h22.setARP('10.0.10.1', '56:1E:10:00:20:02')
    # h22.setDefaultRoute("dev eth0 via %s" % '10.0.10.1')
    # h22.describe()

    print('\n')
    # h3 = net.get('h3')
    # h3.setARP('10.0.31.1', '56:1E:10:00:31:01')
    # h3.setDefaultRoute("dev eth0 via %s" % '10.0.31.1')
    # h3.describe()

    print("Ready !")

    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    main()
