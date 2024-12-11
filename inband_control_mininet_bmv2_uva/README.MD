# Description
This is an implementation of the In-band dataplane Control to respond to congestions in the network.
It aims to speed up the process of responding to congestions in the network switches.
It works by receiving an aggregated In-band Network Telemetry report from the switches in the network, it reads the report and instructs the switch at which the congestion has happened to go over the backup path.
In this repository there are these folders:<br/>
**/mininet** &emsp; this folder contains a mininet with one switch and two hosts to test the functionality of the collector.
            it works by sending a simulated INT report from one of the hosts to the other, this report is detected by the P4 switch, which then responds with the configuration message.

**/p4src**   &emsp; inside this folder there is the source code of the P4 controller 

# Requirements
#### 1. To compile the file "/p4src/collector.p4" need to have the p4c compiler.
#### 2. To run the mininet, need to have the bmv2 software switch.
&emsp; for ubuntu 20.04 and higher, both packages are availalbe and can be installed by running:
```
. /etc/os-release
echo "deb http://download.opensuse.org/repositories/home:/p4lang/xUbuntu_${VERSION_ID}/ /" | sudo tee /etc/apt/sources.list.d/home:p4lang.list
curl -fsSL "https://download.opensuse.org/repositories/home:p4lang/xUbuntu_${VERSION_ID}/Release.key" | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/home_p4lang.gpg > /dev/null
sudo apt update
sudo apt install p4lang-bmv2
```
&emsp; Otherwise consult the repositories: <br/>
- https://github.com/p4lang/p4c
- https://github.com/p4lang/behavioral-model

#### 3. to run the mininet, need to have mininet installed consult https://mininet.org/download/
#### 4. need to have python3 installed 
#### 5. need to have scapy installed https://scapy.readthedocs.io/en/latest/installation.html

# Running the mininet:

1. compie the /mininet/collector.p4 file, by running the bash script `compile.sh`.
2. run the mininet by running the bash script `run_mininet.sh`
3. test the implementation by running the python files inside xterms in the mininet hosts.
from the mininet cli run `xterm h11 h12`
4. in one of the hosts xterm run the pyhton script `/mininet/test_implementation/send.py`.
5. in the other host's xterm run the python script `/mininet/test_implementation/receive.py`.
6. the cli commands to populate  the tables in the p4 switch can be found in `/mininet/cli/commands.txt`
7. check the `/p4src/collector.p4` for further details.

# How it works
the p4 program has three tables: `ipv4_lpm`, `check_congestion` and `inband_reroute`.
`ipv4_lpm` is used to froward normal data packets to their destination it matches packets on the destination IP header field. it has one action `ipv4_forward` that takes two parameters `dst_mac` and `port` which is the index of the output interface.

the `check_congestion` matches on the `count` field of the received telemetry report, this `count` field indicates the number of switches that inserted their telemetry data into the report. the table has 5 actions to check congestion at up to five switches. and convert the congestion detected into a bit map.

the table `inband_reroute` checks the bitmap returned by the table `check_congestion` and it has the action `trigger_forward` that is responsible for generating the control message that is sent to the switch where the path needs to be rerouted.