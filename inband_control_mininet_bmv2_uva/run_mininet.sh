#!/bin/bash
source ~/.bashrc
# get path to this sh file and change to it's directory so it can be called
# from any folder.
SCRIPT_PATH="${BASH_SOURCE[0]:-$0}";
cd "$( dirname -- "$SCRIPT_PATH"; )";

./compile.sh

PATH_CLI="/usr/bin/simple_switch_CLI"

PATH_BEHAVIORAL="/usr/bin/simple_switch"

# path to the network and collector siwtches
PATH_NETSW="./p4out/collector.json"


# clear the mininet cash
sudo mn -c


# commands for installing the flow rules to the switches.
# added a sleep 5 seconds to wait for the switches to boot up before installing
# the flow rules, varies with system performance.
gnome-terminal --tab -- bash -c "sleep 5; python3 $PATH_CLI --thrift-port 9091 < ./mininet/cli/commands.txt"

# start the relevant mininet
sudo python3 ./mininet/mynet.py --behavioral-exe "$PATH_BEHAVIORAL" --json-net "$PATH_NETSW"

