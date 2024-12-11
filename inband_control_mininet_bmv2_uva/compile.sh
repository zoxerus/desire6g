#!/bin/bash
source ~/.bashrc
# get path to this sh file and change to it's directory so it can be called
# from any folder.
SCRIPT_PATH="${BASH_SOURCE[0]:-$0}";
cd "$( dirname -- "$SCRIPT_PATH"; )";

sudo rm ./p4out/*

p4c --target bmv2 --arch v1model --std p4-16 --output ./p4out ./p4src/collector.p4

