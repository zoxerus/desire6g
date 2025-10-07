#!/usr/bin/env python3
import argparse
import sys
import socket
import os
import random
import struct
import time
import threading

from scapy.all import sendp, get_if_list, bind_layers, sniff
from scapy.all import Packet, BitField
from scapy.all import Ether, IP, UDP, TCP, Raw, PacketListField

from datetime import datetime

from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS




# You can generate a Token from the "Tokens Tab" in the UI
token = "ICU4jyNRazt1z0KCgGLaskzh8tg4RQkWlrHvErFEI2xhlSEXKpXF9pWcehYuj1KF-fVelYR65eF25ab1be6Q4w=="
org = "sssa"
bucket = "d6g_demo_cscn"

client = InfluxDBClient(url="http://10.30.7.45:8086", token=token)

write_api = client.write_api(write_options=SYNCHRONOUS)


if len(sys.argv) < 2:
    print(f"usage: {sys.argv[0]} interface_name")
    exit()    


IFACE = sys.argv[1]


D6G_Timestamp_Size = 48

Max_Timestamp_Value = 2**D6G_Timestamp_Size - 1


class CLOCK_UPDATE(Packet):
    name= "CLOCK_UPDATE"
    fields_desc = [
        BitField(name='prop_delay', default= 0, size=32)
    ]
    
class CLOCK_SYNC(Packet):
    name= "CLOCK_SYNC"
    fields_desc = [
        BitField(name='count', default= 0, size=8),
        BitField(name='t0', default= 0, size=D6G_Timestamp_Size),
        BitField(name='t1', default= 0, size=D6G_Timestamp_Size),
        BitField(name='t2', default= 0, size=D6G_Timestamp_Size),
        BitField(name='t3', default= 0, size=D6G_Timestamp_Size)
    ]
    
 
#    def extract_padding(self, s):
#        return '', s

ETHERTYPE_CLOCK_SYNC = 0xBF02
ETHERTYPE_CLOCK_UPDATE = 0xBF03

bind_layers(Ether, CLOCK_SYNC, type= ETHERTYPE_CLOCK_SYNC)
bind_layers(Ether, CLOCK_UPDATE, type= ETHERTYPE_CLOCK_UPDATE)

propagation_delay = 4999999999;

def send_sync():
    while(True):
        try:
            time.sleep(1)
            paylod = "Clock_Synchronization_Packet"
            pkt = Ether(
                src='00:00:00:00:00:01', 
                dst='00:00:00:00:00:02', 
                type=ETHERTYPE_CLOCK_SYNC ) / CLOCK_SYNC(
                    count=0, t0= 0, t1=0, t2=0, t3=0) / paylod
            
            sendp(pkt, iface=IFACE, verbose=False)
            
        except: 
            pass


def send_update():
    pass


def format_number(n):
    n = float(n)
    if n >= 1_000_000_000:
        return f"{n / 1_000_000_000:.3f}s"
    elif n >= 1_000_000:
        return f"{n / 1_000_000:.3f}ms"
    elif n >= 1_000:
        return f"{n / 1_000:.3f}us"
    else:
        return f"{n}ns"

def receive_clock_tstamps(pkt):
    if (CLOCK_SYNC in pkt and pkt[CLOCK_SYNC].count == 4):
        try:
            pkt.show2()
            t0 = int( pkt[CLOCK_SYNC].t0 )
            t1 = int( pkt[CLOCK_SYNC].t1 )
            t2 = int( pkt[CLOCK_SYNC].t2 )
            t3 = int( pkt[CLOCK_SYNC].t3 )
            
            p_delay_tofino = 0
            p_delay_nikss = 0
            
            clock_diff_andata = 0 
            clock_diff_ritorno = 0
            
            p_delay_avg = 0 
            
            if (t3 < t1):
                p_delay_tofino =  abs(t3 + Max_Timestamp_Value - t1)//2
            else:
                p_delay_tofino =  abs(t3 - t1)//2
                
            if (t2 < t0):
                p_delay_nikss =  abs(t2 + Max_Timestamp_Value - t0)//2
                
            else:
                p_delay_nikss =  abs(t2 - t0)//2
            
            if (t1 < t0):
                clock_diff_andata = abs(t1 + Max_Timestamp_Value - t0)
            else:
                clock_diff_andata = abs(t1 - t0)

            if (t3 < t2):
                clock_diff_ritorno = abs(t3 + Max_Timestamp_Value - t2 )
            else:
                clock_diff_ritorno = abs(t3 - t2)
            
            
            difference_local =  abs(p_delay_nikss - p_delay_tofino) 
            difference_path =  abs(clock_diff_andata - clock_diff_ritorno)
           
            p_delay_avg = (p_delay_nikss + p_delay_tofino)//2
            
            write_api = client.write_api(write_options=SYNCHRONOUS)

            data = f"latency,sigment=ran latency={p_delay_avg//1000000}"
            write_api.write(bucket, org, data)
            
            clock_delta = (clock_diff_andata + clock_diff_ritorno)//2 + p_delay_avg//2
            
            if (t1 < t0):
                clock_diff_andata = abs(t1 + Max_Timestamp_Value - t0 - clock_delta)
            else:
                clock_diff_andata = abs(t1 - t0 - clock_delta)

            if (t3 < t2):
                clock_diff_ritorno = abs(t3 + Max_Timestamp_Value - t2 - clock_delta )
            else:
                clock_diff_ritorno = abs(t3 - t2 - clock_delta)
            
            
            
            print(f"p_delay_tofino       = {format_number(p_delay_tofino)}")
            print(f"p_delay_nikss        = {format_number(p_delay_nikss)}")
            print(f"dif_nikss_tofino     = {format_number(difference_local)}")
            print("---------------------------------------------------------")
            print(f"p_delay_andata       = {format_number(clock_diff_andata)}")
            print(f"p_delay_ritorno      = {format_number(clock_diff_ritorno)}")
            print(f"dif_andata_ritorno   = {format_number(difference_path)}")
            print("---------------------------------------------------------")
            print(f"clock_delta          = {format_number(clock_delta)}")
            print(f"p_delay_avg          = {format_number(p_delay_avg)}")
            

        except Exception as e:
            print(e)
        

def main():
    t1 = threading.Thread(target=send_sync)
    t2 = threading.Thread(target=send_update)
    t1.start()
    t2.start()
    sniff(iface = IFACE,
        prn = lambda x: receive_clock_tstamps(x), filter='')
    


if __name__ == '__main__':
    main()
