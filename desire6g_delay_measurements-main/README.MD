# Description
This folder contains latency measurements collected for software NIKSS P4 switch
for more info about the NIKSS switch refer to: https://github.com/NIKSS-vSwitch/nikss

the experiment is conducted as described in the figure shown in the file: dataset_collection_testbed.drawio.png

# Hardware used:

- Spirent SPT N4U TestCenter 
- Juniper M10i
- General Purpose Server running the NIKSS switch (CPU AMD EPYC 7262 8-core 3.4 GHz, 16 GB RAM)

# Methodology 
1- run traffic from the Spirent TestCenter from source port to destination port at various load levels with additional bursts.
2- traffic passes through the NIKSS switch (eBPF implementation running on the general purpose server)
3- NIKSS switch routes the traffic to the juniper router with 2Gbps uplink and 1Gbps download to induce congestion at the juniper router.
4- NIkSS then forwards the returning traffic from the Juniper router to the spirent destination port.
5- NIKSS switch measures the latency data through insertion In-band Network Telemetry.
5- the Spirent measures the end to end delay (includes queuing delay at the NIKSS and the Juniper)

# Results
results are reported in the file data_refined_visualized.ods with the raw data provided in the subfolder ./individual_data