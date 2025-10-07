# restart mmcli
sudo systemctl restart ModemManager


# set modes
sudo mmcli -m 0 --set-allowed-modes='4g,5g' --set-preferred-mode='5g'


# connect after beign registerd (state must be registered)
sudo mmcli -m 0 --set-allowed-modes='4g,5g' --set-preferred-mode='5g'

# set this thing 
cdc=$(ls /dev/cdc-* 2>/dev/null)


#
sudo qmicli --device=${cdc} --wds-set-autoconnect-settings=enabled,home-only
sudo qmicli --device=${cdc}  --set-expected-data-format=raw-ip


#
 sudo mmcli -m 0 --set-power-state-off