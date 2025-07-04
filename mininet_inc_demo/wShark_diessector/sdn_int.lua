-- SDN_INT Protocol Dissector for Wireshark
-- Place this file in your Wireshark plugins directory and restart Wireshark

local sdn_int_proto = Proto("sdn_int", "SDN INT Header")

-- Define fields
local f_label    = ProtoField.uint16("sdn_int.sdn_label", "SDN Label", base.HEX)
local f_ethertype = ProtoField.uint16("sdn_int.original_ether_type", "Original EtherType", base.HEX)
local f_latency  = ProtoField.uint64("sdn_int.sdn_latency", "SDN Latency", base.DEC)

sdn_int_proto.fields = {f_label, f_ethertype, f_latency}

function sdn_int_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "SDN_INT"
    local subtree = tree:add(sdn_int_proto, buffer(), "SDN INT Header")
    subtree:add(f_label, buffer(0,2))
    subtree:add(f_ethertype, buffer(2,2))
    subtree:add(f_latency, buffer(4,6)) -- 48 bits = 6 bytes
end

-- Register dissector for EtherType 0x88b5
local ethertype_table = DissectorTable.get("ethertype")
ethertype_table:add(0x88b5, sdn_int_proto)
