-- D6G_MAIN Protocol Dissector for Wireshark
-- Save as d6g_main.lua and place in your Wireshark plugins directory

local d6g_proto = Proto("d6g_main", "D6G_MAIN Header")

-- Define fields
local f_serviceId   = ProtoField.uint16("d6g_main.serviceId",   "Service ID", base.HEX)
local f_locationId  = ProtoField.uint16("d6g_main.locationId",  "Location ID", base.HEX)
local f_hhFlag      = ProtoField.uint8 ("d6g_main.hhFlag",      "HH Flag", base.DEC, nil, 0x80) -- 1 bit (highest bit in byte)
local f_reserved    = ProtoField.uint8 ("d6g_main.reserved",    "Reserved", base.HEX, nil, 0x7F) -- 7 bits (lower 7 bits in byte)
local f_nextNF      = ProtoField.uint16("d6g_main.nextNF",      "Next NF", base.HEX)
local f_nextHeader  = ProtoField.uint16("d6g_main.nextHeader",  "Next Header", base.HEX)

d6g_proto.fields = {f_serviceId, f_locationId, f_hhFlag, f_reserved, f_nextNF, f_nextHeader}

function d6g_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "D6G_MAIN"
    local subtree = tree:add(d6g_proto, buffer(), "D6G_MAIN Header")

    subtree:add(f_serviceId,  buffer(0,2))
    subtree:add(f_locationId, buffer(2,2))
    -- The next byte contains hhFlag (1 bit, highest) and reserved (7 bits, lower)
    local hh_reserved = buffer(4,1):uint()
    subtree:add(f_hhFlag,    buffer(4,1))
    subtree:add(f_reserved,  buffer(4,1))
    subtree:add(f_nextNF,    buffer(5,2))
    subtree:add(f_nextHeader,buffer(7,2))
end

-- Register dissector for EtherType 0xd6d6
local ethertype_table = DissectorTable.get("ethertype")
ethertype_table:add(0xd6d6, d6g_proto)
