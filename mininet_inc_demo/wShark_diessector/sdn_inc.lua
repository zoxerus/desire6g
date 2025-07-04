-- SDN_INC Protocol Dissector for Wireshark
-- Save as sdn_inc.lua and place in your Wireshark plugins directory

-- 1. Define the protocol
local sdn_inc_proto = Proto("sdn_inc", "SDN INC Header")

-- 2. Define the protocol's fields
local f_sdn_label      = ProtoField.uint16("sdn_inc.sdn_label", "SDN Label", base.HEX)
local f_register_index = ProtoField.uint16("sdn_inc.register_index", "Register Index", base.DEC)
local f_reserved1      = ProtoField.uint8("sdn_inc.reserved1", "Reserved 1", base.HEX)
local f_output_port    = ProtoField.uint16("sdn_inc.output_port", "Output Port", base.DEC)
local f_reserved2      = ProtoField.uint8("sdn_inc.reserved2", "Reserved 2", base.HEX)

sdn_inc_proto.fields = { f_sdn_label, f_register_index, f_reserved1, f_output_port, f_reserved2 }

-- 3. Create the dissector function
function sdn_inc_proto.dissector(buffer, pinfo, tree)
    -- Set the protocol column in Wireshark's packet list
    pinfo.cols.protocol = "SDN_INC"

    -- Create the main subtree for our protocol
    local subtree = tree:add(sdn_inc_proto, buffer(), "SDN INC Header")

    -- Add the simple byte-aligned field first
    subtree:add(f_sdn_label, buffer(0, 2))

    -- The remaining fields are not byte-aligned, so we handle them with bitwise logic.
    -- The next 24 bits (3 bytes) contain the rest of the fields.
    -- We can read these 3 bytes as a 24-bit integer.
    local packed_fields = buffer(2, 3):uint()

    -- Extract each field using bit32.extract(number, start_bit, num_bits)
    -- Note: Bits are counted from the right (least significant), starting at 0.
    -- Total bits = 24. Layout: [reg_idx(9)][res1(3)][out_port(9)][res2(3)]
    local register_index = bit32.extract(packed_fields, 15, 9) -- Bits 15-23
    local reserved1      = bit32.extract(packed_fields, 12, 3) -- Bits 12-14
    local output_port    = bit32.extract(packed_fields, 3,  9) -- Bits 3-11
    local reserved2      = bit32.extract(packed_fields, 0,  3) -- Bits 0-2

    -- Add the extracted bitfields to the tree.
    -- We add them as "expert" fields, which is good practice for derived values.
    subtree:add_expert_info(PI_GENERATED, PI_CHAT, "Register Index: " .. register_index)
    subtree:add_expert_info(PI_GENERATED, PI_CHAT, "Output Port: " .. output_port)

    -- It can also be useful to show the raw bytes containing these fields.
    local bitfield_subtree = subtree:add(buffer(2,3), "Packed Bitfields")
    bitfield_subtree:add(f_register_index, buffer(2,2)) -- Highlight the bytes it's in
    bitfield_subtree:add(f_reserved1, buffer(3,1))
    bitfield_subtree:add(f_output_port, buffer(3,2))
    bitfield_subtree:add(f_reserved2, buffer(4,1))
end

-- 4. Register the dissector with Wireshark
-- We tell Wireshark to use this dissector for any packet with EtherType 0x88b6
local ethertype_table = DissectorTable.get("ethertype")
ethertype_table:add(0x88b6, sdn_inc_proto)
