ibnt_protocol = Proto("INT",  "InBand Telemetry")

message_type = ProtoField.uint8("ibnt.message_type", "messageType", base.DEC)
original_protocol = ProtoField.uint8("ibnt.original_protocol", "originalProtocol", base.DEC)
delay_ran = ProtoField.uint64("ibnt.delay_ran", "delayRAN", base.DEC)
delay_pdp = ProtoField.uint64("ibnt.delay_pdp", "delayPDP", base.DEC)
path_id = ProtoField.uint32("ibnt.path_id", "pathId", base.DEC)


ibnt_protocol.fields = {message_type, original_protocol, delay_ran, delay_pdp, path_id}

function ibnt_protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end

  local type_number = buffer(0,1):uint()
  local type_name = get_message_type(type_number)
  
  pinfo.cols.protocol = ibnt_protocol.name .. " (".. type_name .. ")"

  local subtree = tree:add(ibnt_protocol, buffer(), "InBand Telemetry Data")
  


  subtree:add(message_type,      buffer(0,1)  ):append_text(" (".. type_name .. ")")
  subtree:add(original_protocol, buffer(1,1)  )
  subtree:add(delay_ran,         buffer(2,8)  )
  subtree:add(delay_pdp,         buffer(10,8) )
  subtree:add(path_id,           buffer(18,4) )
end

function get_message_type(type)
    local type_name = "Unknown"
  
        if type ==    0 then type_name = "INT_Report"
    elseif type ==    1 then type_name = "INT_Summary"
    end
  
    return type_name
  end



local ip_proto = DissectorTable.get("ip.proto")
ip_proto:add(253, ibnt_protocol)