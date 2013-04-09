---
-- Port of ec_smtp dissector
--
--    Copyright (C) Ryan Linn and Mike Ryan
--
description = "An SMTP dissector"

local packet = require("packet")
local ffi = require("ettercap_ffi")
local ec_dissector = require('ettercap_dissector_c')

local void_ptr = ffi.typeof("void *")

dissector = function(session_magic, buf_ptr, buflen, len_ptr, po) 
  --
  --if po.DATA.len == 0 then
  --  return
  --end

  print("po type: " .. type(po))
  print("po void type: " .. type(ffi.cast(void_ptr, po)))

  --print("From server: " .. ec_dissector.from_server("smtp", ffi.cast(void_ptr, po)))
  --print("From client: " .. ec_dissector.from_client("smtp", ffi.cast(void_ptr, po)))
  print("From server: " .. ec_dissector.from_server("smtp", po))
  print("From client: " .. ec_dissector.from_client("smtp", po))

  --local packet_len = tonumber(po.DATA.len)
  --print("Packet length: " .. packet_len)
  --local buf = packet.read_data(po)
  --print("OMG I'm SMTP: " .. buf)
end

print "In SMTP"


