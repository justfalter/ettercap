---
-- Dissector handling.
--
--    Copyright (C) Ryan Linn and Mike Ryan
--
--

dissector = {}

ettercap = require("ettercap")
ettercap_dissector_c = require("ettercap_dissector_c")

local ettercap_ffi = require("ettercap_ffi")

-- Dissector interface
--
-- All Ettercap LUA scripts are initialized using a common interface. We've 
-- modeled this interface very closely after that of NMAP's NSE script 
-- interface. Our hope is that the community's familiarity with NSE will 
-- lower the barrier for entry for those looking to write Ettercap LUA 
-- scripts.
--
--
--  Data structures:
--    packet_object - Access to the Ettercap "packet_object" (originally 
--                    defined in include/ec_packet.h) is provided via a 
--                    light luajit FFI wrapper. Details on interacting with 
--                    data-types via luajit FFI can be found here:
--                    http://luajit.org/ext_ffi_semantics.html. 
--
--                    Generally, script implementations should avoid direct
--                    modifications to packet_object, or any FFI wrapped 
--                    structure, instead favoring modification through 
--                    defined ettercap.* interfaces.
--
--                    NOTE: Careful consideration must be taken to when 
--                    interacting with FFI-wrapped data-structures! Data 
--                    originating from outside of the LUA VM must have their
--                    memory managed *manually*! See the section of luajit's
--                    FFI Semantics on "Garbage Collection of cdata Objects"
--                    for details. 
--                    
--
--  Dissector requirements:
--
--    description - (string) Like that of NSE, each script must have a 
--                  description of the its functionality.
--

local packet_object_ctype = ettercap_ffi.typeof("struct packet_object *")
local ffi_cast = ettercap_ffi.cast

local create_dissect_func = function(dissector)
  local orig_dissector_func = dissector.dissector_func
  local dissect_func = function(session_magic, buf_ptr, buflen, len_ptr, packet_object_ptr) 
    print("po orig type: " .. type(packet_object_ptr))
    orig_dissector_func(session_magic, buf_ptr, buflen, len_ptr, ffi_cast(packet_object_ctype, packet_object_ptr))
    --orig_dissector_func(session_magic, buf_ptr, buflen, len_ptr,  packet_object_ptr)
  end
  return(dissect_func)
end

local Dissector = {}

do
  local coroutine = require "coroutine";
  local debug = require "debug";
  local traceback = debug.traceback;

  local REQUIRED_FIELDS = {
    description = "string",
    dissector = "function"
  };

  function Dissector.new (name)
    local full_path = ETTERCAP_LUA_DISSECTOR_PATH .. "/" .. name .. ".lua";
    local file_closure = assert(loadfile(full_path));

    local env = {
      DISSECTOR_PATH = full_path,
      DISSECTOR_NAME = name
    };

    -- No idea what this does.
    setmetatable(env, {__index = _G});
    setfenv(file_closure, env);

    local co = coroutine.create(file_closure); -- Create a garbage thread
    local status, e = coroutine.resume(co); -- Get the globals it loads in env

    if not status then
      ettercap.log("Failed to load %s:\n%s", name, traceback(co, e));
      return nil
    end

    for required_field_name in pairs(REQUIRED_FIELDS) do
      local required_type = REQUIRED_FIELDS[required_field_name];
      local raw_field = rawget(env, required_field_name)
      local actual_type = type(raw_field);
      assert(actual_type == required_type, 
             "Incorrect of missing field: '" .. required_field_name .. "'." ..
             " Must be of type: '" .. required_type .. "'" ..
             " got type: '" .. actual_type .. "'"
      );
    end

    local dissector = {
      name = name,
      env = env,
      dissector_func = env["dissector"],
      file_closure = file_closure,
    };
    setmetatable(dissector, {__index = Dissector, __metatable = Dissector});
    ettercap_dissector_c.register_dissector(name, create_dissect_func(dissector))
    return dissector
  end
end

local init_dissector = function (name)
  local dissector = Dissector.new(name)
end

dissector.init_dissector = init_dissector

return dissector
