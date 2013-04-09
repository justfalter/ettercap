#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#define ETTERCAP_DISSECTOR_C_API_LUA_MODULE "ettercap_dissector_c"

LUALIB_API int luaopen_ettercap_dissector_c(lua_State *L);
