#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#define ETTERCAP_LUA_MODULE "ettercap"
#define ETTERCAP_C_API_LUA_MODULE "ettercap_c"

#define LUA_FATAL_ERROR(x, ...) do { fprintf(stderr, x, ## __VA_ARGS__ ); exit(-1);} while(0)

lua_State * ec_lua_state();
