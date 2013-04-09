#include <ec.h>
#include <ec_file.h>
#include <ec_decode.h>
#include <ec_dissect.h>
#include <ec_session.h>
#include <ec_lua.h>
#include <ec_lua_main.h>
#include <ec_lua_dissector.h>

struct lua_dissector_list {
  char * name;
  size_t name_len;
  int func_ref;
  SLIST_ENTRY(lua_dissector_list) next;
};

SLIST_HEAD(, lua_dissector_list) lua_dissector_table;

void ec_lua_dispatch_dissector(void * dissector_info, void * session_magic, FUNC_DECODER_ARGS)
{
   struct lua_dissector_list *lua_dissector_entry = (struct lua_dissector_list *) dissector_info;

   int err_code;
   lua_State * state = ec_lua_state();

   // Don't have to do anything if we don't have a state.
   if (state == NULL)
     return;

   lua_rawgeti(state, LUA_REGISTRYINDEX, lua_dissector_entry->func_ref);
   lua_pushlightuserdata(state, (void *) session_magic);
   lua_pushlightuserdata(state, (void *) DECODE_DATA);
   lua_pushinteger(state, DECODE_DATALEN);
   lua_pushlightuserdata(state, (void *) &(DECODED_LEN));
   lua_pushlightuserdata(state, (void *) PACKET);
   err_code = lua_pcall(state,5,0,0);
   if (err_code != 0) {
     LUA_FATAL_ERROR("EC_LUA ec_lua_dispatch_dissector Failed. Error %d: %s\n", 
          err_code, lua_tostring(state, -1));
   }

   return;
}


void * ec_lua_get_dissector(const char * name)
{
  struct lua_dissector_list *lua_dissector_entry;
  lua_State * state = ec_lua_state();

  // Don't have to do anything if we don't have a state.
  if (state == NULL)
    return NULL;


  SLIST_FOREACH(lua_dissector_entry, &lua_dissector_table, next) {
    if (strcmp(name, lua_dissector_entry->name) == 0) {
      return (void*) lua_dissector_entry;
    }
  }

  return NULL;
}

// Dissector API

// Registers the name of a dissector ('smtp') to a lua function.
static int l_register_dissector(lua_State* state)
{
  struct lua_dissector_list *lua_dissector_entry;
  SAFE_CALLOC(lua_dissector_entry, 1, sizeof(struct lua_dissector_list));

  size_t temp_str_len;
  const char * temp_str = lua_tolstring(state, 1, &temp_str_len);

  if(temp_str_len < 1)
      LUA_FATAL_ERROR("FATAL: EC_LUA_DISSECTOR: Dissector name cannot be empty.\n");

  SAFE_CALLOC(lua_dissector_entry->name, temp_str_len, sizeof(char));
  strncpy(lua_dissector_entry->name, temp_str, temp_str_len);

  // Set the top of the stack to point to the function.
  lua_settop(state, 2);
  
  int r = luaL_ref(state, LUA_REGISTRYINDEX);
  if(r == LUA_REFNIL)
      LUA_FATAL_ERROR("FATAL: EC_LUA_DISSECTOR: Attempted to register nil dissector for '%s'!\n", lua_dissector_entry->name);

  // Show a reference to the function into the registry.
  lua_dissector_entry->func_ref = r;


  SLIST_INSERT_HEAD(&lua_dissector_table, lua_dissector_entry, next);
  return 0;
}

static int l_from_server(lua_State* state)
{
  char * name = (char *) lua_tostring(state, 1);
  struct packet_object * po = (struct packet_object *) lua_topointer(state, 2);

  if (name == NULL) {
    printf("Missing name\n");
    lua_pushinteger(state, 0);
    return 1;
  }
  if (po == NULL) {
    printf("Missing packet\n");
    lua_pushinteger(state, 0);
    return 1;
  }


  int ret = FROM_SERVER(name, po);
  printf("from server (%s)? %d\n", name, ret);
  lua_pushinteger(state, ret);
  return 1;
}

static int l_from_client(lua_State* state)
{
  char * name = (char *) lua_tostring(state, 1);
  struct packet_object * po = (struct packet_object *) lua_topointer(state, 2);

  if (name == NULL) {
    printf("Missing name\n");
    lua_pushinteger(state, 0);
    return 1;
  }
  if (po == NULL) {
    printf("Missing packet\n");
    lua_pushinteger(state, 0);
    return 1;
  }

  int ret = FROM_CLIENT(name, po);
  printf("from client (%s)? %d\n", name, ret);
  lua_pushinteger(state, ret);
  return 1;
}


static const struct luaL_reg ec_lua_dissector_lib[] = {
  {"register_dissector", l_register_dissector},
  {"from_server", l_from_server},
  {"from_client", l_from_client},
  {NULL, NULL}
};

LUALIB_API int luaopen_ettercap_dissector_c(lua_State *L) 
{
  luaL_register(L, ETTERCAP_DISSECTOR_C_API_LUA_MODULE, ec_lua_dissector_lib);
  return 1;
}

