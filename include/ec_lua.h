#ifndef EC_LUA_H
#define EC_LUA_H
#include <ec_packet.h>
#include <ec_decode.h>

EC_API_EXTERN int ec_lua_init();
EC_API_EXTERN int ec_lua_fini();
EC_API_EXTERN int ec_lua_cli_add_script(char * script);
EC_API_EXTERN int ec_lua_cli_add_args(char * args);
int ec_lua_dispatch_hooked_packet(int point, struct packet_object * po);
void ec_lua_print_stack(FILE * io);
//void init_dissector_lua_smtp();

void ec_lua_dispatch_dissector(void * dissector_info, void * session_magic, FUNC_DECODER_ARGS);

void * ec_lua_get_dissector(const char * name);

#endif
