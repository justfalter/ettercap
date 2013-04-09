
set(INSTALL_LUA_ROOT ${INSTALL_DATADIR}/lua)
set(INSTALL_LUA_INIT ${INSTALL_LUA_ROOT}/init.lua)
set(INSTALL_LUA_CORE ${INSTALL_LUA_ROOT}/core)
set(INSTALL_LUA_LIBS ${INSTALL_LUA_ROOT}/lib)
set(INSTALL_LUA_SCRIPTS ${INSTALL_LUA_ROOT}/scripts)
set(INSTALL_LUA_DISSECTORS ${INSTALL_LUA_ROOT}/dissectors)

configure_file(ec_lua_config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/include/ec_lua_config.h)

# Add our 'shared' code. 
add_subdirectory(share)

# Take care of building our C-based stuff.
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/include)
include_directories(${LUAJIT_INCLUDE_DIR})
add_library(ec_lua ec_lua.c ec_lua_dissect.c)

target_link_libraries(ec_lua ${LUAJIT_LIBRARY})

