add_subdirectory(core)
add_subdirectory(lib)
add_subdirectory(scripts)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/init.lua.in ${CMAKE_CURRENT_BINARY_DIR}/init.lua)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/init.lua DESTINATION ${INSTALL_LUA_ROOT})


# =====

set(DISSECTOR_SRC_FILES)

macro(add_dissector LUA_DISSECTOR_NAME)
  install(FILES
              dissectors/${LUA_DISSECTOR_NAME}.lua
              DESTINATION ${INSTALL_LUA_DISSECTORS})

  set(dissector_file ${CMAKE_CURRENT_BINARY_DIR}/ec_lua_dissect_${LUA_DISSECTOR_NAME}.c)
  set(LUA_DISSECTOR_NAME ${LUA_DISSECTOR_NAME})
  #configure_file(dissector_stub.c.in 
  #  ${dissector_file})

  #list(APPEND DISSECTOR_SRC_FILES ${dissector_file})
endmacro()

# =====

add_dissector(smtp)

message("Dissectors: ${DISSECTOR_SRC_FILES}")

#add_library(ec_lua_dissectors ${DISSECTOR_SRC_FILES})

