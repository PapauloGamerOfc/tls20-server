cmake_minimum_required(VERSION 3.22)
project(tls20_native_primitives LANGUAGES C)

option(TLS20_PWD_BUILD_TEST_ORACLE "Build the test-only, production-rejected PAKE oracle" OFF)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

function(tls20_pwd_target name)
  add_library(${name} SHARED pake.c)
  set_target_properties(${name} PROPERTIES C_VISIBILITY_PRESET hidden)
  if(MSVC)
    target_compile_options(${name} PRIVATE /W4 /WX /O2)
  else()
    target_compile_options(${name} PRIVATE -O2 -Wall -Wextra -Werror)
  endif()
endfunction()

# No OpenSSL link dependency or auto-discovery: the explicit provider supplies
# one public function table and private library context at runtime.
tls20_pwd_target(tls20-pake)
if(TLS20_PWD_BUILD_TEST_ORACLE)
  tls20_pwd_target(tls20-pake-oracle)
  target_compile_definitions(tls20-pake-oracle PRIVATE TLS20_PWD_TESTING)
endif()
install(TARGETS tls20-pake LIBRARY DESTINATION lib RUNTIME DESTINATION bin)
