# Verificador común de pes6pkg (design §13). Win32 o x64, CRT estático, C++14.
#   cmake -S client -B build\client-cmake -A Win32 && cmake --build build\client-cmake --config Release
#   python -I tool\run.py --test-keys vectors --out build\vectors
#   build\client-cmake\Release\test_client.exe build\vectors
cmake_minimum_required(VERSION 3.20)
project(pes6pkg_client LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

set(MONOCYPHER ${CMAKE_CURRENT_SOURCE_DIR}/vendor/monocypher-4.0.2)
add_library(pes6pkg_client STATIC
  pes6pkg_core.cpp
  pes6pkg_zip.cpp
  pes6pkg_win.cpp
  ${MONOCYPHER}/monocypher.c
  ${MONOCYPHER}/optional/monocypher-ed25519.c)
target_include_directories(pes6pkg_client PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${MONOCYPHER})
target_compile_definitions(pes6pkg_client PUBLIC WIN32_LEAN_AND_MEAN NOMINMAX)
target_compile_options(pes6pkg_client PRIVATE /W4 /utf-8 $<$<COMPILE_LANGUAGE:CXX>:/permissive- /EHsc>)
target_link_libraries(pes6pkg_client PUBLIC winhttp bcrypt)

add_executable(test_client tests/test_client.cpp)
target_compile_options(test_client PRIVATE /W4 /utf-8 /permissive- /EHsc)
target_link_libraries(test_client PRIVATE pes6pkg_client)
