cmake_minimum_required(VERSION 3.9)
project(LIU_CLIENT)

set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_C_COMPILER /usr/bin/gcc)

add_definitions(-DDEBUG)

add_subdirectory(src)
add_subdirectory(plugins)