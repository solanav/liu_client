cmake_minimum_required(VERSION 3.9)
project(LIU_CLIENT)

set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_C_COMPILER /usr/bin/gcc)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wpedantic")

find_library(LIBRT rt) 

add_definitions(-DDEBUG)

add_subdirectory(src)
add_subdirectory(plugins)