cmake_minimum_required(VERSION 3.9)
project(LIU_CLIENT)

set(CMAKE_BUILD_TYPE Debug)

add_definitions(-DDEBUG)

add_subdirectory(src)
add_subdirectory(plugins)