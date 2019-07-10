include_directories(../include)
link_directories(../lib)
file(GLOB SOURCES_S "../src/*.c")

add_library(encrypt encrypt.c ${SOURCES_S})
target_link_libraries(encrypt hydrogen)