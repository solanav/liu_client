include_directories(../include)
link_directories(../lib)
file(GLOB SOURCES_S "../src/*.c")

add_executable(liu_client ${SOURCES_S})

target_link_libraries(liu_client dl pthread hydrogen rt ssl crypto)
