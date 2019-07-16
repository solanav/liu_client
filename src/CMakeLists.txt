include_directories(../include)
link_directories(../lib)
file(GLOB SOURCES_S "../src/*.c")

add_executable(liu_client ${SOURCES_S})
set_target_properties(liu_client PROPERTIES LINK_FLAGS "-fno-stack-protector")

target_link_libraries(liu_client dl pthread hydrogen rt ssl crypto)
