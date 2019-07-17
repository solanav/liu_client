include_directories(../include)
link_directories(../lib)
file(GLOB SOURCES_S "../src/*.c")

# Meter un nuevo plugin
add_library(encrypt SHARED encrypt.c ${SOURCES_S})
# Librerias de las que depende el plugin (equivalente a -lhydrogen)
target_link_libraries(encrypt hydrogen)