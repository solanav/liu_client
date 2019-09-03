cmake_minimum_required(VERSION 3.9)
project(LIU_CLIENT)

# Add flags for the compiler
add_compile_options(-Wall -Wextra -Wpedantic)
add_definitions(-DDEBUG)

# Set debug mode
set(CMAKE_BUILD_TYPE Debug)

# Create variables to use in other files
set(LIB_DIR ${PROJECT_SOURCE_DIR}/lib)
set(SRC_DIR ${PROJECT_SOURCE_DIR}/src)
set(NET_DIR ${SRC_DIR}/network)
set(INC_DIR ${PROJECT_SOURCE_DIR}/include)
set(INC_NET_DIR ${INC_DIR}/network)
set(PLG_DIR ${PROJECT_SOURCE_DIR}/plugins)
set(TST_DIR ${PROJECT_SOURCE_DIR}/tests)

# Create library to compile objects once only
add_library(net_lib OBJECT
    ${NET_DIR}/active.c
    ${NET_DIR}/reactive.c
    ${NET_DIR}/request.c
    ${NET_DIR}/tmp_kpeer.c
    ${NET_DIR}/kpeer.c
    ${NET_DIR}/netcore.c
)
target_include_directories(net_lib
    PUBLIC ${INC_DIR} ${INC_NET_DIR}
)

add_library(core_lib OBJECT
    ${SRC_DIR}/keylogger.c
    ${SRC_DIR}/plugin_utils.c
    ${SRC_DIR}/system_utils.c
)
target_include_directories(core_lib
    PUBLIC ${INC_DIR} ${INC_NET_DIR}
)

# Add the other cmake files
add_subdirectory(src)
add_subdirectory(plugins)
add_subdirectory(tests)

# Add the tests
enable_testing()
add_test(NAME tmp_kpeer COMMAND tmp_kpeer_t)
add_test(NAME request COMMAND request_t)