add_executable(liu_client
    $<TARGET_OBJECTS:liu_client_lib>
    ${SRC_DIR}/core.c
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