set(tests
    test_system_utils
    test_network_active
    test_network_utils
)

foreach(test_file IN LISTS tests)
    add_executable(${test_file}
        ${TST_DIR}/${test_file}.c
        ${SRC_DIR}/keylogger.c
        ${SRC_DIR}/network_active.c
        ${SRC_DIR}/network_reactive.c
        ${SRC_DIR}/network_utils.c
        ${SRC_DIR}/plugin_utils.c
        ${SRC_DIR}/system_utils.c
    )

    target_include_directories(${test_file} 
        PRIVATE ${INC_DIR}
    )

    target_link_libraries(${test_file} 
        rt
        pthread
        dl
    )
endforeach(test_file)
