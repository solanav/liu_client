set(tests
    test_system_utils
    test_network_active
    test_network_utils
)

foreach(test_file IN LISTS tests)
    add_executable(${test_file}
        $<TARGET_OBJECTS:liu_client_lib>
        ${TST_DIR}/${test_file}.c
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
