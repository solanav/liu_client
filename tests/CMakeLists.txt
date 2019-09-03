set(tests
    tmp_kpeer_t
    request_t
)

foreach(test_file IN LISTS tests)
    add_executable(${test_file}
        $<TARGET_OBJECTS:net_lib>
        $<TARGET_OBJECTS:core_lib>
        ${TST_DIR}/${test_file}.c
    )

    target_include_directories(${test_file} 
        PRIVATE ${INC_DIR}
    )

    target_link_libraries(${test_file}
        rt
        pthread
        dl
        ${LIB_DIR}/libhydrogen.a
    )
endforeach(test_file)