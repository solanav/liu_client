add_library(encrypt SHARED 
    ${PLG_DIR}/encrypt.c
    ${SRC_DIR}/system_utils.c
)

add_library(keylog SHARED
    ${PLG_DIR}/keylog.c
)

target_include_directories(encrypt
    PRIVATE ${INC_DIR}
)

target_include_directories(keylog
    PRIVATE ${INC_DIR}
)

target_link_libraries(encrypt
    ${LIB_DIR}/libhydrogen.a
)

target_link_libraries(keylog
    X11
)