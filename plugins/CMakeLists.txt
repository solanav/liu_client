add_library(encrypt SHARED 
    ${PLG_DIR}/encrypt.c
    ${SRC_DIR}/system_utils.c
)

target_include_directories(encrypt
    PRIVATE ${INC_DIR} ${INC_NET_DIR} 
)

target_link_libraries(encrypt
    ${LIB_DIR}/libhydrogen.a
)