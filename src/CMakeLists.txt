
LIST (APPEND C20P1305_SRC
    ${CHACHA_PATH}/chacha.c
    ${CHACHA_PATH}/poly1305.c
    ${CHACHA_PATH}/chachapoly_aead.c
    ${HKDF_PATH}/hkdf.c
    bip15x.c
)

ADD_LIBRARY(c20p1305deps STATIC ${C20P1305_SRC})
IF (MINGW)
    TARGET_LINK_OPTIONS(c20p1305deps
        PROPERTIES -Wl,--output-def,src/libc20p1305deps.def
    )
ELSE ()
    TARGET_COMPILE_OPTIONS(c20p1305deps PUBLIC -fPIC)
ENDIF ()

TARGET_INCLUDE_DIRECTORIES(c20p1305deps
    PUBLIC ${LIBBTC_PATH}/src/secp256k1/include
    PUBLIC ${LIBBTC_PATH}/include
    PUBLIC ${CHACHA_PATH}
    PUBLIC ${HKDF_PATH}
    PUBLIC .
)

SET_TARGET_PROPERTIES(c20p1305deps PROPERTIES
    VERSION "0.1.1"
)

#TARGET_LINK_DIRECTORIES(c20p1305deps
#    PUBLIC ${LIBBTC_PATH}/.libs
#)

#TARGET_LINK_LIBRARIES(c20p1305deps
#    ${LIBBTC_PATH}/.libs/libbtc.a
#)

