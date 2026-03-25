cmake_minimum_required(VERSION 3.22.1)
project(xts_aes_native LANGUAGES C CXX)

add_library(xts_aes_native SHARED
    xts_aes_native.cpp
    Serpent.c
    Twofish.c
)

target_include_directories(xts_aes_native PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/Crypto
)

target_link_libraries(xts_aes_native
    android
    log
)

set_target_properties(xts_aes_native PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

# Aggressive optimization for crypto hot paths
# CRYPTOPP_DISABLE_ASM: Twofish.c references x64 assembly stubs (twofish_enc_blk
# etc.) that are not available; disable the ASM path so the portable C
# implementation is used on all architectures.
target_compile_options(xts_aes_native PRIVATE -O3 -DNDEBUG -DCRYPTOPP_DISABLE_ASM)
