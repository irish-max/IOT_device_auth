
# Generated Cmake Pico project file

cmake_minimum_required(VERSION 3.13)

include($ENV{PICO_SDK_PATH}/external/pico_sdk_import.cmake)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

project(sslcert C CXX ASM)

# Initialise the Raspberry Pi Pico SDK
pico_sdk_init()

# Add executable. Default name is the project name, version 0.1

add_executable(sslcert 
wifissl.c
ecc_keygen.c
)

pico_enable_stdio_uart(sslcert 0)
pico_enable_stdio_usb(sslcert 1)

# Add the standard library to the build
target_link_libraries(sslcert
        pico_stdlib)

# Add the standard include files to the build
target_include_directories(sslcert PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}
    ${PICO_SDK_PATH}/lib/lwip/src/include
    ${PICO_SDK_PATH}/lib/lwip/src/apps
    ${PICO_SDK_PATH}/lib/mbedtls/include
    ${PICO_SDK_PATH}/lib/mbedtls/library
)

# Add any user requested libraries
target_link_libraries(sslcert 
        pico_cyw43_arch
        pico_cyw43_arch_lwip_threadsafe_background
        pico_lwip_mbedtls
        pico_mbedtls
        pico_unique_id
        hardware_flash
        )

pico_add_extra_outputs(sslcert)

