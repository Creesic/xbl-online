cmake_minimum_required(VERSION 3.16)
project(xbl_online C)

add_library(xbl_online STATIC
    src/crypto.c
    src/disk.c
    src/profile.c
    src/http.c
    src/signin.c
    src/ui.c
    src/attach.c
    src/qrcodegen.c)

target_include_directories(xbl_online
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_compile_features(xbl_online PUBLIC c_std_11)

if(WIN32)
    target_link_libraries(xbl_online PUBLIC bcrypt ws2_32 xinput shell32)
else()
    target_link_libraries(xbl_online PUBLIC $<$<NOT:$<PLATFORM_ID:Android>>:pthread>)
    target_compile_definitions(xbl_online PRIVATE _POSIX_C_SOURCE=200809L)
endif()

if(MSVC)
    target_compile_options(xbl_online PRIVATE /W3)
else()
    target_compile_options(xbl_online PRIVATE -Wall -Wextra -Wno-unused-function)
endif()
