cmake_minimum_required(VERSION 3.14)
project(HMAC C)

set(CMAKE_C_STANDARD 11)

include_directories(.)

add_executable(HMAC
        main.c common.h cmake-build-debug/common.c)
