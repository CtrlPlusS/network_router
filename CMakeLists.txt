cmake_minimum_required(VERSION 3.10)
project(HighPerfRouter VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_options(-O3 -Wall -Wextra -g)
include_directories(include)

set(SOURCES
    src/main.cpp
    include/common.cpp
    include/packet_read.cpp
    include/packet_send.cpp
    include/route.cpp
    include/router_info.cpp
    include/nat.cpp
    include/firewall.cpp
    include/dhcp.cpp
)

# 실행 파일 생성
add_executable(router_engine ${SOURCES})