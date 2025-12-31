# CMake 는 빌드 파일을 생성해주는 프로그램 입니다.
# 다시 말해 CMake 를 통해서 프로젝트를 빌드를 하는 것이 아니라,
# CMake 를 통해서 빌드 파일을 생성하면 빌드 프로그램을 통해서 프로젝트를 빌드 하는 것입니다. 

# CMake 프로그램의 최소 버전
cmake_minimum_required(VERSION 3.10)


# 프로젝트 정보
project(RawSocketSniffer)
set(CMAKE_CXX_STANDARD 17)
add_executable(sniffer src/main.cpp)