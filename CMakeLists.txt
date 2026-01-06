cmake_minimum_required(VERSION 3.10)
project(HighPerfRouter VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_options(-O3 -Wall -Wextra -g)
include_directories(include)

# ==========================================
# 1. 메인 프로젝트 빌드 (src 폴더)
#    src 안의 모든 파일을 합쳐서 하나의 'router_engine'을 만듦
# ==========================================
file(GLOB_RECURSE SRC_FILES "src/*.cpp")

# 소스 파일이 있을 때만 빌드
if (SRC_FILES)
    add_executable(router_engine ${SRC_FILES})
    target_link_libraries(router_engine pthread)
    message(STATUS "Main Target Added: router_engine")
endif()

# ==========================================
# 2. 연습용 코드 빌드 (practice 폴더)
#    각 파일을 별도의 실행 파일로 만듦 (예: practice_loop)
# ==========================================

# file(GLOB PRACTICE_SOURCES "practice/*.cpp")

# foreach(SOURCE_FILE ${PRACTICE_SOURCES})
#     get_filename_component(TARGET_NAME ${SOURCE_FILE} NAME_WE)
    
#     # 실행 파일명 앞에 'practice_'를 붙여 구분
#     set(EXE_NAME "practice_${TARGET_NAME}")
    
#     add_executable(${EXE_NAME} ${SOURCE_FILE})
#     target_link_libraries(${EXE_NAME} pthread)
    
#     message(STATUS "Practice Target Added: ${EXE_NAME}")
# endforeach()