cmake_minimum_required(VERSION 3.16)
project(dlp_engine CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_library(dlp_engine_lib src/aho_corasick.cpp src/dlp_engine.cpp)
target_include_directories(dlp_engine_lib PUBLIC include)

add_executable(dlp-engine src/main.cpp)
target_link_libraries(dlp-engine PRIVATE dlp_engine_lib)

enable_testing()
add_executable(test_aho_corasick tests/test_aho_corasick.cpp)
target_link_libraries(test_aho_corasick PRIVATE dlp_engine_lib)
add_test(NAME aho_corasick COMMAND test_aho_corasick)
