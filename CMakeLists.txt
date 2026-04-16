cmake_minimum_required(VERSION 3.21)

project(Mini_DNS VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_library(dns_core INTERFACE)
target_include_directories(dns_core INTERFACE ${CMAKE_SOURCE_DIR}/src)

add_executable(dns-server src/main.cpp)
target_link_libraries(dns-server PRIVATE dns_core)
target_compile_features(dns-server PRIVATE cxx_std_23)
target_compile_options(dns-server PRIVATE
    -Wall -Wextra -Wpedantic -Werror -Wshadow -Wconversion
    $<$<CONFIG:Debug>:-g -O0>
    $<$<CONFIG:Release>:-O3>
)

option(BUILD_TESTS "Build tests" ON)
if(BUILD_TESTS)
    add_subdirectory(tests)
endif()
