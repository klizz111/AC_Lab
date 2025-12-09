cmake_minimum_required(VERSION 3.10)
project(BCP LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)

add_executable(bcp
    bcp.cpp
    utils.cpp
)

target_link_libraries(bcp PRIVATE OpenSSL::Crypto OpenSSL::SSL)
