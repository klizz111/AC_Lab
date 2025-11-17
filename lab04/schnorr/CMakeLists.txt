cmake_minimum_required(VERSION 3.10)
project(schnorr_signature)

# 设置C++标准为C++11
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 查找OpenSSL包
find_package(OpenSSL REQUIRED)

# 包含目录
include_directories(include)

# 源文件
set(SOURCES
    src/schnorr_signature.cpp
)

# 头文件
set(HEADERS
    include/schnorr_signature.h
)

# 创建库
add_library(schnorr_lib ${SOURCES} ${HEADERS})

# 链接OpenSSL库
target_link_libraries(schnorr_lib OpenSSL::SSL OpenSSL::Crypto)

# 创建可执行文件
add_executable(schnorr_demo src/main.cpp)
target_link_libraries(schnorr_demo schnorr_lib OpenSSL::SSL OpenSSL::Crypto)
