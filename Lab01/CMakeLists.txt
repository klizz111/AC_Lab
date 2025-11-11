cmake_minimum_required(VERSION 3.16)
project(CryptoLab01 LANGUAGES CXX)  # 定义项目名称和使用的语言（C++）

# 设置C++标准为C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 查找OpenSSL库，这是编译程序所必需的
find_package(OpenSSL REQUIRED)

# 使用O3优化
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")

# 创建目录
file(MAKE_DIRECTORY ${PROJECT_SOURCE_DIR}/bin)

# 编译 hash_commit 可执行文件 - 基于哈希的消息承诺方案
add_executable(hash_commit hash_commit.cpp)
target_link_libraries(hash_commit PRIVATE OpenSSL::Crypto)  # 链接OpenSSL加密库

# 编译 pedersen 可执行文件 - Pedersen承诺方案
add_executable(pedersen pedersen.cpp)
target_link_libraries(pedersen PRIVATE OpenSSL::Crypto)     # 链接OpenSSL加密库

# 编译 shamir 可执行文件 - Shamir秘密分享方案
add_executable(shamir shamir.cpp)
target_link_libraries(shamir PRIVATE OpenSSL::Crypto)      # 链接OpenSSL加密库

# 编译 lab01_test 可执行文件 - lab01实验的测试程序
add_executable(lab01_test lab01_test.cpp)
# 注意：测试程序未链接OpenSSL库，因为它只是调用其他程序并验证输出

function(configure_target target_name output_dir)
    # 设置输出目录
    set_target_properties(${target_name} PROPERTIES 
        RUNTIME_OUTPUT_DIRECTORY ${output_dir})
endfunction()

configure_target(hash_commit ${PROJECT_SOURCE_DIR}/bin)
configure_target(pedersen ${PROJECT_SOURCE_DIR}/bin)
configure_target(shamir ${PROJECT_SOURCE_DIR}/bin)
configure_target(lab01_test ${PROJECT_SOURCE_DIR}/bin)
