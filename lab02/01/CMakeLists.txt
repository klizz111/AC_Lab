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

add_executable(commit commit.cpp)
target_link_libraries(commit PRIVATE OpenSSL::Crypto)  # 链接OpenSSL加密库

add_executable(verify verify.cpp)
target_link_libraries(verify PRIVATE OpenSSL::Crypto)     # 链接OpenSSL加密库

add_executable(crack crack.cpp)
target_link_libraries(crack PRIVATE OpenSSL::Crypto pthread)    

function(configure_target target_name output_dir)
    # 设置输出目录
    set_target_properties(${target_name} PROPERTIES 
        RUNTIME_OUTPUT_DIRECTORY ${output_dir})
endfunction()

configure_target(commit ${PROJECT_SOURCE_DIR}/bin)
configure_target(verify ${PROJECT_SOURCE_DIR}/bin)
configure_target(crack ${PROJECT_SOURCE_DIR}/bin)