cmake_minimum_required(VERSION 3.16)
project(bf_ibe LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_library(PBC_LIB pbc REQUIRED)
find_library(GMP_LIB gmp REQUIRED)
find_path(PBC_INCLUDE_DIR pbc/pbc.h REQUIRED)

add_executable(BF-IBE BF-IBE.cpp common.cpp)
add_executable(BF-IBE2 BF-IBE2.cpp common.cpp)

add_executable(FIBE FIBE.cpp common.cpp)
add_executable(CP-ABE CP-ABE.cpp common.cpp)
add_executable(KP-ABE KP-ABE.cpp common.cpp)

target_include_directories(BF-IBE PRIVATE ${PBC_INCLUDE_DIR})
target_link_libraries(BF-IBE PRIVATE ${PBC_LIB} ${GMP_LIB} OpenSSL::Crypto)

target_include_directories(BF-IBE2 PRIVATE ${PBC_INCLUDE_DIR})
target_link_libraries(BF-IBE2 PRIVATE ${PBC_LIB} ${GMP_LIB} OpenSSL::Crypto)



target_include_directories(FIBE PRIVATE ${PBC_INCLUDE_DIR})
target_link_libraries(FIBE PRIVATE ${PBC_LIB} ${GMP_LIB} OpenSSL::Crypto)

target_include_directories(CP-ABE PRIVATE ${PBC_INCLUDE_DIR})
target_link_libraries(CP-ABE PRIVATE ${PBC_LIB} ${GMP_LIB} OpenSSL::Crypto)

target_include_directories(KP-ABE PRIVATE ${PBC_INCLUDE_DIR})
target_link_libraries(KP-ABE PRIVATE ${PBC_LIB} ${GMP_LIB} OpenSSL::Crypto)
