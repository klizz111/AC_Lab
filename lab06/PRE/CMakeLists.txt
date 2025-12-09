cmake_minimum_required(VERSION 3.15)
project(PRE_Demos LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)
find_path(PBC_INCLUDE_DIR pbc/pbc.h)
find_library(PBC_LIB pbc)
find_library(GMP_LIB gmp)
if(NOT PBC_LIB OR NOT PBC_INCLUDE_DIR OR NOT GMP_LIB)
  message(FATAL_ERROR "pbc/gmp library/headers not found. Please install libpbc和gmp (e.g., brew install pbc gmp).")
endif()

add_library(pre_utils STATIC utils.cpp utils.h common.cpp common.h)
target_link_libraries(pre_utils PUBLIC OpenSSL::Crypto ${PBC_LIB} ${GMP_LIB})
target_include_directories(pre_utils PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${PBC_INCLUDE_DIR})

add_executable(Bi_PRE Bi-PRE.cpp)
target_link_libraries(Bi_PRE PRIVATE pre_utils OpenSSL::SSL OpenSSL::Crypto)

add_executable(Uni_PRE Uni-PRE.cpp)
target_link_libraries(Uni_PRE PRIVATE pre_utils OpenSSL::SSL OpenSSL::Crypto ${PBC_LIB} ${GMP_LIB})
