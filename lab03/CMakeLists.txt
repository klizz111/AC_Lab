cmake_minimum_required(VERSION 3.10)
project(ElGamalDistributed)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find OpenSSL package
find_package(OpenSSL REQUIRED)

# Add executables
add_executable(feldman feldman.cpp)                    # Feldman Verifiable Secret Sharing implementation
# add_executable(elgamal_distributed elgamal.cpp)       # ElGamal with Distributed Decryption using feldman's Secret Sharing
# dd_executable(bgn bgn.cpp)                           # BGN homomorphic encryption implementation

# Link OpenSSL libraries
target_link_libraries(feldman OpenSSL::SSL OpenSSL::Crypto)
# target_link_libraries(elgamal_distributed OpenSSL::SSL OpenSSL::Crypto)

# Link PBC library for BGN
# target_link_libraries(bgn
#    OpenSSL::Crypto
#   /opt/homebrew/opt/pbc/lib/libpbc.a
#    /opt/homebrew/opt/pbc/lib/libpbc.dylib
#    /opt/homebrew/opt/gmp/lib/libgmp.a)

# Include OpenSSL headers
target_include_directories(feldman PRIVATE ${OPENSSL_INCLUDE_DIR})
#target_include_directories(elgamal_distributed PRIVATE ${OPENSSL_INCLUDE_DIR})
#target_include_directories(bgn PRIVATE
#    ${OPENSSL_INCLUDE_DIR}
#    /opt/homebrew/opt/pbc/include
#    /opt/homebrew/opt/gmp/include)

# Set compiler flags for better security and warnings
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(feldman PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(elgamal_distributed PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(bgn PRIVATE -Wall -Wextra -Wpedantic -std=c++17)
endif()

# Print build information
message(STATUS "OpenSSL Include Directory: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL Libraries: ${OPENSSL_LIBRARIES}")
