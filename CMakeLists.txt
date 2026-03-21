cmake_minimum_required(VERSION 3.10)
project(CipherAcceleration LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# AES-256 Library
add_library(aes256 STATIC
    CPU/src/aes256/Constants.cpp
    CPU/src/aes256/Core.cpp
)

target_include_directories(aes256 PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/CPU/include
)

target_compile_options(aes256 PRIVATE
    -Wall -Wextra -Wpedantic
    -O2
)

# AES-128 Library
add_library(aes128 STATIC
    CPU/src/aes128/Constants.cpp
    CPU/src/aes128/Core.cpp
)

target_include_directories(aes128 PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/CPU/include
)

target_compile_options(aes128 PRIVATE
    -Wall -Wextra -Wpedantic
    -O2
)

# SIMON-64 Library
add_library(simon64 STATIC
    CPU/src/simon64/Core.cpp
)

target_include_directories(simon64 PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/CPU/include
)

target_compile_options(simon64 PRIVATE
    -Wall -Wextra -Wpedantic
    -O2
)

# Ascon Library
add_library(ascon STATIC
    CPU/src/ascon/Core.cpp
)

target_include_directories(ascon PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/CPU/include
)

target_compile_options(ascon PRIVATE
    -Wall -Wextra -Wpedantic
    -O2
)

# Salsa20 Library
add_library(salsa20 STATIC
    CPU/src/salsa/Core.cpp
)

target_include_directories(salsa20 PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/CPU/include
)

target_compile_options(salsa20 PRIVATE
    -Wall -Wextra -Wpedantic
    -O2
)

# Trivium Library
add_library(trivium STATIC
    CPU/src/trivium/Core.cpp
)

target_include_directories(trivium PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/CPU/include
)

target_compile_options(trivium PRIVATE
    -Wall -Wextra -Wpedantic
    -O2
)

# Example test executable (if test files exist)
# if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_aes256.cpp)
#     add_executable(test_aes256 tests/test_aes256.cpp)
#     target_link_libraries(test_aes256 aes256)
# endif()

