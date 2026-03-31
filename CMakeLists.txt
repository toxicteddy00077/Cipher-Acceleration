cmake_minimum_required(VERSION 3.10)
project(CipherAcceleration LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Optional CUDA support
find_package(CUDA)

if(CUDA_FOUND)
    enable_language(CUDA)
    set(CMAKE_CUDA_STANDARD 17)
    set(CMAKE_CUDA_STANDARD_REQUIRED ON)
    message(STATUS "CUDA found, building GPU libraries")
else()
    message(STATUS "CUDA not found, GPU libraries will not be built")
endif()

# Common Modes Library
add_library(cipher_modes STATIC
    CPU/src/Modes.cpp
)

target_include_directories(cipher_modes PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/CPU/include
)

target_compile_options(cipher_modes PRIVATE
    -Wall -Wextra -Wpedantic
    -O2
)

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

# ============================================================
# GPU Libraries (if CUDA is available)
# ============================================================

if(CUDA_FOUND)

add_library(gpu_memory STATIC
    GPU/src/common/GPUMemory.cu
)

target_include_directories(gpu_memory PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/GPU/include
)

target_compile_options(gpu_memory PRIVATE
    $<$<COMPILE_LANGUAGE:CUDA>:
        -Xptxas -O3;
        -use_fast_math
    >
)

add_library(aes256_gpu STATIC
    GPU/src/aes256/Constants.cu
    GPU/src/aes256/Core.cu
)

target_include_directories(aes256_gpu PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/GPU/include
    ${CMAKE_CURRENT_SOURCE_DIR}/CPU/include
)

target_link_libraries(aes256_gpu PUBLIC aes256 gpu_memory)

set_target_properties(aes256_gpu PROPERTIES
    CUDA_ARCHITECTURES "75;86;89"
    CUDA_SEPARABLE_COMPILATION ON
    CUDA_STANDARD 17
)

target_compile_options(aes256_gpu PRIVATE
    $<$<COMPILE_LANGUAGE:CUDA>:
        -Xptxas -O3;
        -use_fast_math;
        -lineinfo
    >
)

add_library(aes128_gpu STATIC
    GPU/src/aes128/Constants.cu
    GPU/src/aes128/Core.cu
)

target_include_directories(aes128_gpu PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/GPU/include
    ${CMAKE_CURRENT_SOURCE_DIR}/CPU/include
)

target_link_libraries(aes128_gpu PUBLIC aes128 gpu_memory)

set_target_properties(aes128_gpu PROPERTIES
    CUDA_ARCHITECTURES "75;86;89"
    CUDA_SEPARABLE_COMPILATION ON
    CUDA_STANDARD 17
)

target_compile_options(aes128_gpu PRIVATE
    $<$<COMPILE_LANGUAGE:CUDA>:
        -Xptxas -O3;
        -use_fast_math;
        -lineinfo
    >
)

add_library(simon64_gpu STATIC
    GPU/src/simon64/Constants.cu
    GPU/src/simon64/Core.cu
)

target_include_directories(simon64_gpu PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/GPU/include
    ${CMAKE_CURRENT_SOURCE_DIR}/CPU/include
)

target_link_libraries(simon64_gpu PUBLIC simon64 gpu_memory)

set_target_properties(simon64_gpu PROPERTIES
    CUDA_ARCHITECTURES "75;86;89"
    CUDA_SEPARABLE_COMPILATION ON
    CUDA_STANDARD 17
)

target_compile_options(simon64_gpu PRIVATE
    $<$<COMPILE_LANGUAGE:CUDA>:
        -Xptxas -O3;
        -use_fast_math;
        -lineinfo
    >
)

add_library(ascon_gpu STATIC
    GPU/src/ascon/Constants.cu
    GPU/src/ascon/Core.cu
)

target_include_directories(ascon_gpu PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/GPU/include
    ${CMAKE_CURRENT_SOURCE_DIR}/CPU/include
)

target_link_libraries(ascon_gpu PUBLIC ascon gpu_memory)

set_target_properties(ascon_gpu PROPERTIES
    CUDA_ARCHITECTURES "75;86;89"
    CUDA_SEPARABLE_COMPILATION ON
    CUDA_STANDARD 17
)

target_compile_options(ascon_gpu PRIVATE
    $<$<COMPILE_LANGUAGE:CUDA>:
        -Xptxas -O3;
        -use_fast_math;
        -lineinfo
    >
)

add_library(salsa20_gpu STATIC
    GPU/src/salsa/Constants.cu
    GPU/src/salsa/Core.cu
)

target_include_directories(salsa20_gpu PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/GPU/include
    ${CMAKE_CURRENT_SOURCE_DIR}/CPU/include
)

target_link_libraries(salsa20_gpu PUBLIC salsa20 gpu_memory)

set_target_properties(salsa20_gpu PROPERTIES
    CUDA_ARCHITECTURES "75;86;89"
    CUDA_SEPARABLE_COMPILATION ON
    CUDA_STANDARD 17
)

target_compile_options(salsa20_gpu PRIVATE
    $<$<COMPILE_LANGUAGE:CUDA>:
        -Xptxas -O3;
        -use_fast_math;
        -lineinfo
    >
)

add_library(trivium_gpu STATIC
    GPU/src/trivium/Constants.cu
    GPU/src/trivium/Core.cu
)

target_include_directories(trivium_gpu PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/GPU/include
    ${CMAKE_CURRENT_SOURCE_DIR}/CPU/include
)

target_link_libraries(trivium_gpu PUBLIC trivium gpu_memory)

set_target_properties(trivium_gpu PROPERTIES
    CUDA_ARCHITECTURES "75;86;89"
    CUDA_SEPARABLE_COMPILATION ON
    CUDA_STANDARD 17
)

target_compile_options(trivium_gpu PRIVATE
    $<$<COMPILE_LANGUAGE:CUDA>:
        -Xptxas -O3;
        -use_fast_math;
        -lineinfo
    >
)

endif(CUDA_FOUND)

# ============================================================
# CPU Implementation Layer
# ============================================================

add_library(aes256_impl STATIC
    Implementation/CPU/src/aes256/AES256Impl.cpp
)
target_include_directories(aes256_impl PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/CPU/include
    ${CMAKE_CURRENT_SOURCE_DIR}/Implementation/CPU/include
)
target_link_libraries(aes256_impl PUBLIC aes256)
target_compile_options(aes256_impl PRIVATE -Wall -Wextra -Wpedantic -O2)

add_library(aes128_impl STATIC
    Implementation/CPU/src/aes128/AES128Impl.cpp
)
target_include_directories(aes128_impl PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/CPU/include
    ${CMAKE_CURRENT_SOURCE_DIR}/Implementation/CPU/include
)
target_link_libraries(aes128_impl PUBLIC aes128)
target_compile_options(aes128_impl PRIVATE -Wall -Wextra -Wpedantic -O2)

add_library(simon64_impl STATIC
    Implementation/CPU/src/simon64/SIMON64Impl.cpp
)
target_include_directories(simon64_impl PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/CPU/include
    ${CMAKE_CURRENT_SOURCE_DIR}/Implementation/CPU/include
)
target_link_libraries(simon64_impl PUBLIC simon64)
target_compile_options(simon64_impl PRIVATE -Wall -Wextra -Wpedantic -O2)

add_library(ascon_impl STATIC
    Implementation/CPU/src/ascon/AsconImpl.cpp
)
target_include_directories(ascon_impl PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/CPU/include
    ${CMAKE_CURRENT_SOURCE_DIR}/Implementation/CPU/include
)
target_link_libraries(ascon_impl PUBLIC ascon)
target_compile_options(ascon_impl PRIVATE -Wall -Wextra -Wpedantic -O2)

add_library(salsa20_impl STATIC
    Implementation/CPU/src/salsa/Salsa20Impl.cpp
)
target_include_directories(salsa20_impl PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/CPU/include
    ${CMAKE_CURRENT_SOURCE_DIR}/Implementation/CPU/include
)
target_link_libraries(salsa20_impl PUBLIC salsa20)
target_compile_options(salsa20_impl PRIVATE -Wall -Wextra -Wpedantic -O2)

add_library(trivium_impl STATIC
    Implementation/CPU/src/trivium/TriviumImpl.cpp
)
target_include_directories(trivium_impl PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/CPU/include
    ${CMAKE_CURRENT_SOURCE_DIR}/Implementation/CPU/include
)
target_link_libraries(trivium_impl PUBLIC trivium)
target_compile_options(trivium_impl PRIVATE -Wall -Wextra -Wpedantic -O2)

