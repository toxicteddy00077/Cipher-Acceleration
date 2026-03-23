#ifndef CUDA_UTILS_H
#define CUDA_UTILS_H

#include <cstdio>
#include <cstdint>

// CUDA error checking macro
#define CUDA_CHECK(call) do { \
    cudaError_t err = call; \
    if (err != cudaSuccess) { \
        fprintf(stderr, "CUDA Error at %s:%d - %s: %s\n", \
                __FILE__, __LINE__, #call, cudaGetErrorString(err)); \
        exit(1); \
    } \
} while(0)

// Device memory allocation wrapper
inline uint8_t* cuda_malloc_device(size_t size) {
    uint8_t* ptr = nullptr;
    CUDA_CHECK(cudaMalloc(&ptr, size));
    return ptr;
}

// Host-to-device copy
inline void cuda_copy_to_device(uint8_t* d_dst, const uint8_t* h_src, size_t size) {
    CUDA_CHECK(cudaMemcpy(d_dst, h_src, size, cudaMemcpyHostToDevice));
}

// Device-to-host copy
inline void cuda_copy_to_host(uint8_t* h_dst, const uint8_t* d_src, size_t size) {
    CUDA_CHECK(cudaMemcpy(h_dst, d_src, size, cudaMemcpyDeviceToHost));
}

// Device memory free
inline void cuda_free_device(uint8_t* ptr) {
    if (ptr != nullptr) {
        CUDA_CHECK(cudaFree(ptr));
    }
}

// Copy to constant memory
template<typename T>
inline void cuda_copy_to_constant(const char* symbol, const T* h_src, size_t size) {
    CUDA_CHECK(cudaMemcpyToSymbol(symbol, h_src, size, 0, cudaMemcpyHostToDevice));
}

#endif
