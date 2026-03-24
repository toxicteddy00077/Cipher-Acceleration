# GPU CUDA Implementation - AES-256

This directory contains CUDA accelerated implementations of cryptographic ciphers, starting with AES-256.

## Structure

```
GPU/
├── include/
│   ├── aes256/
│   │   └── AES256_GPU.h       # Public GPU API
│   └── common_gpu/
│       └── cuda_utils.h        # CUDA utility functions (memory mgmt, error checking)
└── src/
    └── aes256/
        ├── aes256_kernel.cu    # CUDA kernels (encrypt/decrypt)
        └── aes256_host.cu      # Host wrapper functions + key schedule
```

## Building

GPU libraries build automatically when CUDA is detected:

```bash
cd build
cmake ..
cmake --build .
```

The GPU library (`libaes256_gpu.a`) is linked against the CPU AES-256 library.

## Architecture Details

### Memory Layout
- **Device Constant Memory**: S-boxes (512 bytes total)
  - `d_SBOX[256]` - Rijndael S-box
  - `d_INV_SBOX[256]` - Inverse S-box
  - `d_RCON[15]` - Round constants

- **Device Global Memory**: Expanded key (240 bytes per batch)

### Kernel Configuration
- **Grid**: `(numBlocks + 255) / 256` blocks
- **Block**: 256 threads per block
- **Parallelism**: Each thread processes one 16-byte AES block independently

### Key Features
- Batch processing: Multiple blocks encrypted in parallel
- Key schedule precomputed on CPU, cached on GPU
- Minimal PCIe transfers (only plaintext/ciphertext)
- Supports both encryption and decryption

## API Usage

```cpp
#include "aes256/AES256_GPU.h"

// Initialize GPU (call once)
AES256_GPU::initialize_gpu();

// Batch encrypt
uint8_t key[32] = {...};
uint8_t plaintext[1024] = {...};  // 64 blocks
uint8_t ciphertext[1024] = {...};

AES256_GPU::encrypt_batch(plaintext, ciphertext, key, 64);

// Batch decrypt
AES256_GPU::decrypt_batch(ciphertext, plaintext_out, key, 64);

// Cleanup
AES256_GPU::cleanup_gpu();
```

## Performance Notes

- **Optimal batch size**: 1024+ blocks (minimize PCIe overhead)
- **Latency**: ~10-20 µs per operation (includes PCIe transfer)
- **Throughput**: 20-50 GB/s (batch mode)
- **Architecture support**: CUDA 7.5+ (Turing, Ampere, Ada supported via CMakeLists.txt)

## Optimization Opportunities

1. **Stream-based async transfers**: Pipeline computation with data transfer
2. **Pinned host memory**: Reduce CPU-GPU copy overhead
3. **Multi-kernel approach**: Separate rounds into smaller kernels for better occupancy
4. **Shared memory**: Cache S-boxes per block for better bandwidth
5. **PTX assembly**: Inline rotate/xtime operations for specialized operations
