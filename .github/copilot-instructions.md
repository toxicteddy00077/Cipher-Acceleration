# Copilot Instructions for Cipher-Acceleration

This repository contains optimized implementations of cryptographic ciphers: **AES-128**, **AES-256**, **SIMON-64**, **Ascon**, **Salsa20**, and **Trivium**. All implementations follow a lean, modular pattern with shared utility functions in `CommonUtils`.

## Build & Compilation

**Prerequisites:** CMake 3.10+, C++17 compiler (g++, clang, etc.)

**Build all cipher libraries:**
```bash
mkdir build && cd build
cmake ..
cmake --build .
```

**CMake Configuration:**
- C++ Standard: C++17 (required)
- Compiler Flags: `-Wall -Wextra -Wpedantic` (enforced) and `-O2` optimization
- Targets: `aes256`, `aes128`, `simon64`, `ascon`, `salsa20`, `trivium` (all static libraries)

## Architecture Overview

### Common Utilities Library (`CommonUtils`)

**Location:** `CPU/include/common/Utilities.h`

Shared utility functions used across all ciphers to reduce code duplication:

**Bit Rotation:**
- `rotateLeft(x, n)` / `rotateRight(x, n)`: Templated rotation for any integer type (used by Salsa20, Ascon)

**Bit Access:**
- `getBit()` / `setBit()`: Single bit read/write on words
- `getBitFromArray()` / `setBitInArray()`: Bit access on arrays (used by Trivium stream cipher)

**Galois Field Arithmetic (GF(2^8)):**
- `xtime(x)`: Multiply by 2 in GF(2^8) with reduction poly 0x1B (used by AES)
- `galoisMult(a, b)`: General GF(2^8) multiplication (used by AES)

**Byte Packing:**
- `loadWord<T>()` / `storeWord<T>()`: Little-endian word load/store from byte arrays
- `loadWordBE<T>()` / `storeWordBE<T>()`: Big-endian variants

**Constants:**
- `GALOIS_POLY`, `BYTE_MASK`, `WORD32_MASK`, etc.

### AES-256 Implementation

**Core Structure:**
- **State Representation:** `AES256_State` struct holds a 4×4 matrix of bytes (16-byte block)
- **Data Flow:** Input → Load → Transform Rounds → Store → Output
- **Key Schedule:** 256-bit (32-byte) key expanded to 240 bytes across 15 round keys

**Key Classes & Namespaces:**

1. **AES256_State** (Core type)
   - `Load()`: Column-major layout conversion from 16-byte block to matrix
   - `Store()`: Reverse of Load
   - `XorRoundKey()`: In-place XOR with round key (used in AddRoundKey)

2. **AES256_Utils::Primitives** (Encryption/Decryption operations)
   - `SubBytes()` / `InvSubBytes()`: S-box substitution
   - `ShiftRows()` / `InvShiftRows()`: Row rotation within state
   - `MixColumns()` / `InvMixColumns()`: Galois Field multiplication (core diffusion step)
   - `AddRoundKey()`: XOR state with round key

3. **AES256_Utils::KeySchedule** (Key expansion)
   - `ExpandKey()`: Transforms 32-byte master key → 240-byte expanded key (15 rounds × 16 bytes)
   - Uses S-box substitution, rotation, and round constants (Rcon)

4. **AES256_Constants** (Lookup tables and constants)
   - `SBOX[256]`: Rijndael S-box for encryption
   - `INV_SBOX[256]`: Inverse S-box for decryption
   - `RCON[15]`: Round constants for key schedule
   - Constants: BLOCK_SIZE (16), KEY_SIZE_256 (32), ROUNDS (14), EXPANDED_KEY_SIZE (240)

### File Organization

```
CPU/
├── include/
│   ├── common/
│   │   └── Utilities.h          # Shared utility functions (bit ops, GF arithmetic, etc.)
│   ├── aes256/AES256.h
│   ├── aes128/AES128.h
│   ├── simon64/SIMON64.h
│   ├── ascon/Ascon.h
│   ├── salsa/Salsa20.h
│   └── trivium/Trivium.h
└── src/
    ├── aes256/{Constants.cpp, Core.cpp}
    ├── aes128/{Constants.cpp, Core.cpp}
    ├── simon64/Core.cpp
    ├── ascon/Core.cpp
    ├── salsa/Core.cpp
    └── trivium/Core.cpp
```

**State Matrix Layout (Column-Major):**
```
AES256_State.mat[row][col] where row,col ∈ [0,3]
Column-major indexing: input[0..3] → mat[:][0], input[4..7] → mat[:][1], etc.
```

### Other Cipher Implementations

- **AES-128:** 10 rounds, 16-byte key, 176-byte expanded key (follows AES-256 pattern)
- **SIMON-64:** 32-bit words, 32 rounds, 128-bit key, lightweight block cipher
- **Ascon:** 5-state permutation, authenticated encryption, 12/6-round variants
- **Salsa20:** 256-bit key stream cipher, quarter-round operations, 20 rounds
- **Trivium:** 288-bit state, 80-bit key/nonce stream cipher, 1152-round initialization

## Key Conventions

### Naming & Types
- **`AES_byte`**: Typedef for `uint8_t` (all AES operations on bytes)
- **Namespace organization:** `AES256_Utils::ClassName` for internal utilities
- **Constants namespace:** `AES256_Constants::` for lookup tables and compile-time constants
- **Inverse operations:** Prefixed with `Inv` (e.g., `InvSubBytes`, `InvShiftRows`)

### Galois Field Arithmetic
- **`xtime(x)`**: Multiply by 2 in GF(2^8) with reduction polynomial 0x1B
- **`galoisMult(a, b)`**: General multiplication in GF(2^8) using iterated xtime
- Both are used exclusively in `MixColumns` and `InvMixColumns`

### State Transformation Order

**Encryption (14 rounds):**
1. Initial: AddRoundKey (round 0)
2. Rounds 1-13: SubBytes → ShiftRows → MixColumns → AddRoundKey
3. Final Round (14): SubBytes → ShiftRows → AddRoundKey (no MixColumns)

**Decryption (14 rounds):** Reverse transformations in reverse order with equivalent inverse operations.

### Code Style
- Explicit use of `std::size_t` for loop counters and array indexing
- Range-based for loops and STL utilities (e.g., `std::rotate`) preferred over manual iteration
- Comments demarcate major sections (e.g., `// ============================================================`)
- No dynamic allocation; all buffers are fixed-size arrays or std::array

## Testing

Currently, no test executable is configured in CMakeLists.txt. To add tests:

1. Create `tests/test_aes256.cpp` with test cases
2. Uncomment the test executable section in CMakeLists.txt
3. Rebuild: `cd build && cmake .. && cmake --build .`

Known placeholders in CMakeLists.txt suggest test infrastructure may be added in future commits.

## License

MIT License (see LICENSE file)
