#include "crypto.h"
#include <cstring>
#include <stdexcept>

namespace qtc {
namespace crypto {

// ============================================================
// SHA-256 Implementation (FIPS 180-4)
// Self-contained — no external dependencies.
// For production, replace with OpenSSL or platform SHA-256.
// ============================================================

namespace {

// SHA-256 constants
constexpr uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

constexpr uint32_t H0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

inline uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

inline uint32_t choose(uint32_t e, uint32_t f, uint32_t g) {
    return (e & f) ^ (~e & g);
}

inline uint32_t majority(uint32_t a, uint32_t b, uint32_t c) {
    return (a & b) ^ (a & c) ^ (b & c);
}

inline uint32_t big_sigma0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

inline uint32_t big_sigma1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

inline uint32_t small_sigma0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

inline uint32_t small_sigma1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

void sha256_compress(uint32_t state[8], const uint8_t block[64]) {
    uint32_t w[64];
    
    // First 16 words from block (big-endian)
    for (int i = 0; i < 16; ++i) {
        w[i] = (static_cast<uint32_t>(block[i * 4]) << 24) |
               (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
               (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
               (static_cast<uint32_t>(block[i * 4 + 3]));
    }
    
    // Extend the remaining 48 words
    for (int i = 16; i < 64; ++i) {
        w[i] = small_sigma1(w[i - 2]) + w[i - 7] + small_sigma0(w[i - 15]) + w[i - 16];
    }
    
    // Initialize working variables
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    
    // Compression
    for (int i = 0; i < 64; ++i) {
        uint32_t t1 = h + big_sigma1(e) + choose(e, f, g) + K[i] + w[i];
        uint32_t t2 = big_sigma0(a) + majority(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    
    // Update state
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

} // anonymous namespace

// ============================================================
// Public API
// ============================================================

std::vector<uint8_t> sha256(const uint8_t* data, size_t len) {
    uint32_t state[8];
    std::memcpy(state, H0, sizeof(H0));
    
    // Process full 64-byte blocks
    const size_t full_blocks = len / 64;
    for (size_t i = 0; i < full_blocks; ++i) {
        sha256_compress(state, data + i * 64);
    }
    
    // Pad and process the final block(s)
    uint8_t final_block[128] = {0};  // up to 2 blocks
    size_t remaining = len - (full_blocks * 64);
    std::memcpy(final_block, data + full_blocks * 64, remaining);
    
    // Append 0x80
    final_block[remaining] = 0x80;
    
    // If remaining > 55, we need two blocks
    size_t pad_len;
    if (remaining >= 56) {
        pad_len = 128;
    } else {
        pad_len = 64;
    }
    
    // Append length (big-endian, 64-bit)
    uint64_t bit_len = static_cast<uint64_t>(len) * 8;
    for (int i = 0; i < 8; ++i) {
        final_block[pad_len - 8 + i] = static_cast<uint8_t>((bit_len >> (56 - 8 * i)) & 0xFF);
    }
    
    // Process final block(s)
    sha256_compress(state, final_block);
    if (pad_len == 128) {
        sha256_compress(state, final_block + 64);
    }
    
    // Output (big-endian)
    std::vector<uint8_t> result(32);
    for (int i = 0; i < 8; ++i) {
        result[i * 4]     = static_cast<uint8_t>((state[i] >> 24) & 0xFF);
        result[i * 4 + 1] = static_cast<uint8_t>((state[i] >> 16) & 0xFF);
        result[i * 4 + 2] = static_cast<uint8_t>((state[i] >> 8) & 0xFF);
        result[i * 4 + 3] = static_cast<uint8_t>(state[i] & 0xFF);
    }
    
    return result;
}

std::vector<uint8_t> sha256(const std::vector<uint8_t>& data) {
    return sha256(data.data(), data.size());
}

std::vector<uint8_t> double_sha256(const uint8_t* data, size_t len) {
    return sha256(sha256(data, len));
}

std::vector<uint8_t> double_sha256(const std::vector<uint8_t>& data) {
    return double_sha256(data.data(), data.size());
}

// ============================================================
// Hex utilities
// ============================================================

std::string to_hex(const std::vector<uint8_t>& bytes) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) {
        result += hex_chars[(b >> 4) & 0xF];
        result += hex_chars[b & 0xF];
    }
    return result;
}

std::vector<uint8_t> from_hex(const std::string& hex) {
    std::vector<uint8_t> result;
    result.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        auto nibble = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            throw std::runtime_error("Invalid hex character: " + std::string(1, c));
        };
        result.push_back((nibble(hex[i]) << 4) | nibble(hex[i + 1]));
    }
    return result;
}

// ============================================================
// Serialization helpers (little-endian)
// ============================================================

std::vector<uint8_t> write_le_u32(uint32_t val) {
    return {
        static_cast<uint8_t>(val & 0xFF),
        static_cast<uint8_t>((val >> 8) & 0xFF),
        static_cast<uint8_t>((val >> 16) & 0xFF),
        static_cast<uint8_t>((val >> 24) & 0xFF)
    };
}

std::vector<uint8_t> write_le_u64(uint64_t val) {
    std::vector<uint8_t> result(8);
    for (int i = 0; i < 8; ++i) {
        result[i] = static_cast<uint8_t>((val >> (8 * i)) & 0xFF);
    }
    return result;
}

uint32_t read_le_u32(const uint8_t* data) {
    return static_cast<uint32_t>(data[0]) |
           (static_cast<uint32_t>(data[1]) << 8) |
           (static_cast<uint32_t>(data[2]) << 16) |
           (static_cast<uint32_t>(data[3]) << 24);
}

uint64_t read_le_u64(const uint8_t* data) {
    uint64_t val = 0;
    for (int i = 0; i < 8; ++i) {
        val |= static_cast<uint64_t>(data[i]) << (8 * i);
    }
    return val;
}

std::vector<uint8_t> concat(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    std::vector<uint8_t> result;
    result.reserve(a.size() + b.size());
    result.insert(result.end(), a.begin(), a.end());
    result.insert(result.end(), b.begin(), b.end());
    return result;
}

// ============================================================
// CompactSize (variable-length integer)
// ============================================================

std::vector<uint8_t> write_compact_size(uint64_t val) {
    std::vector<uint8_t> result;
    if (val < 253) {
        result.push_back(static_cast<uint8_t>(val));
    } else if (val <= 0xFFFF) {
        result.push_back(0xFD);
        result.push_back(static_cast<uint8_t>(val & 0xFF));
        result.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
    } else if (val <= 0xFFFFFFFF) {
        result.push_back(0xFE);
        result.push_back(static_cast<uint8_t>(val & 0xFF));
        result.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
        result.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
        result.push_back(static_cast<uint8_t>((val >> 24) & 0xFF));
    } else {
        result.push_back(0xFF);
        for (int i = 0; i < 8; ++i) {
            result.push_back(static_cast<uint8_t>((val >> (8 * i)) & 0xFF));
        }
    }
    return result;
}

uint64_t read_compact_size(const uint8_t* data, size_t& offset) {
    uint8_t prefix = data[offset++];
    if (prefix < 253) {
        return prefix;
    } else if (prefix == 0xFD) {
        uint64_t val = static_cast<uint64_t>(data[offset]) |
                      (static_cast<uint64_t>(data[offset + 1]) << 8);
        offset += 2;
        return val;
    } else if (prefix == 0xFE) {
        uint64_t val = static_cast<uint64_t>(data[offset]) |
                      (static_cast<uint64_t>(data[offset + 1]) << 8) |
                      (static_cast<uint64_t>(data[offset + 2]) << 16) |
                      (static_cast<uint64_t>(data[offset + 3]) << 24);
        offset += 4;
        return val;
    } else {
        uint64_t val = 0;
        for (int i = 0; i < 8; ++i) {
            val |= static_cast<uint64_t>(data[offset + i]) << (8 * i);
        }
        offset += 8;
        return val;
    }
}

// ============================================================
// Difficulty / target utilities
// ============================================================

std::vector<uint8_t> bits_to_target(uint32_t bits) {
    // Compact representation: 1 byte exponent + 3 bytes mantissa
    uint8_t exponent = (bits >> 24) & 0xFF;
    uint32_t mantissa = bits & 0x00FFFFFF;
    
    // Target = mantissa * 2^(8*(exponent - 3))
    // Represent as a 32-byte big-endian value
    std::vector<uint8_t> target(32, 0);
    
    // Place mantissa bytes (3 bytes, big-endian) at the right position
    int byte_pos = 32 - exponent;
    if (byte_pos < 0) {
        // Very large target — shouldn't happen for valid difficulty
        target.assign(32, 0xFF);
        return target;
    }
    
    // Write mantissa (3 bytes big-endian)
    if (byte_pos >= 0 && byte_pos < 32) target[byte_pos]     = (mantissa >> 16) & 0xFF;
    if (byte_pos + 1 >= 0 && byte_pos + 1 < 32) target[byte_pos + 1] = (mantissa >> 8) & 0xFF;
    if (byte_pos + 2 >= 0 && byte_pos + 2 < 32) target[byte_pos + 2] = mantissa & 0xFF;
    
    return target;
}

bool hash_meets_target(const std::vector<uint8_t>& hash, const std::vector<uint8_t>& target) {
    // Both are 32-byte big-endian values
    // Hash must be less than or equal to target
    if (hash.size() != 32 || target.size() != 32) return false;
    
    for (size_t i = 0; i < 32; ++i) {
        if (hash[i] < target[i]) return true;
        if (hash[i] > target[i]) return false;
    }
    return true;  // Equal — meets target
}

} // namespace crypto
} // namespace qtc
