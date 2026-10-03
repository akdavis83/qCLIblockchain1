#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace qtc {
namespace crypto {

// --- Hex utilities ---
std::string to_hex(const std::vector<uint8_t>& bytes);
std::vector<uint8_t> from_hex(const std::string& hex);

// --- SHA-256 (self-contained, no external dependency) ---
std::vector<uint8_t> sha256(const std::vector<uint8_t>& data);
std::vector<uint8_t> sha256(const uint8_t* data, size_t len);

// Double SHA-256 (Bitcoin-style: SHA256(SHA256(data)))
std::vector<uint8_t> double_sha256(const std::vector<uint8_t>& data);
std::vector<uint8_t> double_sha256(const uint8_t* data, size_t len);

// --- Serialization helpers (little-endian) ---
std::vector<uint8_t> write_le_u32(uint32_t val);
std::vector<uint8_t> write_le_u64(uint64_t val);
uint32_t read_le_u32(const uint8_t* data);
uint64_t read_le_u64(const uint8_t* data);

// --- CompactSize (Bitcoin-style variable-length integer) ---
// Encodes/decodes counts and lengths in a compact format:
//   < 253:          1 byte
//   253-65535:      0xFD + 2 bytes LE
//   65536-4G:       0xFE + 4 bytes LE
//   > 4G:           0xFF + 8 bytes LE
std::vector<uint8_t> write_compact_size(uint64_t val);
// Reads compact size from data at offset, returns the value and advances offset
uint64_t read_compact_size(const uint8_t* data, size_t& offset);

// Concatenate byte vectors
std::vector<uint8_t> concat(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);

// --- Difficulty / target utilities ---
std::vector<uint8_t> bits_to_target(uint32_t bits);
bool hash_meets_target(const std::vector<uint8_t>& hash, const std::vector<uint8_t>& target);

} // namespace crypto
} // namespace qtc
