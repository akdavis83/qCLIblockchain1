#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace qtc {
namespace pq {

// Placeholder interface for post-quantum cryptography.
// Will be implemented in Day 5 using liboqs or oqs_wallet_cli.
//
// DO NOT implement crypto primitives here.
// This interface exists so the blockchain code can be structured
// around PQ signatures from day one, even before liboqs is linked.

// Algorithm IDs (must match consensus.h SigAlgorithm / KemAlgorithm)
constexpr uint8_t SIG_ML_DSA_65 = 0x01;
constexpr uint8_t KEM_ML_KEM_1024 = 0x01;

// Key sizes (bytes)
constexpr size_t ML_DSA_65_PUBLIC_KEY_SIZE = 1952;
constexpr size_t ML_DSA_65_SECRET_KEY_SIZE = 4000;
constexpr size_t ML_DSA_65_SIGNATURE_SIZE = 3293;

constexpr size_t ML_KEM_1024_PUBLIC_KEY_SIZE = 1568;
constexpr size_t ML_KEM_1024_SECRET_KEY_SIZE = 3168;
constexpr size_t ML_KEM_1024_CIPHERTEXT_SIZE = 1568;
constexpr size_t ML_KEM_1024_SHARED_SECRET_SIZE = 32;

// Witness program size (20 bytes — SHA3-256 of Dilithium public key, truncated)
constexpr size_t WITNESS_PROGRAM_SIZE = 20;

// Result of a signature verification
struct SignatureResult {
    bool valid = false;
    std::string error;
};

// Result of key generation
struct KeyPair {
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> secret_key;
    std::string error;
};

// Address derivation result
struct AddressResult {
    std::string address;       // qtc1... bech32m encoded
    std::vector<uint8_t> witness_program;  // 20-byte commitment
    std::string error;
};

// --- Interface (to be implemented in Day 5) ---

// Generate ML-DSA-65 keypair from a seed (deterministic)
// KeyPair generate_mldsa65_keypair(const std::vector<uint8_t>& seed);

// Sign a message with ML-DSA-65
// std::vector<uint8_t> sign_mldsa65(
//     const std::vector<uint8_t>& secret_key,
//     const std::vector<uint8_t>& message
// );

// Verify an ML-DSA-65 signature
// SignatureResult verify_mldsa65(
//     const std::vector<uint8_t>& public_key,
//     const std::vector<uint8_t>& message,
//     const std::vector<uint8_t>& signature
// );

// Derive qtc1 address from a Dilithium public key
// AddressResult derive_address(
//     const std::vector<uint8_t>& public_key,
//     WitnessVersion version,
//     Network network
// );

} // namespace pq
} // namespace qtc
