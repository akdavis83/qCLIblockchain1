#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include "consensus.h"

namespace qtc {
namespace pq {

// Canonical names are the FIPS-203/204 names. "Dilithium3" is a removed liboqs
// identifier and must not be reintroduced here.

// Algorithm IDs (must match consensus.h SigAlgorithm / KemAlgorithm)
constexpr uint8_t SIG_ML_DSA_65 = 0x01;
constexpr uint8_t KEM_ML_KEM_1024 = 0x01;

constexpr size_t ML_DSA_65_PUBLIC_KEY_SIZE = 1952;
constexpr size_t ML_DSA_65_SECRET_KEY_SIZE = 4032;
constexpr size_t ML_DSA_65_SIGNATURE_SIZE = 3309;

constexpr size_t ML_KEM_1024_PUBLIC_KEY_SIZE = 1568;
constexpr size_t ML_KEM_1024_SECRET_KEY_SIZE = 3168;
constexpr size_t ML_KEM_1024_CIPHERTEXT_SIZE = 1568;
constexpr size_t ML_KEM_1024_SHARED_SECRET_SIZE = 32;

// v1 addresses carry the full 32-byte SHA3-256 hash. Truncating it to 20 bytes,
// compressing it, and the v2 tag are all later upgrades for when block space
// gets tight — none of them are in use.
constexpr size_t WITNESS_PROGRAM_SIZE = 32;

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

// --- Interface ---

// Generate an ML-DSA-65 keypair deterministically from a seed.
// The same seed always yields the same keypair.
KeyPair generate_mldsa65_keypair(const std::vector<uint8_t>& seed);

// Sign a message with ML-DSA-65. Returns an empty vector on failure, with
// `error_out` set. ML-DSA signing is hedged by design, so the bytes are not
// reproducible across calls — verify rather than compare.
std::vector<uint8_t> sign_mldsa65(
    const std::vector<uint8_t>& secret_key,
    const std::vector<uint8_t>& message,
    std::string* error_out = nullptr);

// Verify an ML-DSA-65 signature.
SignatureResult verify_mldsa65(
    const std::vector<uint8_t>& public_key,
    const std::vector<uint8_t>& message,
    const std::vector<uint8_t>& signature
);

struct KemResult {
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> secret_key;
    std::vector<uint8_t> shared_secret;
    std::vector<uint8_t> ciphertext;
    std::string error;
};

// Confirm the linked liboqs agrees with the sizes declared in this header.
bool linked_sizes_match(std::string* error_out = nullptr);

// Deterministic ML-KEM-1024 keypair from a seed.
KeyPair generate_mlkem1024_keypair(const std::vector<uint8_t>& seed);

// Deterministic ML-KEM-1024 keypair plus a shared secret, mirroring the
// reference wallet's kem_self_from_seed.
KemResult kem_self_from_seed(const std::vector<uint8_t>& seed);

// Encode a full program as a bech32m address. No version word is prepended.
std::string encode_address(const std::vector<uint8_t>& program,
                           Network network = Network::MAINNET);

// Result of decoding a wallet address. Decoding is read-only and does not
// assert how the address was derived, so it stays valid across the Day 6
// decision on bech32 versus bech32m.
struct DecodedAddress {
    bool valid = false;
    Network network = Network::MAINNET;
    uint8_t witness_version = 0;
    std::vector<uint8_t> program;
    bool bech32m = false;  // which checksum variant the address used
    std::string error;
};

// Decode a qtc/tqtc address into network, witness version and program.
// Accepts either checksum variant and reports which one was found.
DecodedAddress decode_address(const std::string& address);

} // namespace pq
} // namespace qtc
