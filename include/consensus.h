#pragma once

#include <cstdint>
#include <string>

namespace qtc {

// --- Monetary policy ---
constexpr uint64_t COIN = 100000000;              // 1 QTC = 100,000,000 satoshis
constexpr uint64_t MAX_MONEY = 21000000ULL * COIN; // 21 million QTC cap
constexpr uint32_t BLOCK_INTERVAL = 600;           // 10-minute target (seconds)
constexpr uint32_t MAX_BLOCK_SIZE = 32 * 1024 * 1024; // 32 MB development target
constexpr uint32_t COINBASE_MATURITY = 100;        // 100 confirmations before spendable

// --- Subsidy ---
constexpr uint64_t INITIAL_SUBSIDY = 50 * COIN;   // 50 QTC per block at launch
constexpr uint32_t HALVING_INTERVAL = 210000;      // blocks between halvings

// --- Proof of Work ---
enum class PowAlgorithm : uint8_t {
    SHA256  = 0x01,
    // Future: QRANDOMX = 0x02
};

// --- Signature algorithms ---
enum class SigAlgorithm : uint8_t {
    ML_DSA_65 = 0x01,  // Dilithium3 / FIPS-204
    // Future: other PQ signature schemes
};

// --- KEM algorithms ---
enum class KemAlgorithm : uint8_t {
    ML_KEM_1024 = 0x01,  // Kyber1024 / FIPS-203
    // Future: other KEMs
};

// --- Witness versions ---
enum class WitnessVersion : uint8_t {
    V1 = 1,  // Standard PQ wallet (Dilithium pubkey → SHA3-256 → 20 bytes → bech32m)
    V2 = 2,  // PQ-HD wallet (reserved for future)
};

// --- Block / Transaction versions ---
constexpr uint32_t BLOCK_VERSION = 1;
constexpr uint32_t TX_VERSION = 1;

// --- Network types ---
enum class Network : uint8_t {
    MAINNET = 0x00,
    TESTNET = 0x01,
    REGTEST = 0x02,
};

// --- Address HRP (Human Readable Part) for bech32m ---
constexpr const char* HRP_MAINNET = "qtc";
constexpr const char* HRP_TESTNET = "tqtc";
constexpr const char* HRP_REGTEST = "qtc";  // regtest uses same HRP, scoped by chain mode

// --- Genesis constants ---
// Fixed timestamp for reproducible genesis hash.
// Regtest genesis: January 1, 2026 00:00:00 UTC
constexpr uint32_t REGTEST_GENESIS_TIMESTAMP = 1767225600;
constexpr const char* REGTEST_GENESIS_MESSAGE = "QTC Regtest Genesis 2026 - Post-Quantum from Day One";

// Difficulty bits for regtest: extremely easy (target = 0x7fffff0000...)
constexpr uint32_t REGTEST_GENESIS_BITS = 0x207fffff;

// Mining difficulty for regtest (same as genesis — trivially easy)
constexpr uint32_t REGTEST_MINING_BITS = REGTEST_GENESIS_BITS;

// Genesis nonce — starting point for mining the genesis block.
// The actual nonce is found by mining and is deterministic.
constexpr uint32_t REGTEST_GENESIS_START_NONCE = 0;

// --- Block subsidy ---
// Calculate the block subsidy at a given height.
// Implements Bitcoin-style halving: subsidy halves every HALVING_INTERVAL blocks.
// Returns 0 when all 21M QTC have been mined.
uint64_t get_block_subsidy(uint32_t height);

} // namespace qtc
