#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include "transaction.h"
#include "consensus.h"

namespace qtc {

// QTC Block Header (80 bytes when serialized — matches Bitcoin format)
//
//   version          (4 bytes, LE)
//   prev_block_hash  (32 bytes, LE)
//   merkle_root      (32 bytes, LE)
//   timestamp        (4 bytes, LE)
//   difficulty_bits  (4 bytes, LE)
//   nonce            (4 bytes, LE)
//
struct BlockHeader {
    uint32_t version = BLOCK_VERSION;
    std::vector<uint8_t> prev_block_hash;  // 32 bytes, all zeros for genesis
    std::vector<uint8_t> merkle_root;      // 32 bytes
    uint32_t timestamp = 0;
    uint32_t difficulty_bits = 0;
    uint32_t nonce = 0;

    // Serialize header to 80 bytes (for hashing)
    std::vector<uint8_t> serialize() const;

    // Compute block hash: double_sha256(serialized header)
    std::vector<uint8_t> hash() const;
    std::string hash_hex() const;
};

// QTC Block
struct Block {
    BlockHeader header;
    std::vector<Transaction> transactions;

    // Compute merkle root from transactions
    std::vector<uint8_t> compute_merkle_root() const;

    // Serialize full block (header + tx count + transactions)
    std::vector<uint8_t> serialize() const;

    // Validate the block's PoW
    bool validate_pow() const;

    // Create the QTC regtest genesis block
    static Block create_regtest_genesis();

    // Get block height from coinbase (if available)
    // Returns -1 if not determinable
    int32_t get_height_from_coinbase() const;
};

} // namespace qtc
