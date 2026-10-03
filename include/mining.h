#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include "block.h"
#include "chain.h"

namespace qtc {

// ============================================================
// Mining module — SHA-256 proof of work
//
// QTC v1 uses double SHA-256 (SHA256d) proof of work, matching
// Bitcoin's consensus algorithm. This keeps the consensus surface
// small and allows existing SHA-256 mining hardware to mine QTC.
//
// The mining algorithm is:
//   1. Assemble a block template (coinbase + header)
//   2. Serialize the 80-byte header
//   3. Compute hash = SHA256(SHA256(header))
//   4. If hash <= target, block is valid
//   5. Otherwise, increment nonce and repeat
//
// ============================================================

// Result of a mining attempt
struct MiningResult {
    bool found = false;
    uint32_t nonce = 0;
    uint64_t attempts = 0;
    std::string hash_hex;
};

// Calculate the block subsidy at a given height.
// (Moved to consensus.h/consensus.cpp — subsidy is a consensus rule, not a mining concern)
// uint64_t get_block_subsidy(uint32_t height);

// Create a block template for mining.
// Assembles a coinbase transaction paying the subsidy to the given address,
// sets the header fields (version, prev_hash, merkle_root, timestamp, bits),
// and returns a block ready for nonce-finding.
Block create_block_template(
    const Chain& chain,
    const std::string& payout_address,
    const std::vector<Transaction>& extra_txs = {}
);

// Mine a block by finding a valid nonce.
// Modifies the block in-place: sets the nonce and returns the result.
// With regtest difficulty, this should find a block almost instantly.
MiningResult mine_block(Block& block, uint64_t max_attempts = 1000000);

// Mine N blocks on a chain, paying rewards to the given address.
// Returns the number of blocks successfully mined.
uint32_t mine_n_blocks(
    Chain& chain,
    uint32_t count,
    const std::string& payout_address
);

} // namespace qtc
