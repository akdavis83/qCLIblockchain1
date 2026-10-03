#include "block.h"
#include "crypto.h"
#include "consensus.h"
#include <algorithm>
#include <stdexcept>

namespace qtc {

// ============================================================
// BlockHeader
// ============================================================

std::vector<uint8_t> BlockHeader::serialize() const {
    std::vector<uint8_t> result;
    result.reserve(80);
    
    // version (4 bytes LE)
    auto v = crypto::write_le_u32(version);
    result.insert(result.end(), v.begin(), v.end());
    
    // prev_block_hash (32 bytes — pad if empty)
    for (size_t i = 0; i < 32; ++i) {
        result.push_back(i < prev_block_hash.size() ? prev_block_hash[i] : 0);
    }
    
    // merkle_root (32 bytes — pad if empty)
    for (size_t i = 0; i < 32; ++i) {
        result.push_back(i < merkle_root.size() ? merkle_root[i] : 0);
    }
    
    // timestamp (4 bytes LE)
    auto ts = crypto::write_le_u32(timestamp);
    result.insert(result.end(), ts.begin(), ts.end());
    
    // difficulty_bits (4 bytes LE)
    auto bits = crypto::write_le_u32(difficulty_bits);
    result.insert(result.end(), bits.begin(), bits.end());
    
    // nonce (4 bytes LE)
    auto n = crypto::write_le_u32(nonce);
    result.insert(result.end(), n.begin(), n.end());
    
    return result;
}

std::vector<uint8_t> BlockHeader::hash() const {
    return crypto::double_sha256(serialize());
}

std::string BlockHeader::hash_hex() const {
    auto h = hash();
    // Bitcoin convention: display hash in reversed (little-endian) byte order
    std::reverse(h.begin(), h.end());
    return crypto::to_hex(h);
}

// ============================================================
// Block
// ============================================================

std::vector<uint8_t> Block::compute_merkle_root() const {
    if (transactions.empty()) {
        return std::vector<uint8_t>(32, 0);
    }
    
    // Compute leaf hashes (txids)
    std::vector<std::vector<uint8_t>> hashes;
    hashes.reserve(transactions.size());
    for (const auto& tx : transactions) {
        hashes.push_back(tx.txid());
    }
    
    // Build merkle tree
    while (hashes.size() > 1) {
        std::vector<std::vector<uint8_t>> next_level;
        for (size_t i = 0; i < hashes.size(); i += 2) {
            if (i + 1 < hashes.size()) {
                // Concatenate two hashes and double-SHA256
                auto combined = crypto::concat(hashes[i], hashes[i + 1]);
                next_level.push_back(crypto::double_sha256(combined));
            } else {
                // Odd count: duplicate the last hash
                auto combined = crypto::concat(hashes[i], hashes[i]);
                next_level.push_back(crypto::double_sha256(combined));
            }
        }
        hashes = std::move(next_level);
    }
    
    return hashes[0];
}

std::vector<uint8_t> Block::serialize() const {
    std::vector<uint8_t> result;
    
    // Header (80 bytes)
    auto header_bytes = header.serialize();
    result.insert(result.end(), header_bytes.begin(), header_bytes.end());
    
    // Transaction count (CompactSize)
    auto tx_count = crypto::write_compact_size(transactions.size());
    result.insert(result.end(), tx_count.begin(), tx_count.end());
    
    // Transactions
    for (const auto& tx : transactions) {
        auto tx_bytes = tx.serialize();
        result.insert(result.end(), tx_bytes.begin(), tx_bytes.end());
    }
    
    return result;
}

bool Block::validate_pow() const {
    auto hash = header.hash();
    auto target = crypto::bits_to_target(header.difficulty_bits);
    return crypto::hash_meets_target(hash, target);
}

Block Block::create_regtest_genesis() {
    Block block;
    
    // Create genesis coinbase transaction
    Transaction coinbase = Transaction::create_genesis_coinbase(
        REGTEST_GENESIS_MESSAGE,
        INITIAL_SUBSIDY
    );
    block.transactions.push_back(coinbase);
    
    // Build header
    block.header.version = BLOCK_VERSION;
    block.header.prev_block_hash = std::vector<uint8_t>(32, 0);  // all zeros
    block.header.merkle_root = block.compute_merkle_root();
    block.header.timestamp = REGTEST_GENESIS_TIMESTAMP;
    block.header.difficulty_bits = REGTEST_GENESIS_BITS;
    block.header.nonce = REGTEST_GENESIS_START_NONCE;
    
    // For regtest with very easy difficulty, nonce 0 should produce a valid block.
    // If not, we mine to find a valid nonce.
    if (!block.validate_pow()) {
        // Mine the genesis block with easy difficulty
        while (!block.validate_pow()) {
            block.header.nonce++;
        }
    }
    
    return block;
}

int32_t Block::get_height_from_coinbase() const {
    if (transactions.empty()) return -1;
    if (!transactions[0].is_coinbase()) return -1;
    if (transactions[0].inputs.empty()) return -1;
    
    const auto& script = transactions[0].inputs[0].script;
    if (script.empty()) return -1;
    
    // Simplified: first byte is height (works for heights 0-252)
    return static_cast<int32_t>(script[0]);
}

} // namespace qtc
