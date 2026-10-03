#include "mining.h"
#include "crypto.h"
#include "consensus.h"
#include "transaction.h"
#include "utxo.h"
#include <iostream>

namespace qtc {

// ============================================================
// Block subsidy — implemented in consensus.cpp
// ============================================================
// (get_block_subsidy is now in consensus.h/consensus.cpp)

// ============================================================
// Block template creation
// ============================================================

Block create_block_template(
    const Chain& chain,
    const std::string& payout_address,
    const std::vector<Transaction>& extra_txs
) {
    Block block;
    
    uint32_t next_height = chain.get_blockchain_info().height + 1;
    uint64_t subsidy = get_block_subsidy(next_height);
    
    // Create coinbase transaction
    Transaction coinbase = Transaction::create_coinbase(
        next_height,
        "QTC mined block " + std::to_string(next_height),
        subsidy,
        script::for_address(payout_address)
    );
    
    // Assemble transactions: coinbase first, then any extra txs
    block.transactions.push_back(coinbase);
    for (const auto& tx : extra_txs) {
        block.transactions.push_back(tx);
    }
    
    // Build header
    const auto& tip = chain.get_block(chain.get_blockchain_info().height);
    block.header.version = BLOCK_VERSION;
    block.header.prev_block_hash = tip.header.hash();
    block.header.merkle_root = block.compute_merkle_root();
    block.header.timestamp = tip.header.timestamp + BLOCK_INTERVAL;
    block.header.difficulty_bits = REGTEST_MINING_BITS;
    block.header.nonce = 0;
    
    return block;
}

// ============================================================
// Mining loop
// ============================================================

MiningResult mine_block(Block& block, uint64_t max_attempts) {
    MiningResult result;
    result.attempts = 0;
    
    // Ensure merkle root is computed before mining
    block.header.merkle_root = block.compute_merkle_root();
    
    // Check if already valid (nonce 0 might work)
    if (block.validate_pow()) {
        result.found = true;
        result.nonce = block.header.nonce;
        result.hash_hex = block.header.hash_hex();
        return result;
    }
    
    // Mining loop: increment nonce until we find a valid hash
    while (result.attempts < max_attempts) {
        block.header.nonce++;
        result.attempts++;
        
        if (block.validate_pow()) {
            result.found = true;
            result.nonce = block.header.nonce;
            result.hash_hex = block.header.hash_hex();
            return result;
        }
        
        // If nonce wraps around (uint32_t overflow), increment timestamp
        // and reset nonce. This is a simplified version of Bitcoin's
        // extra-nonce / timestamp adjustment.
        if (block.header.nonce == 0) {
            block.header.timestamp++;
            // Recompute merkle root in case coinbase changed
            // (In this simplified version, coinbase doesn't change,
            // but in production the extra-nonce would be in the coinbase)
        }
    }
    
    result.found = false;
    result.hash_hex = block.header.hash_hex();
    return result;
}

// ============================================================
// Mine N blocks
// ============================================================

uint32_t mine_n_blocks(
    Chain& chain,
    uint32_t count,
    const std::string& payout_address
) {
    uint32_t mined = 0;
    
    for (uint32_t i = 0; i < count; ++i) {
        Block block = create_block_template(chain, payout_address);
        MiningResult result = mine_block(block);
        
        if (!result.found) {
            std::cerr << "Failed to mine block " << (i + 1) << " after "
                      << result.attempts << " attempts\n";
            break;
        }
        
        if (!chain.add_block(block)) {
            std::cerr << "Failed to add mined block " << (i + 1) << " to chain\n";
            break;
        }
        
        mined++;
        
        std::cout << "  Block " << chain.get_blockchain_info().height
                  << " mined | nonce=" << result.nonce
                  << " attempts=" << result.attempts
                  << " hash=" << result.hash_hex << "\n";
    }
    
    return mined;
}

} // namespace qtc
