#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include "block.h"
#include "utxo.h"

namespace qtc {

// Chain state — manages the blockchain and provides query methods
class Chain {
public:
    Chain();

    // Initialize with genesis block (idempotent)
    void init(Network network = Network::REGTEST);

    // Get blockchain info
    struct BlockchainInfo {
        Network network;
        uint32_t height;
        std::string best_block_hash;
        uint32_t difficulty_bits;
        uint64_t chain_work;  // simplified
        bool initialized;
    };

    BlockchainInfo get_blockchain_info() const;
    const Block& get_block(uint32_t height) const;
    const Block& get_genesis() const;
    
    // Get the current tip block
    const Block& tip() const;
    
    // Get current chain height
    uint32_t height() const;
    
    // Get the blocks vector (for validation/rebuild)
    const std::vector<Block>& blocks() const;

    // Add a block to the chain (with full validation)
    bool add_block(const Block& block);

    // Validate the entire chain
    bool validate_chain() const;

    // Access the UTXO set
    UTXOSet& utxo_set();
    const UTXOSet& utxo_set() const;

    // Save / load chain state (JSON-based for development)
    bool save(const std::string& filepath) const;
    bool load(const std::string& filepath);

private:
    Network network_;
    std::vector<Block> blocks_;
    UTXOSet utxo_set_;
    bool initialized_ = false;
};

} // namespace qtc
