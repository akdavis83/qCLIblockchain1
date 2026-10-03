#include "chain.h"
#include "crypto.h"
#include "consensus.h"
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace qtc {

Chain::Chain() : network_(Network::REGTEST), initialized_(false) {}

void Chain::init(Network network) {
    if (initialized_) return;
    
    network_ = network;
    
    Block genesis;
    switch (network) {
        case Network::REGTEST:
            genesis = Block::create_regtest_genesis();
            break;
        default:
            genesis = Block::create_regtest_genesis();
            break;
    }
    
    blocks_.clear();
    blocks_.push_back(genesis);
    
    // Rebuild UTXO set from chain
    utxo_set_.rebuild_from_blocks(blocks_);
    
    initialized_ = true;
}

Chain::BlockchainInfo Chain::get_blockchain_info() const {
    BlockchainInfo info;
    info.network = network_;
    info.height = static_cast<uint32_t>(blocks_.size()) - 1;
    info.best_block_hash = blocks_.empty() ? "" : blocks_.back().header.hash_hex();
    info.difficulty_bits = blocks_.empty() ? 0 : blocks_.back().header.difficulty_bits;
    info.chain_work = 0;
    info.initialized = initialized_;
    return info;
}

const Block& Chain::get_block(uint32_t height) const {
    if (height >= blocks_.size()) {
        throw std::out_of_range("Block height " + std::to_string(height) + " out of range");
    }
    return blocks_[height];
}

const Block& Chain::get_genesis() const {
    if (blocks_.empty()) {
        throw std::runtime_error("Chain not initialized");
    }
    return blocks_[0];
}

const Block& Chain::tip() const {
    if (blocks_.empty()) {
        throw std::runtime_error("Chain not initialized");
    }
    return blocks_.back();
}

uint32_t Chain::height() const {
    if (blocks_.empty()) return 0;
    return static_cast<uint32_t>(blocks_.size()) - 1;
}

const std::vector<Block>& Chain::blocks() const {
    return blocks_;
}

bool Chain::add_block(const Block& block) {
    if (blocks_.empty()) {
        return false;
    }
    
    // Reject empty blocks
    if (block.transactions.empty()) {
        std::cerr << "Block rejected: no transactions\n";
        return false;
    }
    
    // Validate: previous hash must match current tip
    const auto& tip = blocks_.back();
    auto tip_hash = tip.header.hash();
    
    if (block.header.prev_block_hash.size() != 32 || tip_hash.size() != 32) {
        return false;
    }
    for (size_t i = 0; i < 32; ++i) {
        if (block.header.prev_block_hash[i] != tip_hash[i]) {
            std::cerr << "Block rejected: previous hash mismatch\n";
            return false;
        }
    }
    
    // Check merkle root
    auto computed_root = block.compute_merkle_root();
    if (computed_root.size() != 32 || block.header.merkle_root.size() != 32) {
        return false;
    }
    for (size_t i = 0; i < 32; ++i) {
        if (block.header.merkle_root[i] != computed_root[i]) {
            std::cerr << "Block rejected: merkle root mismatch\n";
            return false;
        }
    }
    
    // Check PoW
    if (!block.validate_pow()) {
        std::cerr << "Block rejected: PoW invalid\n";
        return false;
    }
    
    // Validate all transactions in the block against a candidate UTXO set
    // We apply sequentially to catch block-level double spends
    uint32_t new_height = static_cast<uint32_t>(blocks_.size());
    UTXOSet candidate = utxo_set_;
    
    for (size_t i = 0; i < block.transactions.size(); ++i) {
        const auto& tx = block.transactions[i];
        
        // Enforce coinbase position: first tx must be coinbase, no others
        if (i == 0 && !tx.is_coinbase()) {
            std::cerr << "Block rejected: first transaction is not a coinbase\n";
            return false;
        }
        if (i > 0 && tx.is_coinbase()) {
            std::cerr << "Block rejected: coinbase in position " << i << "\n";
            return false;
        }
        
        // Check coinbase subsidy does not exceed allowed amount
        if (tx.is_coinbase() && !tx.outputs.empty()) {
            uint64_t subsidy = get_block_subsidy(new_height);
            uint64_t coinbase_output = tx.total_output();
            if (coinbase_output > subsidy) {
                std::cerr << "Block rejected: coinbase output (" << coinbase_output
                          << ") exceeds subsidy (" << subsidy << ")\n";
                return false;
            }
        }
        
        std::string error;
        if (!candidate.apply_transaction(tx, new_height, error)) {
            std::cerr << "Block rejected: transaction validation failed: " << error << "\n";
            return false;
        }
    }
    
    // Commit the candidate UTXO set
    utxo_set_ = std::move(candidate);
    
    blocks_.push_back(block);
    return true;
}

bool Chain::validate_chain() const {
    if (blocks_.empty()) return false;
    
    // Validate genesis PoW
    if (!blocks_[0].validate_pow()) {
        std::cerr << "Genesis block PoW invalid" << std::endl;
        return false;
    }
    
    // Walk the chain, rebuilding a candidate UTXO set
    UTXOSet utxos;
    
    for (size_t i = 0; i < blocks_.size(); ++i) {
        const auto& curr = blocks_[i];
        uint32_t block_height = static_cast<uint32_t>(i);
        
        // Reject empty blocks
        if (curr.transactions.empty()) {
            std::cerr << "Block " << i << ": no transactions" << std::endl;
            return false;
        }
        
        // Validate PoW for all blocks
        if (!curr.validate_pow()) {
            std::cerr << "Block " << i << ": PoW invalid" << std::endl;
            return false;
        }
        
        // Validate block linkage (skip genesis)
        if (i > 0) {
            const auto& prev = blocks_[i - 1];
            auto prev_hash = prev.header.hash();
            for (size_t j = 0; j < 32 && j < curr.header.prev_block_hash.size(); ++j) {
                if (curr.header.prev_block_hash[j] != prev_hash[j]) {
                    std::cerr << "Block " << i << ": previous hash mismatch" << std::endl;
                    return false;
                }
            }
        }
        
        // Validate merkle root
        auto computed_root = curr.compute_merkle_root();
        for (size_t j = 0; j < 32 && j < curr.header.merkle_root.size(); ++j) {
            if (curr.header.merkle_root[j] != computed_root[j]) {
                std::cerr << "Block " << i << ": merkle root mismatch" << std::endl;
                return false;
            }
        }
        
        // Validate transactions in this block
        for (size_t tx_i = 0; tx_i < curr.transactions.size(); ++tx_i) {
            const auto& tx = curr.transactions[tx_i];
            
            // Enforce coinbase position
            if (tx_i == 0 && !tx.is_coinbase()) {
                std::cerr << "Block " << i << ": first tx is not coinbase" << std::endl;
                return false;
            }
            if (tx_i > 0 && tx.is_coinbase()) {
                std::cerr << "Block " << i << ": coinbase in position " << tx_i << std::endl;
                return false;
            }
            
            // Check coinbase subsidy
            if (tx.is_coinbase() && !tx.outputs.empty()) {
                uint64_t subsidy = get_block_subsidy(block_height);
                uint64_t coinbase_output = tx.total_output();
                if (coinbase_output > subsidy) {
                    std::cerr << "Block " << i << ": coinbase output (" << coinbase_output
                              << ") exceeds subsidy (" << subsidy << ")" << std::endl;
                    return false;
                }
            }
            
            // Validate against candidate UTXO set
            std::string error;
            if (!utxos.validate_transaction(tx, error)) {
                std::cerr << "Block " << i << " tx " << tx_i << ": " << error << std::endl;
                return false;
            }
            
            // Apply transaction to candidate UTXO set
            if (!utxos.apply_transaction(tx, block_height, error)) {
                std::cerr << "Block " << i << " tx " << tx_i << ": apply failed: " << error << std::endl;
                return false;
            }
        }
    }
    
    return true;
}

UTXOSet& Chain::utxo_set() {
    return utxo_set_;
}

const UTXOSet& Chain::utxo_set() const {
    return utxo_set_;
}

bool Chain::save(const std::string& filepath) const {
    std::ofstream out(filepath);
    if (!out) return false;
    
    out << "# QTC Chain State (development format)" << std::endl;
    out << "network=" << static_cast<int>(network_) << std::endl;
    out << "height=" << (blocks_.size() - 1) << std::endl;
    out << "utxo_count=" << utxo_set_.size() << std::endl;
    
    for (size_t i = 0; i < blocks_.size(); ++i) {
        out << "block_" << i << "_hash=" << blocks_[i].header.hash_hex() << std::endl;
        out << "block_" << i << "_timestamp=" << blocks_[i].header.timestamp << std::endl;
        out << "block_" << i << "_nonce=" << blocks_[i].header.nonce << std::endl;
        out << "block_" << i << "_txcount=" << blocks_[i].transactions.size() << std::endl;
    }
    
    return true;
}

bool Chain::load(const std::string& filepath) {
    std::ifstream in(filepath);
    if (!in) return false;
    
    init(network_);
    return true;
}

} // namespace qtc
